# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph adapter for Norviq tool interception."""

import json
from typing import Any

import structlog

from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.interceptor import ToolInterceptor, depth_scope
from norviq.sdk.core.wrapping import _output_dlp
# Shared declared-schema ingestion. It lives in the LangChain adapter module only because this
# change is scoped to the five adapter files (see the banner there); LangGraph tools ARE LangChain
# tools, so this adapter reads exactly the same declaration.
from norviq.sdk.langchain.adapter import LANGCHAIN_SCHEMA_ATTRS, ingest_declared_schema

log = structlog.get_logger()


def _get_tool_node() -> type[Any]:
    """Load LangGraph ToolNode class lazily."""
    try:
        from langgraph.prebuilt import ToolNode
    except ImportError as exc:
        raise ImportError("langgraph not installed. pip install langgraph") from exc
    return ToolNode


def _tool_call_field(tool_call: Any, key: str, default: Any) -> Any:
    """Read field from dict/object tool call."""
    if isinstance(tool_call, dict):
        return tool_call.get(key, default)
    return getattr(tool_call, key, default)


def _apply_output_dlp(result: Any) -> None:
    """Best-effort output DLP on each executed tool's ToolMessage; enforcement above already ran.

    Opt-in, default OFF: redact PAN/SSN in an allowed tool's string return before it
    propagates. ToolNode returns ``{"messages": [ToolMessage, ...]}`` (or a bare list), each
    ToolMessage carrying the tool's string result in ``.content``; masked in place to mirror the
    other adapters. Disabled → exact passthrough (no hot-path or behavior change).
    """
    try:
        messages = result.get("messages") if isinstance(result, dict) else result
        if not isinstance(messages, list):
            return
        for msg in messages:
            content = getattr(msg, "content", None)
            if not isinstance(content, str):
                continue
            masked = _output_dlp(str(_tool_call_field(msg, "name", "") or "unknown"), content)
            if masked != content:
                msg.content = masked
    except Exception as exc:  # noqa: BLE001 - DLP is best-effort, must not affect the result
        log.warning("nrvq.langgraph.output_dlp_failed", error=str(exc), code="NRVQ-SDK-1043")


def _normalise_tool_args(args: Any) -> dict[str, Any]:
    """Whatever LangGraph handed us, as something the engine can actually inspect.

    This was ``args if isinstance(args, dict) else {}``, and the else branch was the whole bug: a tool
    call in the OpenAI shape carries its arguments as a JSON STRING, so the payload was replaced with
    an empty dict before it ever reached the interceptor. Every per-argument control walks
    ``tool_params`` -- the PII, secret, SQL and shell detectors, every ``param_paths`` clause, the
    destination and recipient facts -- so under LangGraph all of them were inert while the console
    showed a clean allow. A framework that looks compliant because nothing was inspected is the worst
    of the three possible outcomes, and it is the one a campaign scores as a pass.

    A non-dict that is not JSON is WRAPPED rather than dropped. The argument NAME is unknowable there,
    but the content is not, and the content detectors walk values regardless of key -- so a secret
    passed as a bare string is still caught. Dropping it silently was the failure; inventing a
    plausible key name would be a different lie.
    """
    if isinstance(args, dict):
        return args
    if args is None:
        return {}
    if isinstance(args, str):
        try:
            parsed = json.loads(args)
        except (ValueError, TypeError):
            return {"_nrvq_unparsed_args": args}
        return parsed if isinstance(parsed, dict) else {"_nrvq_unparsed_args": parsed}
    return {"_nrvq_unparsed_args": args}


class GuardedToolNode:
    """LangGraph ToolNode wrapper with Norviq policy enforcement."""

    def __init__(self, tools: list[Any], interceptor: ToolInterceptor, session_id: str = "") -> None:
        """Store wrapped ToolNode and interception dependencies."""
        tool_node = _get_tool_node()
        self._interceptor = interceptor
        self._session_id = session_id
        # Graph-build time is the only moment this adapter sees the tool OBJECTS — every later call
        # arrives as a `{"name": ..., "args": {...}}` message. So the argument names the framework
        # declares are ingested here, which is also before any traffic exists to observe them from.
        # Contained, because this is the ONE adapter where reading a tool's name is new work at a
        # point that previously did none. `getattr(..., default)` only swallows AttributeError, so a
        # `.name` implemented as a property that raises anything else would turn "Norviq could not
        # read a schema" into "your graph does not build" — the failure this whole path exists to
        # never cause. `ingest_declared_schema` is already total; the name read is not.
        for tool in tools:
            try:
                name = str(getattr(tool, "name", "") or "")
            except Exception as exc:  # noqa: BLE001 - a hostile tool must not break graph building
                log.warning("nrvq.langgraph.schema_ingest_failed", error=str(exc), code="NRVQ-SDK-1045")
                continue
            if not name:
                continue  # nothing to key a record on; a nameless object is not a tool
            ingest_declared_schema(
                tool, tool_name=name, framework="langgraph", attrs=LANGCHAIN_SCHEMA_ATTRS
            )
        self._node = tool_node(tools)
        log.info("nrvq.langgraph.init", tool_count=len(tools), code="NRVQ-SDK-1040")

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Intercept tool calls from last message before execution."""
        calls = _tool_call_field((state.get("messages") or [None])[-1], "tool_calls", None)
        if not calls:
            return await self._node.ainvoke(state)
        for call in calls:
            name = str(_tool_call_field(call, "name", ""))
            args = _normalise_tool_args(_tool_call_field(call, "args", {}))
            try:
                await self._interceptor.intercept_or_raise(
                    tool_name=name,
                    tool_params=args,
                    session_id=self._session_id,
                    framework="langgraph",
                )
            except (NorviqBlockError, NorviqEscalateError):
                log.warning("nrvq.langgraph.denied", tool=name, code="NRVQ-SDK-1041")
                raise
            log.debug("nrvq.langgraph.allowed", tool=name, code="NRVQ-SDK-1041")
        # Held across the node's execution, which IS the tool body here: LangGraph runs the tools for
        # the whole message inside one node invocation, so anything those tools invoke must report a
        # deeper level. Without it `_CALL_DEPTH` stays 0 on this framework and `chain_depth_limit`
        # cannot fire at any depth (F-025).
        with depth_scope():
            result = await self._node.ainvoke(state)
        _apply_output_dlp(result)
        log.info("nrvq.langgraph.executed", tool_count=len(calls), code="NRVQ-SDK-1042")
        return result
