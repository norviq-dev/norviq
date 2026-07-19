# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph adapter for Norviq tool interception."""

from typing import Any

import structlog

from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _output_dlp

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


class GuardedToolNode:
    """LangGraph ToolNode wrapper with Norviq policy enforcement."""

    def __init__(self, tools: list[Any], interceptor: ToolInterceptor, session_id: str = "") -> None:
        """Store wrapped ToolNode and interception dependencies."""
        tool_node = _get_tool_node()
        self._interceptor = interceptor
        self._session_id = session_id
        self._node = tool_node(tools)
        log.info("nrvq.langgraph.init", tool_count=len(tools), code="NRVQ-SDK-1040")

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """Intercept tool calls from last message before execution."""
        calls = _tool_call_field((state.get("messages") or [None])[-1], "tool_calls", None)
        if not calls:
            return await self._node.ainvoke(state)
        for call in calls:
            name = str(_tool_call_field(call, "name", ""))
            args = _tool_call_field(call, "args", {})
            try:
                await self._interceptor.intercept_or_raise(
                    tool_name=name,
                    tool_params=args if isinstance(args, dict) else {},
                    session_id=self._session_id,
                    framework="langgraph",
                )
            except (NorviqBlockError, NorviqEscalateError):
                log.warning("nrvq.langgraph.denied", tool=name, code="NRVQ-SDK-1041")
                raise
            log.debug("nrvq.langgraph.allowed", tool=name, code="NRVQ-SDK-1041")
        result = await self._node.ainvoke(state)
        _apply_output_dlp(result)
        log.info("nrvq.langgraph.executed", tool_count=len(calls), code="NRVQ-SDK-1042")
        return result
