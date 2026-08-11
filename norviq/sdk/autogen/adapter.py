# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""AutoGen adapter for Norviq tool interception.

Targets autogen-core >= 0.4's `autogen_core.tools.BaseTool` API, which is what
autogen-agentchat's `AssistantAgent` consumes.
"""

from typing import Any

import structlog

from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _output_dlp
# Shared declared-schema ingestion. It lives in the LangChain adapter module only because this
# change is scoped to the five adapter files (see the banner there); that module imports no
# framework at import time, so an AutoGen-only install pays nothing for this.
from norviq.sdk.langchain.adapter import ingest_declared_schema

log = structlog.get_logger()

# autogen-core publishes an OpenAI-style tool schema on `.schema`
# (`{"name": ..., "parameters": {"type": "object", "properties": {...}}}`) — the exact document it
# sends to the model.
_AUTOGEN_SCHEMA_ATTRS = ("schema",)


def _ingest_tool_schema(tool: Any, tool_name: str) -> None:
    """Ingest the argument names AutoGen already declares for this tool.

    Two independent statements of the same fact, tried in order: the published `.schema`, then the
    pydantic args model behind `args_type()`. The second is a CALL on a third-party object, so it is
    only made when the first yielded nothing — a tool whose schema is already readable is never
    poked further — and any exception it raises is contained here.
    """
    if ingest_declared_schema(
        tool, tool_name=tool_name, framework="autogen", attrs=_AUTOGEN_SCHEMA_ATTRS
    ).schema_available:
        return
    args_type = getattr(tool, "args_type", None)
    if not callable(args_type):
        return
    try:
        args_model = args_type()
    except Exception as exc:  # noqa: BLE001 - a failing args_type() leaves the schema unknown
        log.debug("nrvq.autogen.args_type_failed", tool=tool_name, error=str(exc), code="NRVQ-SDK-1064")
        return
    if args_model is not None:
        ingest_declared_schema(
            tool, tool_name=tool_name, framework="autogen", schema=args_model, source="args_type"
        )


def _get_base_tool() -> type[Any]:
    """Load autogen-core BaseTool class lazily."""
    try:
        from autogen_core.tools import BaseTool
    except ImportError as exc:
        raise ImportError("autogen-core not installed. pip install autogen-core autogen-agentchat") from exc
    return BaseTool


def _run_params(args: Any) -> dict[str, Any]:
    """Build a stable parameter payload from a tool's run() args object."""
    model_dump = getattr(args, "model_dump", None)
    if callable(model_dump):
        return model_dump()
    if isinstance(args, dict):
        return args
    return {"args": str(args)}


def protect(
    tools: list[Any], interceptor: ToolInterceptor, session_id: str = "", *, allow_unwrapped: bool = False
) -> list[Any]:
    """Wrap AutoGen tools so policy runs before their async `run()` executes.

    Fail-closed by default: a framework upgrade that moves/renames `BaseTool` (or a caller that
    hands in something that was never a `BaseTool`) must be a loud startup error, not a silently
    unprotected tool — an item Norviq doesn't recognize as a `BaseTool` cannot be wrapped, so
    letting it through unwrapped means it runs with NO policy enforcement at all. Pass
    `allow_unwrapped=True` to downgrade this to a logged warning and accept the item as-is.
    """
    base_tool = _get_base_tool()
    protected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, base_tool):
            if not allow_unwrapped:
                raise TypeError(
                    f"norviq.sdk.autogen.adapter.protect: {type(tool).__name__!r} is not a "
                    f"{base_tool.__name__} instance and cannot be wrapped — fail-closed protection: "
                    "this tool would run WITHOUT policy enforcement. Pass allow_unwrapped=True to "
                    "permit it deliberately."
                )
            log.warning(
                "nrvq.autogen.unwrapped",
                tool_type=type(tool).__name__,
                code="NRVQ-SDK-1063",
            )
            protected.append(tool)
            continue
        _ingest_tool_schema(tool, str(tool.name))
        original_run = tool.run

        async def async_wrapper(
            args: Any, cancellation_token: Any, _name: str = tool.name, _orig: Any = original_run
        ) -> Any:
            await interceptor.intercept_or_raise(
                tool_name=_name,
                tool_params=_run_params(args),
                session_id=session_id,
                framework="autogen",
            )
            log.info("nrvq.autogen.allowed", tool=_name, code="NRVQ-SDK-1062")
            result = await _orig(args, cancellation_token)
            return _output_dlp(_name, result)

        tool.run = async_wrapper  # type: ignore[method-assign]
        protected.append(tool)
        log.debug("nrvq.autogen.protected", tool=tool.name, code="NRVQ-SDK-1061")
    log.info("nrvq.autogen.protect", count=len(protected), code="NRVQ-SDK-1060")
    return protected
