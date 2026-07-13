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

log = structlog.get_logger()


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


def protect(tools: list[Any], interceptor: ToolInterceptor, session_id: str = "") -> list[Any]:
    """Wrap AutoGen tools so policy runs before their async `run()` executes."""
    base_tool = _get_base_tool()
    protected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, base_tool):
            protected.append(tool)
            continue
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
