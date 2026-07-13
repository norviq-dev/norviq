# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""CrewAI adapter for Norviq tool interception."""

from typing import Any

import structlog

from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _output_dlp, _run_sync, _tool_params

log = structlog.get_logger()


def _get_base_tool() -> type[Any]:
    """Load CrewAI BaseTool class lazily."""
    try:
        from crewai.tools import BaseTool
    except ImportError as exc:
        raise ImportError("crewai not installed. pip install crewai") from exc
    return BaseTool


def protect(
    tools: list[Any], interceptor: ToolInterceptor, session_id: str = "", *, allow_unwrapped: bool = False
) -> list[Any]:
    """Wrap CrewAI tools so policy runs before execution.

    CrewAI's `BaseTool` is sync-only (`_run`); there is no async execution path to wrap.

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
                    f"norviq.sdk.crewai.adapter.protect: {type(tool).__name__!r} is not a "
                    f"{base_tool.__name__} instance and cannot be wrapped — fail-closed protection: "
                    "this tool would run WITHOUT policy enforcement. Pass allow_unwrapped=True to "
                    "permit it deliberately."
                )
            log.warning(
                "nrvq.crewai.unwrapped",
                tool_type=type(tool).__name__,
                code="NRVQ-SDK-1053",
            )
            protected.append(tool)
            continue
        original_run = tool._run

        def sync_wrapper(*args: Any, _name: str = tool.name, _orig: Any = original_run, **kwargs: Any) -> Any:
            _run_sync(
                interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs),
                    session_id=session_id,
                    framework="crewai",
                )
            )
            log.info("nrvq.crewai.allowed", tool=_name, code="NRVQ-SDK-1052")
            return _output_dlp(_name, _orig(*args, **kwargs))

        tool._run = sync_wrapper  # type: ignore[method-assign]
        protected.append(tool)
        log.debug("nrvq.crewai.protected", tool=tool.name, code="NRVQ-SDK-1051")
    log.info("nrvq.crewai.protect", count=len(protected), code="NRVQ-SDK-1050")
    return protected
