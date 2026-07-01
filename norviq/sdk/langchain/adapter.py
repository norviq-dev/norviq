# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangChain adapter for Norviq tool interception."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.masking import mask_text
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()
_SYNC_EXECUTOR = ThreadPoolExecutor(max_workers=1)


def _output_dlp(tool_name: str, result: Any) -> Any:
    """F-22 (opt-in, default OFF): redact PAN/SSN in an allowed tool's string return before it propagates.
    Norviq's PEP is input-only; this is a minimal output-side guard so a tool whose OUTPUT carries sensitive data
    doesn't silently exfiltrate it. Disabled by default → exact passthrough (no hot-path or behavior change)."""
    if not settings.sdk_output_dlp_enabled or not isinstance(result, str):
        return result
    masked = mask_text(result)
    if masked != result:
        log.warning("nrvq.sdk.output_dlp_redacted", tool=tool_name, code="NRVQ-SDK-1043")
    return masked


def _get_base_tool() -> type[Any]:
    """Load LangChain BaseTool class lazily."""
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        from langchain.tools import BaseTool
    return BaseTool


def _tool_params(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Build a stable parameter payload from invocation data."""
    return kwargs or {"args": list(args)}


def _run_sync(coro: Any) -> Any:
    """Run coroutine from sync context regardless of active loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return _SYNC_EXECUTOR.submit(asyncio.run, coro).result()


def protect(tools: list[Any], interceptor: ToolInterceptor, session_id: str = "") -> list[Any]:
    """Wrap LangChain tools so policy runs before execution.

    In sync-in-async usage, prefer `_arun` because async Redis clients are event-loop bound.
    """
    base_tool = _get_base_tool()
    protected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, base_tool):
            protected.append(tool)
            continue
        original_run = tool._run
        original_arun = getattr(tool, "_arun", None)

        def sync_wrapper(*args: Any, _name: str = tool.name, _orig: Any = original_run, **kwargs: Any) -> Any:
            _run_sync(
                interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs),
                    session_id=session_id,
                    framework="langchain",
                )
            )
            log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
            return _output_dlp(_name, _orig(*args, **kwargs))

        tool._run = sync_wrapper  # type: ignore[method-assign]
        if original_arun is not None:

            async def async_wrapper(*args: Any, _name: str = tool.name, _orig: Any = original_arun, **kwargs: Any) -> Any:
                await interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs),
                    session_id=session_id,
                    framework="langchain",
                )
                log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
                return _output_dlp(_name, await _orig(*args, **kwargs))

            tool._arun = async_wrapper  # type: ignore[method-assign]
        protected.append(tool)
        log.debug("nrvq.langchain.protected", tool=tool.name, code="NRVQ-SDK-1031")
    log.info("nrvq.langchain.protect", count=len(protected), code="NRVQ-SDK-1032")
    return protected
