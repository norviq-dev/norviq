# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Shared tool-wrapping helpers for framework adapters."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.masking import mask_text

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
