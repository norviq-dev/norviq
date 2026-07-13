# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Shared tool-wrapping helpers for framework adapters."""

import asyncio
import threading
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.masking import mask_text

log = structlog.get_logger()

# One persistent background loop for EVERY sync-wrapped call (daemon thread: never blocks exit).
# A throwaway `asyncio.run` per call gives each call a different loop, so any loop-bound resource
# the evaluator holds (httpx/redis connection pools) is reused across loops and crashes — which the
# client then converts to its fail-closed fallback, silently blocking healthy traffic. A single
# stable loop keeps the sync path loop-consistent for the lifetime of the process.
_BG_LOOP: asyncio.AbstractEventLoop | None = None
_BG_LOOP_LOCK = threading.Lock()


def _background_loop() -> asyncio.AbstractEventLoop:
    """Return the shared background loop, starting its daemon thread on first use."""
    global _BG_LOOP
    with _BG_LOOP_LOCK:
        if _BG_LOOP is None or _BG_LOOP.is_closed():
            loop = asyncio.new_event_loop()
            threading.Thread(target=loop.run_forever, name="nrvq-sdk-sync-loop", daemon=True).start()
            _BG_LOOP = loop
        return _BG_LOOP


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
    """Run coroutine from sync context on the shared background loop (works with or without an
    active loop in the caller, and keeps loop-bound evaluator resources on ONE stable loop)."""
    return asyncio.run_coroutine_threadsafe(coro, _background_loop()).result()
