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
    """Opt-in, default OFF: redact PAN/SSN in an allowed tool's string return before it propagates.
    Norviq's PEP is input-only; this is a minimal output-side guard so a tool whose OUTPUT carries sensitive data
    doesn't silently exfiltrate it. Disabled by default → exact passthrough (no hot-path or behavior change)."""
    if not settings.sdk_output_dlp_enabled or not isinstance(result, str):
        return result
    masked = mask_text(result)
    if masked != result:
        log.warning("nrvq.sdk.output_dlp_redacted", tool=tool_name, code="NRVQ-SDK-1043")
    return masked


# Control kwargs a framework injects into a tool's ``_run``/``_arun`` — LangChain's ``RunnableConfig``
# and callback managers. They are plumbing, not tool arguments: they carry no authorization-relevant
# data and are not JSON-serializable, so they must never enter the policy-evaluate payload. Signature
# mirroring (see the LangChain adapter) makes LangChain inject these into our wrapper's ``**kwargs``;
# the wrapper still forwards them to the original tool, but we strip them here so the engine sees only
# the real parameters. Without this, a benign call carrying a ``CallbackManagerForToolRun`` fails to
# serialize and the client fails closed — silently blocking healthy traffic for a non-policy reason.
_FRAMEWORK_CONTROL_KWARGS = frozenset(
    {"config", "run_manager", "callbacks", "callback_manager", "run_id", "run_name", "metadata", "tags"}
)


def _tool_params(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Build a stable parameter payload from invocation data.

    Framework control kwargs (``config``/``run_manager``/…) are excluded — they are plumbing, not
    tool arguments, and are not serializable for the evaluate payload.
    """
    params = {k: v for k, v in kwargs.items() if k not in _FRAMEWORK_CONTROL_KWARGS}
    return params or {"args": list(args)}


def _run_sync(coro: Any) -> Any:
    """Run coroutine from sync context on the shared background loop (works with or without an
    active loop in the caller, and keeps loop-bound evaluator resources on ONE stable loop)."""
    return asyncio.run_coroutine_threadsafe(coro, _background_loop()).result()
