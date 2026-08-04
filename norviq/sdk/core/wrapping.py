# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Shared tool-wrapping helpers for framework adapters."""

import asyncio
import inspect
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


def _tool_params(
    args: tuple[Any, ...], kwargs: dict[str, Any], sig: inspect.Signature | None = None
) -> dict[str, Any]:
    """Build a stable parameter payload from invocation data.

    Framework control kwargs (``config``/``run_manager``/…) are excluded — they are plumbing, not
    tool arguments, and are not serializable for the evaluate payload.

    POSITIONAL ARGUMENTS ARE BOUND VIA ``Signature.bind``, never by zipping a name list against the
    argument tuple. The difference is the whole safety of this function.

    Without any binding, a positionally-invoked tool reached the engine as ``{"args": [...]}`` and no
    per-argument control could fire — every one of them addresses a parameter BY NAME. That is a hole,
    but a fail-CLOSED one under the deny-by-default policy the intent compiler emits: the rule simply
    never matches.

    Binding by INDEX replaces it with a worse hole. A decorator that injects a leading argument (a
    tenant/retry/audit wrapper, and ``functools.wraps`` makes ``inspect.signature`` report the
    UNDECORATED signature) shifts every name by one, so the engine is told
    ``{"tenant": "collector@attacker.example", "to": "ops@acme.com"}`` while the tool sends to the
    attacker. The operator's ``param_paths.to`` pin inspects a compliant value and ALLOWS. A missing
    name is fail-closed; a WRONG name is fail-open, and it also lies to the near-miss explainer.

    ``bind`` refuses rather than guesses: if the arguments do not fit the signature — which is exactly
    what a shifted convention looks like — it raises, and we fall back to the honest ``{"args": [...]}``
    shape. Better to lose the names than to invent the wrong ones.
    """
    clean_kwargs = {k: v for k, v in kwargs.items() if k not in _FRAMEWORK_CONTROL_KWARGS}
    if not args:
        return clean_kwargs or {"args": []}
    if sig is None:
        return clean_kwargs or {"args": list(args)}

    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError:
        # The call does not fit the signature we read — a decorated/rebound callable, or a framework
        # convention we cannot see. Naming anything here would be a guess.
        return clean_kwargs or {"args": list(args)}

    out: dict[str, Any] = {}
    leftover: list[Any] = []
    for name, value in bound.arguments.items():
        if name in ("self", "cls") or name in _FRAMEWORK_CONTROL_KWARGS:
            continue
        kind = sig.parameters[name].kind
        if kind is inspect.Parameter.VAR_POSITIONAL:
            leftover.extend(value)      # *args genuinely has no name to bind to
        elif kind is inspect.Parameter.VAR_KEYWORD:
            out.update({k: v for k, v in value.items() if k not in _FRAMEWORK_CONTROL_KWARGS})
        else:
            out[name] = value
    if leftover:
        out.setdefault("args", leftover)
    return out or {"args": list(args)}


def callable_signature(func: Any) -> inspect.Signature | None:
    """The signature to bind against, or None when it cannot be trusted.

    ``follow_wrapped=False`` ON PURPOSE. ``functools.wraps`` sets ``__wrapped__``, and
    ``inspect.signature`` follows it by default — reporting the signature of the function UNDERNEATH
    the decorator while the caller is using the decorated convention. Reading the wrapper's own
    signature instead means a wrapper declared ``(self, *a, **k)`` yields no usable names and we fall
    back to the unnamed shape, which is the correct outcome: we do not know the names, so we must not
    claim to.
    """
    try:
        return inspect.signature(func, follow_wrapped=False)
    except (TypeError, ValueError):  # builtins, C extensions, exotic callables
        return None


def _run_sync(coro: Any) -> Any:
    """Run coroutine from sync context on the shared background loop (works with or without an
    active loop in the caller, and keeps loop-bound evaluator resources on ONE stable loop)."""
    return asyncio.run_coroutine_threadsafe(coro, _background_loop()).result()
