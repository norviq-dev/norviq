# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Shared tool-wrapping helpers for framework adapters."""

import asyncio
import inspect
import threading
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.masking import mask_structure

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
    """Opt-in, default OFF: redact PAN/SSN anywhere in an allowed tool's return before it propagates.
    Norviq's PEP is input-only; this is a minimal output-side guard so a tool whose OUTPUT carries sensitive data
    doesn't silently exfiltrate it. Disabled by default → exact passthrough (no hot-path or behavior change)."""
    if not settings.sdk_output_dlp_enabled:
        return result
    # STRUCTURED, not just top-level. This tested `isinstance(result, str)`, so a tool returning a
    # list of rows, a dict record or a paginated envelope — the shapes real tools return — carried a
    # PAN straight through. The MCP plane already redacts structured output
    # (nrvq.mcp.output_dlp.structured_redacted), so the same product masked a card number on one path
    # and missed it on the other while calling both "output DLP".
    masked = mask_structure(result)
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

# ...but "plumbing" is a claim about WHERE the value came from, not about its NAME, and these are
# eight of the most ordinary words in an API. `metadata`, `tags` and `config` are real parameters of
# real tools, and a tool that DECLARES one is not receiving plumbing — it is receiving an argument.
#
# Stripping by name alone deleted those arguments from the payload. Measured through the real
# evaluator and real `opa`, one AWS key in a `tags: str` parameter of `notify_team`:
#
#   payload {"args": [...]} (the value present, merely unnamed)  -> ("block", "llm02_data_leakage")
#   payload {"channel": "C0ATTACKER"} (the value gone)           -> ("allow", "default_allow")
#
# on comprehensive.rego AND webhook/presets/strict.rego. Recovering the argument NAMES made this
# reachable: while the payload was the unnamed `{"args": [...]}` the value was still in it, so the
# data-class detector still saw the credential. Naming the arguments is what let the name-based strip
# find something to delete.
#
# So the strip is now scoped to values that arrived through a ``**kwargs`` the tool never declared —
# which is what injected plumbing actually looks like — and a DECLARED parameter is kept. A declared
# `config`/`run_manager` can still hold a framework object (LangChain injects `RunnableConfig` into a
# parameter annotated for it), so the value is representability-checked rather than trusted; an
# unrepresentable one is reported as the sentinel below rather than dropped. Dropping it would spell
# "I could not represent this argument" exactly like "this call has no such argument", and the engine
# must be able to tell those apart.
_UNREPRESENTABLE = "<nrvq:unrepresentable>"

# Bounds for that check. It runs per call on attacker-controlled input and the engine fails closed at
# a 2s evaluator timeout, so an unbounded walk here would itself be the denial of service. Exceeding
# either bound answers "not representable", which is the fail-closed answer.
_REPR_MAX_NODES = 256
_REPR_MAX_DEPTH = 6


def _is_representable(value: Any) -> bool:
    """Whether ``value`` can enter the evaluate payload as data, decided in bounded work."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > _REPR_MAX_NODES or depth > _REPR_MAX_DEPTH:
            return False
        if item is None or isinstance(item, (str, int, float, bool)):
            continue
        if isinstance(item, (list, tuple)):
            stack.extend((sub, depth + 1) for sub in item)
            continue
        if isinstance(item, dict):
            for key, sub in item.items():
                if not isinstance(key, str):
                    return False
                stack.append((sub, depth + 1))
            continue
        return False
    return True


# The subset LangChain injects into a tool body BY DECLARED PARAMETER NAME: `run_manager` when the
# signature accepts it, `config` when a parameter is annotated `RunnableConfig` (see the adapter's
# `_mirror_signature` — it mirrors annotations for exactly this reason). A declared parameter with one
# of these names really can be plumbing. The other four — `run_id`, `run_name`, `metadata`, `tags` —
# are `.run()`-level kwargs that never reach `_run` as tool arguments, so a parameter a tool declares
# under those names is always the tool's own data.
_FRAMEWORK_INJECTED_PARAMS = frozenset({"config", "run_manager", "callbacks", "callback_manager"})


def _declared_value(name: str, value: Any) -> tuple[bool, Any]:
    """``(keep, value)`` for a parameter the tool itself DECLARED.

    An injected callback manager or ``RunnableConfig`` carries nothing authorization-relevant and does
    not serialize, so it is dropped — that was always the right call and nothing is lost, because it
    is not data. Everything else a tool declares IS data and is kept, whatever it is named. An
    unrepresentable value under a name the framework cannot inject here is reported as the sentinel
    rather than dropped, so "I could not represent this argument" stays distinguishable from "this
    call has no such argument".
    """
    if name not in _FRAMEWORK_CONTROL_KWARGS:
        return True, value
    if name in _FRAMEWORK_INJECTED_PARAMS and (value is None or not _is_representable(value)):
        return False, None
    if _is_representable(value):
        return True, value
    return True, _UNREPRESENTABLE


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
    if sig is None:
        # No signature to consult, so there is no way to tell a declared parameter from injected
        # plumbing. Strip by name, which is the conservative reading when nothing better is knowable.
        return clean_kwargs or {"args": list(args)}

    # Two bind attempts, in this order:
    #   1. the call EXACTLY as it arrived, so nothing about it is assumed;
    #   2. the same call with the framework's plumbing kwargs removed.
    # (2) exists because `callable_signature` may hand back the signature of the tool's own
    # implementation (see there) rather than the framework trampoline's — and a tool body does not
    # declare `config`/`run_manager`, so the exact bind raises on plumbing the tool never asked for.
    #
    # The retry CANNOT renumber anything. Positional arguments map to parameters left-to-right in
    # declaration order, and that mapping does not depend on which keywords accompany them: a keyword
    # can only make a bind FAIL (unexpected/duplicate), never shift a positional onto a different
    # name. So (2) is strictly "the same bind, minus plumbing", not a second guess.
    attempts = [kwargs] if clean_kwargs == kwargs else [kwargs, clean_kwargs]
    bound = None
    for candidate in attempts:
        try:
            bound = sig.bind(*args, **candidate)
            break
        except TypeError:
            continue
    if bound is None:
        # The call does not fit the signature we read — a decorated/rebound callable, or a framework
        # convention we cannot see. Naming anything here would be a guess.
        return clean_kwargs or {"args": list(args)}

    out: dict[str, Any] = {}
    leftover: list[Any] = []
    for name, value in bound.arguments.items():
        if name in ("self", "cls"):
            continue
        kind = sig.parameters[name].kind
        if kind is inspect.Parameter.VAR_POSITIONAL:
            leftover.extend(value)      # *args genuinely has no name to bind to
        elif kind is inspect.Parameter.VAR_KEYWORD:
            # Arrived through a `**kwargs` the tool never declared — this, and only this, is what
            # injected framework plumbing looks like. Strip the control names here.
            out.update({k: v for k, v in value.items() if k not in _FRAMEWORK_CONTROL_KWARGS})
        else:
            # DECLARED by the tool itself, so it is an argument whatever it is called.
            keep, resolved = _declared_value(name, value)
            if keep:
                out[name] = resolved
    if leftover:
        out.setdefault("args", leftover)
    return out or {"args": list(args)}


# Attributes on which a framework tool object hangs the callable its ``_run``/``_arun`` trampoline
# forwards to. LangChain's ``StructuredTool`` (what ``@tool`` produces) and CrewAI's ``Tool`` (what its
# ``@tool`` produces) both use these names.
_IMPLEMENTATION_ATTRS = ("func", "coroutine")


def _binds_no_names(sig: inspect.Signature) -> bool:
    """True when this signature can put a NAME on no positional argument at all.

    That is the ``(*args, **kwargs)`` trampoline shape: every positional the caller supplies lands in
    ``*args``, so binding against it yields the unnamed ``{"args": [...]}`` payload and no
    per-argument control can address the call.
    """
    named = [
        p for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and p.name not in ("self", "cls")
    ]
    if named:
        return False
    return any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())


def _named_positionals(sig: inspect.Signature) -> set[str]:
    return {
        p.name for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and p.name not in ("self", "cls")
    }


def _declared_arg_names(owner: Any) -> set[str]:
    """The argument names the FRAMEWORK itself declares for this tool (``args_schema``), or empty.

    This is a second, independent statement of the same fact — LangChain and CrewAI both build
    ``args_schema`` from the tool's own implementation and both publish it to the model. Requiring it
    to corroborate the signature we read is what keeps the fallthrough below from ever inventing a
    name off some unrelated attribute that merely happens to be called ``func``.
    """
    schema = getattr(owner, "args_schema", None)
    fields = getattr(schema, "model_fields", None)          # pydantic v2
    if not isinstance(fields, dict):
        fields = getattr(schema, "__fields__", None)        # pydantic v1
    if not isinstance(fields, dict):
        return set()
    return {str(k) for k in fields}


def _framework_implementation(trampoline: Any) -> Any | None:
    """The callable a bound ``_run``/``_arun`` trampoline forwards its arguments to, or None."""
    owner = getattr(trampoline, "__self__", None)
    if owner is None:
        return None
    attrs = _IMPLEMENTATION_ATTRS
    if inspect.iscoroutinefunction(trampoline):
        attrs = tuple(reversed(attrs))  # `_arun` forwards to `coroutine`, `_run` to `func`
    for attr in attrs:
        target = getattr(owner, attr, None)
        if callable(target):
            return target
    return None


def callable_signature(func: Any) -> inspect.Signature | None:
    """The signature to bind against, or None when it cannot be trusted.

    ``follow_wrapped=False`` ON PURPOSE. ``functools.wraps`` sets ``__wrapped__``, and
    ``inspect.signature`` follows it by default — reporting the signature of the function UNDERNEATH
    the decorator while the caller is using the decorated convention. Reading the wrapper's own
    signature instead means a wrapper declared ``(self, *a, **k)`` yields no usable names and we fall
    back to the unnamed shape, which is the correct outcome: we do not know the names, so we must not
    claim to.

    THE ``(*args, **kwargs)`` TRAMPOLINE IS NOT THAT CASE, and treating it as if it were left the
    framework's most common tool unnamed. ``@tool`` — the decorator LangChain's own docs lead with —
    produces a ``StructuredTool`` whose ``_run`` is ``(self, *args, config, run_manager=None,
    **kwargs)`` and which forwards those arguments verbatim to ``self.func``; CrewAI's ``@tool`` has
    the same shape. So ``fetch_url.run("https://evil.example/collect")`` reached the engine as
    ``{"args": [...]}`` — fail-closed, but it means a hand-written ``BaseTool`` could be scoped by
    argument name and a decorated one never could.

    When (and only when) the callable we were handed can name NOTHING, we read the signature of the
    implementation it forwards to instead, and accept it only if the framework's own ``args_schema``
    declares those same names. Three independent conditions must all hold, so none of the ways a
    signature goes wrong can slip through:

    * the trampoline itself binds no names (a real ``_run(self, query)`` is used as-is);
    * the implementation binds some (a ``functools.wraps`` wrapper under ``func`` reports ``(*a, **k)``
      — the very skew this function refuses to follow — and we stay unnamed);
    * every name it binds is one the framework already declared for this tool.
    """
    try:
        sig = inspect.signature(func, follow_wrapped=False)
    except (TypeError, ValueError):  # builtins, C extensions, exotic callables
        return None
    if not _binds_no_names(sig):
        return sig

    target = _framework_implementation(func)
    if target is None:
        return sig
    try:
        inner = inspect.signature(target, follow_wrapped=False)
    except (TypeError, ValueError):
        return sig
    if _binds_no_names(inner):
        return sig
    declared = _declared_arg_names(getattr(func, "__self__", None))
    if not declared or not _named_positionals(inner) <= declared:
        return sig
    return inner


def _run_sync(coro: Any) -> Any:
    """Run coroutine from sync context on the shared background loop (works with or without an
    active loop in the caller, and keeps loop-bound evaluator resources on ONE stable loop)."""
    return asyncio.run_coroutine_threadsafe(coro, _background_loop()).result()
