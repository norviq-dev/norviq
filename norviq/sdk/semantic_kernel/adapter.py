# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Semantic Kernel adapter for Norviq tool interception.

Semantic Kernel's idiomatic interception point is a function-invocation filter, not a tool
wrapper: an async callable `(context, next)` registered via `kernel.add_filter`. A filter
needs no `semantic_kernel` import at all — it duck-types on the `context` object — so, unlike
the other adapters, this module has no lazy framework loader and imports cleanly with or
without `semantic-kernel` installed.

Semantic Kernel is also Azure's agent framework runtime, so this module doubles as the Azure
integration point: Microsoft Agent Framework middleware can call the same generic
`ToolInterceptor.intercept_or_raise` used here, since the interceptor only depends on
`SupportsEvaluate` and plain tool-name/params strings, not on any Semantic-Kernel type.

Usage::

    kernel.add_filter("function_invocation", policy_filter(interceptor))
"""

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.interceptor import ToolInterceptor, depth_scope
from norviq.sdk.core.wrapping import _output_dlp
# Shared declared-schema ingestion. It lives in the LangChain adapter module only because this
# change is scoped to the five adapter files (see the banner there); that module imports no
# framework at import time, so this one still imports cleanly with or without SK installed.
from norviq.sdk.langchain.adapter import declared_tool_schema, ingest_declared_schema

log = structlog.get_logger()

_FilterFunc = Callable[[Any, Callable[[Any], Awaitable[None]]], Awaitable[None]]

# Where SK states a function's declared arguments: `KernelFunctionMetadata.parameters`, a list of
# `KernelParameterMetadata` (each a `name` plus a per-parameter JSON Schema on `schema_data`), with
# the function's own `.parameters` property as the equivalent second route.
_SK_SCHEMA_ATTRS = ("metadata.parameters", "parameters")


def _ingest_function_schema(context: Any, tool_name: str) -> None:
    """Ingest SK's own declaration of this function's arguments, ONCE per function.

    There is no wrap step to hang this on — SK's integration point is a filter — so it happens the
    first time a function is seen. Every later invocation costs one dict lookup, and the whole thing
    is contained: a context shape we cannot read must never keep a call from being evaluated.
    """
    try:
        if not tool_name or getattr(context, "function", None) is None:
            # No function object means no tool to key a record on. `_extract_tool_name` falls back
            # to the literal "unknown", and registering THAT would put a row in the registry for a
            # tool that does not exist.
            return
        if declared_tool_schema("semantic-kernel", tool_name) is not None:
            # Already known: one O(1) lookup is all a later invocation costs.
            #
            # KNOWN LIMITATION, stated rather than hidden. Records are keyed by the BARE function
            # name because that is Norviq's policy identity (see `_extract_tool_name`), so if two
            # plugins each serve an `issue_refund` with DIFFERENT arguments, the first one invoked is
            # the one whose argument names are recorded. Both are the same policy target, so the
            # honest answer is the union of their declarations; producing it needs a per-function
            # merge that is not built yet, and re-ingesting on every invocation to discover the
            # collision would put schema work on the hot path.
            return
        ingest_declared_schema(
            context.function,
            tool_name=tool_name,
            framework="semantic-kernel",
            attrs=_SK_SCHEMA_ATTRS,
        )
    except Exception as exc:  # noqa: BLE001 - ingestion must never affect enforcement
        log.warning(
            "nrvq.semantic_kernel.schema_ingest_failed",
            tool=tool_name,
            error=str(exc),
            code="NRVQ-SDK-1074",
        )


def _extract_tool_name(context: Any) -> str:
    """The BARE Semantic Kernel function name, never plugin-qualified.

    Norviq policies match on a framework-agnostic tool name: a `delete_record` rule must enforce
    identically whether the tool is a LangChain `BaseTool`, a CrewAI tool, an AutoGen `FunctionTool`,
    or an SK `@kernel_function`. SK addresses functions plugin-qualified (`support.delete_record`), so
    sending that qualified name here made the SAME policy silently NOT match under SK — a cross-framework
    enforcement bypass (the call was allowed because `support.delete_record != delete_record`). We send
    the bare function name to stay consistent with every other adapter; plugin scoping is an SK addressing
    detail, not part of the policy identity. Never crashes on unexpected shapes."""
    try:
        function = getattr(context, "function", None)
        name = getattr(function, "name", None)
        return str(name) if name else "unknown"
    except Exception:  # noqa: BLE001 - name extraction must never block evaluation
        return "unknown"


def _extract_tool_params(context: Any) -> dict[str, Any]:
    """Best-effort argument dict; failure yields {} rather than skipping evaluation."""
    try:
        arguments = getattr(context, "arguments", None)
        return dict(arguments) if arguments else {}
    except Exception:  # noqa: BLE001 - params extraction must never block evaluation
        return {}


def _apply_output_dlp(context: Any, tool_name: str) -> None:
    """Best-effort output DLP on the function result; enforcement above already ran."""
    try:
        # semantic-kernel's FunctionInvocationContext exposes the result as `.result`
        # (verified against SK 1.44 model_fields); `.function_result` kept as a fallback
        # for older/alternative context shapes.
        function_result = getattr(context, "result", None)
        if function_result is None:
            function_result = getattr(context, "function_result", None)
        if function_result is None:
            return
        value = getattr(function_result, "value", None)
        if not isinstance(value, str):
            return
        masked = _output_dlp(tool_name, value)
        if masked != value:
            function_result.value = masked
    except Exception as exc:  # noqa: BLE001 - DLP is best-effort, must not affect the result
        log.warning("nrvq.semantic_kernel.output_dlp_failed", tool=tool_name, error=str(exc), code="NRVQ-SDK-1073")


def policy_filter(interceptor: ToolInterceptor, session_id: str = "") -> _FilterFunc:
    """Return a Semantic Kernel function-invocation filter enforcing Norviq policy.

    Register with `kernel.add_filter("function_invocation", policy_filter(interceptor))`.
    A block/escalate decision raises and `next(context)` is never called, so the underlying
    function never runs (fail-closed).
    """

    async def _filter(context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        """Evaluate policy before delegating to the next filter/function in the chain."""
        tool_name = _extract_tool_name(context)
        tool_params = _extract_tool_params(context)
        _ingest_function_schema(context, tool_name)
        try:
            await interceptor.intercept_or_raise(
                tool_name=tool_name,
                tool_params=tool_params,
                session_id=session_id,
                framework="semantic-kernel",
            )
        except (NorviqBlockError, NorviqEscalateError):
            log.warning("nrvq.semantic_kernel.denied", tool=tool_name, code="NRVQ-SDK-1072")
            raise
        log.info("nrvq.semantic_kernel.allowed", tool=tool_name, code="NRVQ-SDK-1071")
        # `next(context)` runs the rest of the filter chain and then the function itself, so it is
        # this framework's tool body: a function invoked from inside it re-enters this filter and
        # must report a deeper level. Without it `_CALL_DEPTH` stays 0 and `chain_depth_limit`
        # cannot fire at any depth (F-025).
        with depth_scope():
            await next(context)
        _apply_output_dlp(context, tool_name)

    log.debug("nrvq.semantic_kernel.filter_created", code="NRVQ-SDK-1070")
    return _filter
