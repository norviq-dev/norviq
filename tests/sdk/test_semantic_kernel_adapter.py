# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for Semantic Kernel adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.langchain.adapter import (
    declared_tool_schemas,
    forget_declared_tool_schemas,
)
from norviq.sdk.semantic_kernel.adapter import policy_filter


class _FakeParameter:
    """Mimic SK's KernelParameterMetadata (verified against semantic-kernel 1.36: a `name` plus a
    per-parameter JSON Schema on `schema_data`)."""

    def __init__(self, name: str, schema_data: Any = None) -> None:
        """Store the declared parameter name and its JSON Schema."""
        self.name = name
        self.schema_data = schema_data


class _FakeMetadata:
    """Mimic SK's KernelFunctionMetadata."""

    def __init__(self, name: str, parameters: list[Any]) -> None:
        """Store the function name and its declared parameters."""
        self.name = name
        self.parameters = parameters


class _FakeFunction:
    """Mimic Semantic Kernel's KernelFunction metadata."""

    def __init__(self, name: str, plugin_name: str | None = None, metadata: Any = None) -> None:
        """Store function and plugin name, plus the declared-parameter metadata SK carries."""
        self.name = name
        self.plugin_name = plugin_name
        if metadata is not None:
            self.metadata = metadata


class _FakeFunctionResult:
    """Mimic Semantic Kernel's FunctionResult."""

    def __init__(self, value: Any) -> None:
        """Store result value."""
        self.value = value


class _FakeContext:
    """Mimic Semantic Kernel's FunctionInvocationContext.

    Real SK (>=1.x, verified on 1.44) exposes the invocation result as ``.result`` —
    this fake mirrors that so the DLP test exercises the REAL attribute contract
    (the old ``function_result`` name was a fake-drift bug that masked a dead DLP path).
    """

    def __init__(self, function: Any = None, arguments: Any = None, result: Any = None) -> None:
        """Store context fields used by the filter."""
        self.function = function
        self.arguments = arguments
        self.result = result


class _UnIterableArguments:
    """Truthy object that is not dict()-able, to force params extraction failure."""

    def __bool__(self) -> bool:
        """Report truthy so dict() conversion is attempted."""
        return True


@dataclass
class _FakeInterceptor:
    """Track intercepted tool calls and block named tools."""

    blocked: set[str] = field(default_factory=set)
    calls: list[tuple[str, dict[str, Any], str]] = field(default_factory=list)

    async def intercept_or_raise(
        self, tool_name: str, tool_params: dict[str, Any], session_id: str = "", framework: str = ""
    ) -> PolicyDecision:
        """Record call and optionally raise block error."""
        self.calls.append((tool_name, tool_params, framework))
        if tool_name in self.blocked:
            raise NorviqBlockError(PolicyDecision(decision="block", rule_id="deny.tool", reason="blocked"))
        return PolicyDecision(decision="allow")


async def test_filter_allows_and_calls_next_with_params(monkeypatch: pytest.MonkeyPatch) -> None:
    """Allowed call should reach next() and interceptor should see name/params/framework."""
    interceptor = _FakeInterceptor()
    context = _FakeContext(function=_FakeFunction("search_kb"), arguments={"query": "hello"})
    next_calls: list[Any] = []

    async def next_fn(ctx: Any) -> None:
        next_calls.append(ctx)

    filt = policy_filter(interceptor, session_id="sess-1")  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert next_calls == [context]
    assert interceptor.calls == [("search_kb", {"query": "hello"}, "semantic-kernel")]


async def test_filter_blocks_and_never_calls_next() -> None:
    """Blocked call should raise and the underlying function must not execute."""
    interceptor = _FakeInterceptor(blocked={"execute_sql"})
    context = _FakeContext(function=_FakeFunction("execute_sql"), arguments={"query": "DROP TABLE users"})
    next_calls: list[Any] = []

    async def next_fn(ctx: Any) -> None:
        next_calls.append(ctx)

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    with pytest.raises(NorviqBlockError):
        await filt(context, next_fn)
    assert next_calls == []


async def test_filter_name_extraction_failure_still_evaluates() -> None:
    """A context with no usable function shape must still be evaluated, never skipped."""
    interceptor = _FakeInterceptor()
    context = object()  # no `.function`, no `.arguments`
    next_calls: list[Any] = []

    async def next_fn(ctx: Any) -> None:
        next_calls.append(ctx)

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert interceptor.calls == [("unknown", {}, "semantic-kernel")]
    assert next_calls == [context]


async def test_filter_sends_bare_name_not_plugin_qualified() -> None:
    """The tool name evaluated must be the BARE function name, never plugin-qualified.

    Norviq policies match on a framework-agnostic tool name. Sending SK's plugin-qualified
    'email.send' made a 'send' policy silently not match under Semantic Kernel while it enforced fine
    under LangChain/CrewAI/AutoGen — a cross-framework enforcement bypass. The bare name keeps SK
    consistent with every other adapter."""
    interceptor = _FakeInterceptor()
    context = _FakeContext(function=_FakeFunction("send", plugin_name="email"), arguments={})

    async def next_fn(ctx: Any) -> None:
        pass

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert interceptor.calls == [("send", {}, "semantic-kernel")]


async def test_filter_params_extraction_failure_still_evaluates() -> None:
    """Arguments that can't be dict()-ed must fall back to {} without skipping evaluation."""
    interceptor = _FakeInterceptor()
    context = _FakeContext(function=_FakeFunction("lookup"), arguments=_UnIterableArguments())

    async def next_fn(ctx: Any) -> None:
        pass

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert interceptor.calls == [("lookup", {}, "semantic-kernel")]


async def test_filter_applies_output_dlp_after_next(monkeypatch: pytest.MonkeyPatch) -> None:
    """When output DLP is enabled, a str context.result.value should be redacted in place."""
    from norviq.config import settings

    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    interceptor = _FakeInterceptor()
    result = _FakeFunctionResult("ssn 123-45-6789")
    context = _FakeContext(function=_FakeFunction("lookup"), arguments={}, result=result)

    async def next_fn(ctx: Any) -> None:
        pass

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert "123-45-6789" not in result.value
    assert "***-**-6789" in result.value


# ── the DECLARED argument schema is ingested when the filter first sees a function ──────────────
#
# Semantic Kernel has no wrap step — the integration point is a filter — so ingestion happens the
# first time a function is seen, from the metadata SK already carries (`function.metadata.parameters`,
# each a `KernelParameterMetadata` with `name` and `schema_data`). It is recorded ONCE per function:
# after that, the ingest path is one dict lookup on the hot path.


@pytest.fixture(autouse=True)
def _isolate_declared_schemas() -> Any:
    """The declared-schema registry is process-global; no test may inherit another's entries."""
    forget_declared_tool_schemas()
    yield
    forget_declared_tool_schemas()


async def test_filter_ingests_the_declared_kernel_parameters() -> None:
    """`issue_refund` is known to carry an argument called `amount` from SK's own metadata."""
    interceptor = _FakeInterceptor()
    metadata = _FakeMetadata(
        "issue_refund",
        [_FakeParameter("txn_id", {"type": "string"}), _FakeParameter("amount", {"type": "number"})],
    )
    context = _FakeContext(
        function=_FakeFunction("issue_refund", plugin_name="billing", metadata=metadata),
        arguments={"txn_id": "TXN-8891", "amount": 25.0},
    )

    async def next_fn(ctx: Any) -> None:
        pass

    await policy_filter(interceptor)(context, next_fn)  # type: ignore[arg-type]
    record = declared_tool_schemas()[("semantic-kernel", "issue_refund")]
    assert record.schema_available is True
    assert record.param_keys == ("amount", "txn_id")
    assert record.param_keys_truncated is False


async def test_a_function_declaring_no_parameters_is_not_spelled_like_one_we_could_not_read() -> None:
    """SK says "this function takes nothing"; a function with no metadata says nothing at all."""
    interceptor = _FakeInterceptor()

    async def next_fn(ctx: Any) -> None:
        pass

    empty_ctx = _FakeContext(function=_FakeFunction("ping", metadata=_FakeMetadata("ping", [])), arguments={})
    await policy_filter(interceptor)(empty_ctx, next_fn)  # type: ignore[arg-type]
    bare_ctx = _FakeContext(function=_FakeFunction("lookup"), arguments={})
    await policy_filter(interceptor)(bare_ctx, next_fn)  # type: ignore[arg-type]

    empty = declared_tool_schemas()[("semantic-kernel", "ping")]
    unknown = declared_tool_schemas()[("semantic-kernel", "lookup")]
    assert empty.schema_available is True and empty.param_keys == ()
    assert unknown.schema_available is False and unknown.param_keys is None
    assert empty.as_dict() != unknown.as_dict()


async def test_a_context_with_no_function_records_nothing_and_still_evaluates() -> None:
    """No function object means no tool to key a record on — inventing one under the name we fall
    back to ("unknown") would put a row in the registry for a tool that does not exist."""
    interceptor = _FakeInterceptor()

    async def next_fn(ctx: Any) -> None:
        pass

    await policy_filter(interceptor)(object(), next_fn)  # type: ignore[arg-type]
    assert declared_tool_schemas() == {}
    assert interceptor.calls == [("unknown", {}, "semantic-kernel")]


async def test_metadata_that_explodes_does_not_stop_the_call_being_evaluated() -> None:
    """Enforcement is the product; schema ingestion is never allowed to cost it."""

    class _HostileFunction:
        name = "hostile_tool"

        @property
        def metadata(self) -> Any:
            raise RuntimeError("metadata access exploded")

    interceptor = _FakeInterceptor()
    context = _FakeContext(function=_HostileFunction(), arguments={"query": "hello"})
    next_calls: list[Any] = []

    async def next_fn(ctx: Any) -> None:
        next_calls.append(ctx)

    await policy_filter(interceptor)(context, next_fn)  # type: ignore[arg-type]
    assert interceptor.calls == [("hostile_tool", {"query": "hello"}, "semantic-kernel")]
    assert next_calls == [context]
    record = declared_tool_schemas()[("semantic-kernel", "hostile_tool")]
    assert record.schema_available is False
    assert record.param_keys is None


async def test_filter_output_dlp_legacy_function_result_attr(monkeypatch: pytest.MonkeyPatch) -> None:
    """The legacy `.function_result` context shape must still get DLP (fallback path)."""
    from norviq.config import settings

    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    interceptor = _FakeInterceptor()
    result = _FakeFunctionResult("ssn 123-45-6789")
    context = _FakeContext(function=_FakeFunction("lookup"), arguments={})
    context.function_result = result  # legacy attribute name, no `.result`
    context.result = None

    async def next_fn(ctx: Any) -> None:
        pass

    filt = policy_filter(interceptor)  # type: ignore[arg-type]
    await filt(context, next_fn)
    assert "123-45-6789" not in result.value
    assert "***-**-6789" in result.value


async def test_a_saturated_registry_does_not_put_a_schema_walk_in_front_of_every_call() -> None:
    """Semantic Kernel is the ONE adapter that ingests from inside the filter, so its short-circuit
    is on the evaluate path. It short-circuits on "already recorded" — and a saturated registry can
    never record, so without a second guard every invocation of the 1025th tool re-walks the schema
    and re-emits a warning, forever, in front of `intercept_or_raise`. The engine fails CLOSED at a
    2s timeout, which makes repeated unbounded work in front of it an availability defect, not a
    performance nit."""
    import norviq.sdk.langchain.adapter as schema_registry

    walks: list[str] = []
    real_walk = schema_registry._declared_param_keys

    def _counting_walk(schema: Any) -> Any:
        walks.append("walk")
        return real_walk(schema)

    metadata = _FakeMetadata("issue_refund", [_FakeParameter("txn_id"), _FakeParameter("amount")])
    context = _FakeContext(
        function=_FakeFunction("issue_refund", plugin_name="billing", metadata=metadata),
        arguments={"txn_id": "TXN-8891"},
    )
    interceptor = _FakeInterceptor()

    async def next_fn(ctx: Any) -> None:
        pass

    for i in range(schema_registry._MAX_REGISTERED_TOOLS):
        schema_registry._DECLARED[("filler", f"tool_{i}")] = schema_registry.DeclaredToolSchema(
            tool=f"tool_{i}", framework="filler", source="", param_keys=(),
            param_keys_truncated=False, unavailable_reason="",
        )
    schema_registry._declared_param_keys = _counting_walk  # type: ignore[assignment]
    try:
        filt = policy_filter(interceptor)  # type: ignore[arg-type]
        for _ in range(5):
            await filt(context, next_fn)
    finally:
        schema_registry._declared_param_keys = real_walk  # type: ignore[assignment]

    assert walks == [], "the schema was walked on the evaluate path of a saturated registry"
    # ...and the calls were still evaluated: refusing to ingest never refuses to enforce.
    assert len(interceptor.calls) == 5
    # The tool's arguments are UNKNOWN, which is not the same statement as "it has none".
    assert declared_tool_schemas().get(("semantic-kernel", "issue_refund")) is None
