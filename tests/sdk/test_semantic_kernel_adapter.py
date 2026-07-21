# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for Semantic Kernel adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.semantic_kernel.adapter import policy_filter


class _FakeFunction:
    """Mimic Semantic Kernel's KernelFunction metadata."""

    def __init__(self, name: str, plugin_name: str | None = None) -> None:
        """Store function and plugin name."""
        self.name = name
        self.plugin_name = plugin_name


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
