# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Real-framework compat test: `norviq.sdk.semantic_kernel.adapter.policy_filter` registered on
a real `semantic_kernel.Kernel`, invoking a real `@kernel_function`-decorated plugin method.

Part of the weekly framework-compat matrix (`.github/workflows/framework-compat.yml`).
`semantic-kernel` is not in this repo's dev extras, so this module SKIPS locally — `FRAMEWORK`
below skips collection of the whole module when `semantic_kernel` isn't installed. It exists for
the CI matrix, which installs `semantic-kernel` and runs it against whatever SK just released.
No Redis, engine, or network: policy evaluation is faked in-process with the same
`_FakeInterceptor` dataclass pattern used by `tests/sdk/test_langgraph_adapter.py`.

Semantic Kernel's function-invocation pipeline wraps/re-raises exceptions raised inside a filter,
so a block doesn't necessarily surface as a bare `NorviqBlockError` at the `kernel.invoke()` call
site — the block test below catches broadly and walks `__cause__`/`__context__` to find it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

FRAMEWORK = pytest.importorskip("semantic_kernel")

from semantic_kernel import Kernel  # noqa: E402 - after importorskip, by design
from semantic_kernel.functions import KernelArguments, kernel_function  # noqa: E402 - after importorskip, by design

from norviq.exceptions import NorviqBlockError  # noqa: E402 - after importorskip, by design
from norviq.sdk.core.decisions import PolicyDecision  # noqa: E402 - after importorskip, by design
from norviq.sdk.semantic_kernel.adapter import policy_filter  # noqa: E402 - after importorskip, by design


@dataclass
class _FakeInterceptor:
    """Track intercepted tool calls and block named tools (no Redis/engine/network)."""

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


class _EchoPlugin:
    """Real Semantic Kernel plugin; records every executed call into the list it's given."""

    def __init__(self, executed: list[str]) -> None:
        """Store the shared executed-call log."""
        self._executed = executed

    @kernel_function(name="echo", description="Echo the query back (compat test function).")
    def echo(self, query: str) -> str:
        """Execute the real kernel function body and record the call."""
        self._executed.append(query)
        return f"echo:{query}"


def _cause_chain(exc: BaseException) -> list[BaseException]:
    """Walk __cause__/__context__ from exc to build the full exception chain."""
    chain: list[BaseException] = []
    cursor: BaseException | None = exc
    while cursor is not None and cursor not in chain:
        chain.append(cursor)
        cursor = cursor.__cause__ or cursor.__context__
    return chain


async def test_allowed_tool_call_executes_through_real_kernel() -> None:
    """A real kernel_function should execute when the registered filter's policy allows the call."""
    executed: list[str] = []
    kernel = Kernel()
    kernel.add_plugin(_EchoPlugin(executed), plugin_name="test")
    interceptor = _FakeInterceptor()
    kernel.add_filter("function_invocation", policy_filter(interceptor, session_id="compat-sk"))

    result = await kernel.invoke(function_name="echo", plugin_name="test", arguments=KernelArguments(query="hello"))

    assert str(result) == "echo:hello"
    assert executed == ["hello"]
    # BARE function name, not plugin-qualified 'test.echo' — a framework-agnostic policy must match
    # under SK exactly as it does under the other adapters (see adapter._extract_tool_name).
    assert interceptor.calls == [("echo", {"query": "hello"}, "semantic-kernel")]


async def test_blocked_tool_call_raises_and_never_executes_through_real_kernel() -> None:
    """A blocked decision should abort before the real kernel function body ever runs.

    Semantic Kernel's invocation pipeline may wrap the raised NorviqBlockError, so this asserts
    on the full __cause__/__context__ chain rather than the raw exception type.
    """
    executed: list[str] = []
    kernel = Kernel()
    kernel.add_plugin(_EchoPlugin(executed), plugin_name="test")
    # a policy written for the bare tool name 'echo' must block the SK-hosted function (it would NOT
    # if the adapter still sent the plugin-qualified 'test.echo' — the cross-framework bypass this guards)
    interceptor = _FakeInterceptor(blocked={"echo"})
    kernel.add_filter("function_invocation", policy_filter(interceptor, session_id="compat-sk"))

    raised: BaseException | None = None
    try:
        await kernel.invoke(function_name="echo", plugin_name="test", arguments=KernelArguments(query="boom"))
    except Exception as exc:  # noqa: BLE001 - SK may re-wrap the block error; chain-walked below
        raised = exc

    assert raised is not None, "kernel.invoke() should have raised on a blocked decision"
    assert any(isinstance(e, NorviqBlockError) for e in _cause_chain(raised))
    assert executed == []
