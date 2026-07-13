# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Real-framework compat test: `norviq.sdk.autogen.adapter.protect` against a real
`autogen_core.tools.FunctionTool` (a concrete `autogen_core.tools.BaseTool`).

Part of the weekly framework-compat matrix (`.github/workflows/framework-compat.yml`).
`autogen-core` is not in this repo's dev extras, so this module SKIPS locally — `FRAMEWORK`
below skips collection of the whole module when `autogen_core` isn't installed. It exists for
the CI matrix, which installs `autogen-core` and runs it against whatever AutoGen just released.
No Redis, engine, or network: policy evaluation is faked in-process with the same
`_FakeInterceptor` dataclass pattern used by `tests/sdk/test_langgraph_adapter.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

FRAMEWORK = pytest.importorskip("autogen_core")

from autogen_core import CancellationToken  # noqa: E402 - after importorskip, by design
from autogen_core.tools import FunctionTool  # noqa: E402 - after importorskip, by design

from norviq.exceptions import NorviqBlockError  # noqa: E402 - after importorskip, by design
from norviq.sdk.autogen.adapter import protect  # noqa: E402 - after importorskip, by design
from norviq.sdk.core.decisions import PolicyDecision  # noqa: E402 - after importorskip, by design


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


async def test_allowed_tool_call_executes_through_real_function_tool() -> None:
    """A real FunctionTool's wrapped async run() should execute when policy allows the call."""
    executed: list[str] = []

    async def echo(query: str) -> str:
        """Echo the query back (compat test tool)."""
        executed.append(query)
        return f"echo:{query}"

    real_tool = FunctionTool(echo, description="echo tool for compat testing", name="echo")
    interceptor = _FakeInterceptor()
    protected = protect([real_tool], interceptor, session_id="compat-autogen")
    args_model = real_tool.args_type()(query="hello")
    result = await protected[0].run(args_model, CancellationToken())
    assert result == "echo:hello"
    assert executed == ["hello"]
    assert interceptor.calls == [("echo", {"query": "hello"}, "autogen")]


async def test_blocked_tool_call_raises_and_never_executes_through_real_function_tool() -> None:
    """A blocked decision should raise NorviqBlockError before the real tool body ever runs."""
    executed: list[str] = []

    async def dangerous(query: str) -> str:
        """A tool that must never run once blocked (compat test tool)."""
        executed.append(query)
        return f"ran:{query}"

    real_tool = FunctionTool(dangerous, description="dangerous tool for compat testing", name="dangerous")
    interceptor = _FakeInterceptor(blocked={"dangerous"})
    protected = protect([real_tool], interceptor, session_id="compat-autogen")
    args_model = real_tool.args_type()(query="boom")
    with pytest.raises(NorviqBlockError):
        await protected[0].run(args_model, CancellationToken())
    assert executed == []
