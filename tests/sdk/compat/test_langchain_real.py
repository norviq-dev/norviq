# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Real-framework compat test: `norviq.sdk.langchain.adapter.protect` against a real
`langchain_core.tools.BaseTool` subclass.

Part of the weekly framework-compat matrix (`.github/workflows/framework-compat.yml`). Runs only
when `langchain-core` is installed — `FRAMEWORK` below skips collection of this whole module
otherwise, so it is safe to run in any environment. No Redis, engine, or network: policy
evaluation is faked in-process with the same `_FakeInterceptor` dataclass pattern used by
`tests/sdk/test_langgraph_adapter.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

FRAMEWORK = pytest.importorskip("langchain_core")

from langchain_core.tools import BaseTool  # noqa: E402 - after importorskip, by design
from pydantic import Field  # noqa: E402 - after importorskip, by design

from norviq.exceptions import NorviqBlockError  # noqa: E402 - after importorskip, by design
from norviq.sdk.core.decisions import PolicyDecision  # noqa: E402 - after importorskip, by design
from norviq.sdk.langchain.adapter import protect  # noqa: E402 - after importorskip, by design


class _RealEchoTool(BaseTool):
    """Real langchain_core BaseTool subclass; records every executed call on itself."""

    name: str = "echo"
    description: str = "echo tool for compat testing"
    executed: list[str] = Field(default_factory=list)

    def _run(self, query: str = "") -> str:
        """Execute sync tool body and record the call."""
        self.executed.append(query)
        return f"echo:{query}"

    async def _arun(self, query: str = "") -> str:
        """Execute async tool body and record the call."""
        self.executed.append(query)
        return f"echo:{query}"


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


async def test_allowed_tool_call_executes_through_real_base_tool() -> None:
    """A real BaseTool's wrapped async body should execute when policy allows the call."""
    tool = _RealEchoTool()
    interceptor = _FakeInterceptor()
    wrapped = protect([tool], interceptor, session_id="compat-langchain")
    result = await wrapped[0]._arun(query="hello")
    assert result == "echo:hello"
    assert tool.executed == ["hello"]
    assert interceptor.calls == [("echo", {"query": "hello"}, "langchain")]


async def test_blocked_tool_call_raises_and_never_executes_through_real_base_tool() -> None:
    """A blocked decision should raise NorviqBlockError before the real tool body ever runs."""
    tool = _RealEchoTool()
    interceptor = _FakeInterceptor(blocked={"echo"})
    wrapped = protect([tool], interceptor, session_id="compat-langchain")
    with pytest.raises(NorviqBlockError):
        await wrapped[0]._arun(query="boom")
    assert tool.executed == []
