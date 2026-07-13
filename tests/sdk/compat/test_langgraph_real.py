# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Real-framework compat test: `norviq.sdk.langgraph.adapter.GuardedToolNode` driven inside a
real compiled `langgraph.graph.StateGraph`, with a real `langchain_core` tool as its payload.

Part of the weekly framework-compat matrix (`.github/workflows/framework-compat.yml`). Runs only
when `langgraph` is installed — `FRAMEWORK` below skips collection of this whole module
otherwise, so it is safe to run in any environment. No Redis, engine, or network: policy
evaluation is faked in-process with the same `_FakeInterceptor` dataclass pattern used by
`tests/sdk/test_langgraph_adapter.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

FRAMEWORK = pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage  # noqa: E402 - after importorskip, by design
from langchain_core.tools import tool  # noqa: E402 - after importorskip, by design
from langgraph.graph import END, START, MessagesState, StateGraph  # noqa: E402 - after importorskip, by design

from norviq.exceptions import NorviqBlockError  # noqa: E402 - after importorskip, by design
from norviq.sdk.core.decisions import PolicyDecision  # noqa: E402 - after importorskip, by design
from norviq.sdk.langgraph.adapter import GuardedToolNode  # noqa: E402 - after importorskip, by design


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


def _compiled_graph(tools: list[Any], interceptor: _FakeInterceptor) -> Any:
    """Compile a minimal real StateGraph whose only node is a real GuardedToolNode."""
    guarded = GuardedToolNode(tools=tools, interceptor=interceptor, session_id="compat-langgraph")
    graph = StateGraph(MessagesState)
    graph.add_node("tools", guarded)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


async def test_allowed_tool_call_executes_through_real_state_graph() -> None:
    """A real compiled StateGraph should execute the wrapped tool body when policy allows the call."""
    executed: list[str] = []

    @tool
    def echo(query: str) -> str:
        """Echo the query back (compat test tool)."""
        executed.append(query)
        return f"echo:{query}"

    interceptor = _FakeInterceptor()
    compiled = _compiled_graph([echo], interceptor)
    state = {"messages": [AIMessage(content="", tool_calls=[{"name": "echo", "args": {"query": "hello"}, "id": "call-1"}])]}
    result = await compiled.ainvoke(state)
    assert executed == ["hello"]
    assert interceptor.calls == [("echo", {"query": "hello"}, "langgraph")]
    tool_messages = [m for m in result["messages"] if getattr(m, "name", None) == "echo"]
    assert tool_messages and tool_messages[0].content == "echo:hello"


async def test_blocked_tool_call_raises_and_never_executes_through_real_state_graph() -> None:
    """A blocked decision should raise before the real tool body ever runs, inside a real graph."""
    executed: list[str] = []

    @tool
    def dangerous(query: str) -> str:
        """A tool that must never run once blocked (compat test tool)."""
        executed.append(query)
        return f"ran:{query}"

    interceptor = _FakeInterceptor(blocked={"dangerous"})
    compiled = _compiled_graph([dangerous], interceptor)
    state = {
        "messages": [AIMessage(content="", tool_calls=[{"name": "dangerous", "args": {"query": "boom"}, "id": "call-2"}])]
    }
    with pytest.raises(NorviqBlockError):
        await compiled.ainvoke(state)
    assert executed == []
