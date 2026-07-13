# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangGraph adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.langgraph.adapter import GuardedToolNode


class _FakeToolNode:
    """Capture calls and mimic LangGraph ToolNode."""

    def __init__(self, tools: list[Any]) -> None:
        """Store tools and invocation count."""
        self.tools = tools
        self.calls = 0

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        """Return state with execution marker."""
        self.calls += 1
        return {**state, "executed": True}


@dataclass
class _FakeInterceptor:
    """Track intercepted tool calls and block SQL tool."""

    blocked: set[str] = field(default_factory=set)
    calls: list[tuple[str, dict[str, Any], str]] = field(default_factory=list)

    async def intercept_or_raise(
        self, tool_name: str, tool_params: dict[str, Any], session_id: str = "", framework: str = ""
    ) -> PolicyDecision:
        """Record call and optionally raise block error."""
        self.calls.append((tool_name, tool_params, framework))
        if tool_name in self.blocked:
            raise NorviqBlockError(PolicyDecision(decision="block", rule_id="deny.sql", reason="blocked"))
        return PolicyDecision(decision="allow")


@dataclass
class _Msg:
    """Simple message with tool_calls support."""

    tool_calls: list[dict[str, Any]]


@pytest.fixture
def fake_tool_node(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch adapter ToolNode loader with fake implementation."""
    monkeypatch.setattr("norviq.sdk.langgraph.adapter._get_tool_node", lambda: _FakeToolNode)


async def test_guarded_tool_node_allows_safe_tool_call(fake_tool_node: None) -> None:
    """Safe tool call should execute ToolNode after intercept."""
    interceptor = _FakeInterceptor()
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-1")  # type: ignore[arg-type]
    state = {"messages": [_Msg(tool_calls=[{"name": "search_kb", "args": {"query": "hello"}}])]}
    result = await node(state)
    assert result["executed"] is True
    assert interceptor.calls == [("search_kb", {"query": "hello"}, "langgraph")]
    assert node._node.calls == 1  # type: ignore[attr-defined]


async def test_guarded_tool_node_blocks_sql_and_skips_execution(fake_tool_node: None) -> None:
    """Blocked tool call should raise and avoid ToolNode execution."""
    interceptor = _FakeInterceptor(blocked={"execute_sql"})
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-2")  # type: ignore[arg-type]
    state = {"messages": [_Msg(tool_calls=[{"name": "execute_sql", "args": {"query": "DROP TABLE users"}}])]}
    with pytest.raises(NorviqBlockError):
        await node(state)
    assert node._node.calls == 0  # type: ignore[attr-defined]


async def test_guarded_tool_node_blocks_when_one_of_multiple_is_denied(fake_tool_node: None) -> None:
    """Any blocked call in a batch should abort node execution."""
    interceptor = _FakeInterceptor(blocked={"execute_sql"})
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-3")  # type: ignore[arg-type]
    state = {
        "messages": [
            _Msg(
                tool_calls=[
                    {"name": "search_kb", "args": {"query": "hello"}},
                    {"name": "execute_sql", "args": {"query": "DROP TABLE users"}},
                ]
            )
        ]
    }
    with pytest.raises(NorviqBlockError):
        await node(state)
    assert [call[0] for call in interceptor.calls] == ["search_kb", "execute_sql"]
    assert node._node.calls == 0  # type: ignore[attr-defined]


async def test_guarded_tool_node_passthrough_when_no_tool_calls(fake_tool_node: None) -> None:
    """States without tool calls should pass through to ToolNode."""
    interceptor = _FakeInterceptor()
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-4")  # type: ignore[arg-type]
    result = await node({"messages": [{"content": "hello"}]})
    assert result["executed"] is True
    assert interceptor.calls == []
    assert node._node.calls == 1  # type: ignore[attr-defined]


def test_guarded_tool_node_works_as_state_graph_node() -> None:
    """Guarded node should be accepted by LangGraph StateGraph."""
    langgraph = pytest.importorskip("langgraph.graph")
    messages = pytest.importorskip("langchain_core.messages")
    prebuilt = pytest.importorskip("langgraph.prebuilt")
    state_type = getattr(langgraph, "MessagesState")
    graph_cls = getattr(langgraph, "StateGraph")
    start = getattr(langgraph, "START")
    end = getattr(langgraph, "END")
    guarded = GuardedToolNode(tools=[], interceptor=_FakeInterceptor())  # type: ignore[arg-type]
    graph = graph_cls(state_type)
    graph.add_node("tools", guarded)
    graph.add_edge(start, "tools")
    graph.add_edge("tools", end)
    compiled = graph.compile()
    assert compiled is not None
    assert prebuilt is not None
    assert messages is not None
