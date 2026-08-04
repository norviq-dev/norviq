# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangGraph adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import BaseModel

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.langchain.adapter import declared_tool_schemas, forget_declared_tool_schemas
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


@dataclass
class _ToolMsg:
    """Mimic a LangGraph ToolMessage carrying a tool's string result."""

    content: Any
    name: str = "export_statement"


class _ResultToolNode:
    """Fake ToolNode returning ToolMessage results (mimics executed tool output)."""

    def __init__(self, tools: list[Any]) -> None:
        """Store tools and the messages to return on invocation."""
        self.tools = tools
        self.calls = 0
        self.messages: list[Any] = [_ToolMsg(content="PAN 4111111111111111 ssn 123-45-6789")]

    async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
        """Return a ToolNode-shaped result with tool messages."""
        self.calls += 1
        return {"messages": list(self.messages)}


@pytest.fixture
def result_tool_node(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch adapter ToolNode loader with a result-producing fake."""
    monkeypatch.setattr("norviq.sdk.langgraph.adapter._get_tool_node", lambda: _ResultToolNode)


async def test_output_dlp_off_is_passthrough(result_tool_node: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """With output DLP disabled (default), tool result content is returned unchanged."""
    from norviq.config import settings

    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", False)
    interceptor = _FakeInterceptor()
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-dlp")  # type: ignore[arg-type]
    state = {"messages": [_Msg(tool_calls=[{"name": "export_statement", "args": {}}])]}
    result = await node(state)
    assert result["messages"][0].content == "PAN 4111111111111111 ssn 123-45-6789"


async def test_output_dlp_on_redacts_tool_message_content(
    result_tool_node: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With output DLP enabled, PAN/SSN in an allowed tool's ToolMessage content are redacted in place."""
    from norviq.config import settings

    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    interceptor = _FakeInterceptor()
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-dlp")  # type: ignore[arg-type]
    state = {"messages": [_Msg(tool_calls=[{"name": "export_statement", "args": {}}])]}
    result = await node(state)
    content = result["messages"][0].content
    assert "4111111111111111" not in content and "****1111" in content
    assert "123-45-6789" not in content and "***-**-6789" in content


async def test_output_dlp_on_leaves_non_string_content(
    result_tool_node: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-string tool content is passed through untouched even with DLP enabled."""
    from norviq.config import settings

    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    interceptor = _FakeInterceptor()
    node = GuardedToolNode(tools=[object()], interceptor=interceptor, session_id="sess-dlp")  # type: ignore[arg-type]
    node._node.messages = [_ToolMsg(content={"rows": 1})]  # type: ignore[attr-defined]
    state = {"messages": [_Msg(tool_calls=[{"name": "export_statement", "args": {}}])]}
    result = await node(state)
    assert result["messages"][0].content == {"rows": 1}


# ── the DECLARED argument schema is ingested when the node is built ─────────────────────────────
#
# `GuardedToolNode` is handed the tool objects themselves, and LangGraph's tools ARE LangChain tools,
# so the argument names the framework already declares are available at construction — before any
# traffic exists to observe them from.


async def test_guarded_tool_node_ingests_the_declared_schema_of_its_tools(fake_tool_node: None) -> None:
    """`issue_refund` carries an argument called `amount`, knowable at graph-build time."""
    forget_declared_tool_schemas()
    try:
        base_tool = pytest.importorskip("langchain_core.tools").BaseTool

        class _RefundArgs(BaseModel):
            txn_id: str
            amount: float

        class _RefundTool(base_tool):  # type: ignore[misc, valid-type]
            name: str = "issue_refund"
            description: str = "issues a refund"
            args_schema: type[BaseModel] = _RefundArgs

            def _run(self, txn_id: str = "", amount: float = 0.0) -> str:
                return "ok"

        GuardedToolNode(tools=[_RefundTool()], interceptor=_FakeInterceptor(), session_id="s")  # type: ignore[arg-type]
        record = declared_tool_schemas()[("langgraph", "issue_refund")]
        assert record.schema_available is True
        assert record.param_keys == ("amount", "txn_id")
    finally:
        forget_declared_tool_schemas()


async def test_a_tool_whose_NAME_explodes_does_not_break_node_construction(fake_tool_node: None) -> None:
    """This is the one adapter where reading a tool's name is NEW work at a point that previously
    did none, so it is the one place ingestion can turn "Norviq could not read a schema" into "your
    graph does not build". `getattr(obj, "name", "")` swallows only AttributeError; a `.name`
    property raising anything else escaped straight out of `__init__` before this was contained."""
    forget_declared_tool_schemas()

    class _NamelessHostile:
        @property
        def name(self) -> str:
            raise RuntimeError("name access exploded")

    try:
        node = GuardedToolNode(
            tools=[_NamelessHostile()], interceptor=_FakeInterceptor(), session_id="s"  # type: ignore[arg-type]
        )
        assert node is not None
        assert declared_tool_schemas() == {}  # nothing was recorded under a name we could not read
    finally:
        forget_declared_tool_schemas()


async def test_a_tool_whose_schema_explodes_does_not_break_node_construction(fake_tool_node: None) -> None:
    """A graph that fails to build because Norviq could not read a schema is the worse outcome."""
    forget_declared_tool_schemas()

    class _Hostile:
        name = "hostile_tool"

        @property
        def args_schema(self) -> Any:
            raise RuntimeError("schema access exploded")

    try:
        interceptor = _FakeInterceptor()
        node = GuardedToolNode(tools=[_Hostile()], interceptor=interceptor, session_id="s")  # type: ignore[arg-type]
        state = {"messages": [_Msg(tool_calls=[{"name": "hostile_tool", "args": {"q": "x"}}])]}
        assert (await node(state))["executed"] is True
        assert interceptor.calls == [("hostile_tool", {"q": "x"}, "langgraph")]
        record = declared_tool_schemas()[("langgraph", "hostile_tool")]
        assert record.schema_available is False
        assert record.param_keys is None
    finally:
        forget_declared_tool_schemas()


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
