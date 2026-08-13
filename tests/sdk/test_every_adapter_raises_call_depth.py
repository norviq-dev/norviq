# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-025: every adapter must hold `depth_scope()` for the tool body, not just LangChain.

`chain_depth_limit` blocks when `input.call_depth >= 8`, and that value comes from the `_CALL_DEPTH`
ContextVar, which only advances while an adapter holds `depth_scope()`. Only `langchain/adapter.py`
did. On CrewAI, AutoGen, LangGraph and Semantic Kernel the depth stayed 0 forever, so a
tool-chaining attack that LangChain blocks passed on the other four — at shipped defaults, while the
Compliance view counted the control as enforced. That last part is what makes it worth a test rather
than a note: the product REPORTED a control it could not apply.

These assert the observable property — the depth seen from INSIDE the tool body — rather than
scanning source for the string `depth_scope`, because the thing that broke was whether the scope is
actually held around execution, and a source scan cannot tell a scope held around the interceptor
call from one held around the tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.interceptor import current_call_depth


@dataclass
class _Interceptor:
    """Allows everything, and records the depth the interceptor itself observed."""

    seen: list[int] = field(default_factory=list)

    async def intercept_or_raise(
        self, tool_name: str, tool_params: dict[str, Any], session_id: str = "", framework: str = ""
    ) -> PolicyDecision:
        self.seen.append(current_call_depth())
        return PolicyDecision(decision="allow")


# What every case below actually measures: the depth visible while the tool's own code runs. A tool
# that called another tool from here is what `chain_depth_limit` exists to stop.
_observed: list[int] = []


@pytest.fixture(autouse=True)
def _reset() -> None:
    _observed.clear()


def _record() -> str:
    _observed.append(current_call_depth())
    return "ok"


def test_crewai_holds_the_scope_around_the_tool_body(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Tool:
        name = "search_kb"

        def _run(self, **kwargs: Any) -> str:
            return _record()

    monkeypatch.setattr("norviq.sdk.crewai.adapter._get_base_tool", lambda: _Tool)
    from norviq.sdk.crewai.adapter import protect

    protect([_Tool()], _Interceptor(), session_id="s")[0]._run(q="x")  # type: ignore[arg-type]
    assert _observed == [1], f"crewai tool body ran at depth {_observed}, so chain_depth_limit is inert"


async def test_autogen_holds_the_scope_around_the_tool_body(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Tool:
        name = "search_kb"

        async def run(self, args: Any, cancellation_token: Any) -> str:
            return _record()

    monkeypatch.setattr("norviq.sdk.autogen.adapter._get_base_tool", lambda: _Tool)
    from norviq.sdk.autogen.adapter import protect

    tool = protect([_Tool()], _Interceptor(), session_id="s")[0]  # type: ignore[arg-type]
    await tool.run({"q": "x"}, None)
    assert _observed == [1], f"autogen tool body ran at depth {_observed}, so chain_depth_limit is inert"


async def test_langgraph_holds_the_scope_around_the_node(monkeypatch: pytest.MonkeyPatch) -> None:
    from norviq.sdk.langgraph.adapter import GuardedToolNode

    class _Node:
        def __init__(self, _tools: Any) -> None:
            pass

        async def ainvoke(self, state: dict[str, Any]) -> dict[str, Any]:
            _record()
            return {"messages": []}

    class _Tool:
        name = "search_kb"

    class _Msg:
        tool_calls = [{"name": "search_kb", "args": {"q": "x"}}]

    # GuardedToolNode builds LangGraph's own ToolNode from the tools; substituting it keeps this a
    # test of the depth scope rather than of LangGraph's executor.
    monkeypatch.setattr("norviq.sdk.langgraph.adapter._get_tool_node", lambda: _Node)
    node = GuardedToolNode([_Tool()], _Interceptor(), session_id="s")  # type: ignore[arg-type]
    await node({"messages": [_Msg()]})
    assert _observed == [1], f"langgraph node ran at depth {_observed}, so chain_depth_limit is inert"


async def test_semantic_kernel_holds_the_scope_around_next() -> None:
    from norviq.sdk.semantic_kernel.adapter import policy_filter

    class _Fn:
        name = "search_kb"

    class _Ctx:
        function = _Fn()
        arguments = {"q": "x"}
        result = None

    async def _next(_ctx: Any) -> None:
        _record()

    await policy_filter(_Interceptor(), session_id="s")(_Ctx(), _next)  # type: ignore[arg-type]
    assert _observed == [1], f"SK function ran at depth {_observed}, so chain_depth_limit is inert"


async def test_langchain_still_holds_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one adapter that was already correct — pinned so a refactor cannot quietly drop it."""
    from norviq.sdk.langchain.adapter import protect

    class _Tool:
        name = "search_kb"

        def _run(self, **kwargs: Any) -> str:
            return _record()

    monkeypatch.setattr("norviq.sdk.langchain.adapter._get_base_tool", lambda: _Tool)
    protect([_Tool()], _Interceptor(), session_id="s")[0]._run(q="x")  # type: ignore[arg-type]
    assert _observed == [1]


def test_the_depth_unwinds_after_each_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tool that leaked depth would inflate every SIBLING call after it, blocking benign traffic."""

    class _Tool:
        name = "search_kb"

        def _run(self, **kwargs: Any) -> str:
            return _record()

    monkeypatch.setattr("norviq.sdk.crewai.adapter._get_base_tool", lambda: _Tool)
    from norviq.sdk.crewai.adapter import protect

    tool = protect([_Tool()], _Interceptor(), session_id="s")[0]  # type: ignore[arg-type]
    tool._run(q="a")
    tool._run(q="b")
    assert _observed == [1, 1], "depth leaked between sibling calls"
    assert current_call_depth() == 0
