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

import inspect  # noqa: E402 - after importorskip, by design

from langchain_core.tools import BaseTool  # noqa: E402 - after importorskip, by design
from langchain_core.tools import tool as make_tool  # noqa: E402 - after importorskip, by design
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


# --- forward-compat: langchain-core 1.x injects `config`/`run_manager` into _run/_arun -------------
# Regression for the crash surfaced by the end-to-end chatbot demo: `create_react_agent`/`ToolNode`
# drive tools through the real `.invoke()`/`.ainvoke()` path, which inspects the tool's `_run`
# signature AND type hints to decide whether to inject a keyword-only `config: RunnableConfig` (and a
# `run_manager`). A `StructuredTool` built from a plain function requires that `config`. Our wrapper is
# `(*args, **kwargs)`, so unless it mirrors BOTH the signature (for `run_manager`, read via
# inspect.signature) and the resolved annotations (for `config`, read via typing.get_type_hints),
# langchain injects nothing and the original `_run` fails with "missing argument 'config'". These
# tests exercise the real framework entrypoint — a direct `._run(...)` call would NOT reproduce it.


def _kb_tool() -> Any:
    """A real StructuredTool (keyword-only `config` on langchain-core 1.x) built from a function."""

    @make_tool
    def lookup(query: str) -> str:
        """Look up an answer for the query."""
        return f"answer:{query}"

    return lookup


def test_structured_tool_invoke_injects_config_and_does_not_crash() -> None:
    """`.invoke()` (the ToolNode entrypoint) must run the body — not raise 'missing config'."""
    interceptor = _FakeInterceptor()
    wrapped = protect([_kb_tool()], interceptor, session_id="compat-langchain")[0]
    # Before the fix this raised: TypeError: StructuredTool._run() missing 'config'.
    assert wrapped.invoke({"query": "refund"}) == "answer:refund"


async def test_structured_tool_ainvoke_injects_config_and_does_not_crash() -> None:
    """Async entrypoint must also run the body without a 'missing config' crash."""
    interceptor = _FakeInterceptor()
    wrapped = protect([_kb_tool()], interceptor, session_id="compat-langchain")[0]
    assert await wrapped.ainvoke({"query": "policy"}) == "answer:policy"


def test_framework_control_kwargs_never_reach_policy_payload() -> None:
    """The RunnableConfig/callback-manager the framework injects are plumbing, not tool params: they
    must not appear in what we send to the engine (and would not be JSON-serializable if they did)."""
    interceptor = _FakeInterceptor()
    wrapped = protect([_kb_tool()], interceptor, session_id="compat-langchain")[0]
    wrapped.invoke({"query": "refund"})
    assert interceptor.calls, "interceptor was never called"
    _name, params, _fw = interceptor.calls[-1]
    assert params == {"query": "refund"}
    assert "config" not in params and "run_manager" not in params


def test_wrapper_is_not_unwrappable_to_original_no_bypass() -> None:
    """Mirroring must not expose `__wrapped__`: `inspect.unwrap` reaching the original `_run` would let
    a framework call the tool body bypassing Norviq's interception (a silent enforcement bypass)."""
    original = _RealEchoTool()
    captured_run = original._run
    wrapped = protect([original], _FakeInterceptor(), session_id="compat-langchain")[0]
    assert wrapped._run is not captured_run
    assert inspect.unwrap(wrapped._run) is wrapped._run  # no __wrapped__ chain to the original
