# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for CrewAI adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
import subprocess
import sys
from typing import Any

import pytest
import structlog.testing
from pydantic import BaseModel

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.crewai.adapter import protect
from norviq.sdk.langchain.adapter import declared_tool_schemas, forget_declared_tool_schemas


class _FakeBaseTool:
    """Mimic CrewAI's sync-only BaseTool."""

    def __init__(self, name: str) -> None:
        """Store tool name and invocation count."""
        self.name = name
        self.calls = 0

    def _run(self, *args: Any, **kwargs: Any) -> str:
        """Execute and record call args."""
        self.calls += 1
        self.last_call = (args, kwargs)
        return f"ran:{self.name}"


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


@pytest.fixture
def fake_base_tool(monkeypatch: pytest.MonkeyPatch) -> type[_FakeBaseTool]:
    """Patch adapter BaseTool loader with fake implementation."""
    monkeypatch.setattr("norviq.sdk.crewai.adapter._get_base_tool", lambda: _FakeBaseTool)
    return _FakeBaseTool


def test_protect_allowed_tool_executes_with_kwargs(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Allowed tool call should run and interceptor should see kwargs as params."""
    interceptor = _FakeInterceptor()
    tool = _FakeBaseTool("search_kb")
    protected = protect([tool], interceptor, session_id="sess-1")  # type: ignore[arg-type]
    result = protected[0]._run(query="hello")
    assert result == "ran:search_kb"
    assert tool.calls == 1
    assert interceptor.calls == [("search_kb", {"query": "hello"}, "crewai")]


def test_protect_blocked_tool_raises_and_skips_execution(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Blocked tool call should raise and the underlying tool must not execute."""
    interceptor = _FakeInterceptor(blocked={"execute_sql"})
    tool = _FakeBaseTool("execute_sql")
    protected = protect([tool], interceptor, session_id="sess-2")  # type: ignore[arg-type]
    with pytest.raises(NorviqBlockError):
        protected[0]._run(query="DROP TABLE users")
    assert tool.calls == 0


def test_protect_passthrough_for_non_base_tool_when_allowed(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Non-BaseTool objects pass through unwrapped only when allow_unwrapped=True, loudly."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with structlog.testing.capture_logs() as cap_logs:
        protected = protect([sentinel], interceptor, allow_unwrapped=True)  # type: ignore[arg-type]
    assert protected == [sentinel]
    assert interceptor.calls == []
    assert any(
        entry["event"] == "nrvq.crewai.unwrapped"
        and entry["log_level"] == "warning"
        and entry["code"] == "NRVQ-SDK-1053"
        for entry in cap_logs
    )


def test_protect_default_raises_on_non_base_tool_and_evaluates_nothing(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """Fail-closed default: an unrecognized item raises TypeError and nothing is evaluated."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with pytest.raises(TypeError, match="object"):
        protect([sentinel], interceptor)  # type: ignore[arg-type]
    assert interceptor.calls == []


def test_protect_positional_args_become_args_list(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Positional-only invocation should fall back to an args list payload."""
    interceptor = _FakeInterceptor()
    tool = _FakeBaseTool("lookup")
    protected = protect([tool], interceptor)  # type: ignore[arg-type]
    protected[0]._run("value1")
    assert interceptor.calls == [("lookup", {"args": ["value1"]}, "crewai")]


# ── the DECLARED argument schema is ingested at wrap time ───────────────────────────────────────
#
# CrewAI tools declare `args_schema` exactly as LangChain tools do (both build it from the tool's own
# implementation and both publish it to the model), so the same ingestion runs here. The adapter used
# to read `.name` and discard it.


@pytest.fixture(autouse=True)
def _isolate_declared_schemas() -> Any:
    """The declared-schema registry is process-global; no test may inherit another's entries."""
    forget_declared_tool_schemas()
    yield
    forget_declared_tool_schemas()


class _RefundArgs(BaseModel):
    """The schema a real CrewAI tool declares."""

    txn_id: str
    amount: float


class _SchemaTool(_FakeBaseTool):
    """A CrewAI-shaped tool that declares its arguments."""

    def __init__(self) -> None:
        super().__init__("issue_refund")
        self.args_schema = _RefundArgs


def test_protect_ingests_the_argument_names_crewai_already_declares(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """`issue_refund` is now known to carry an argument called `amount` — before any rule is saved."""
    tool = _SchemaTool()
    protect([tool], _FakeInterceptor(), session_id="sess-1")  # type: ignore[arg-type]
    record = declared_tool_schemas()[("crewai", "issue_refund")]
    assert record.schema_available is True
    assert record.param_keys == ("amount", "txn_id")
    assert record.param_keys_truncated is False


def test_a_crewai_tool_with_no_schema_is_recorded_as_UNKNOWN_not_as_empty(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """`_FakeBaseTool` declares no `args_schema` at all — that is unknown, never "no arguments"."""
    protect([_FakeBaseTool("lookup")], _FakeInterceptor(), session_id="sess-2")  # type: ignore[arg-type]
    record = declared_tool_schemas()[("crewai", "lookup")]
    assert record.schema_available is False
    assert record.param_keys is None
    assert record.unavailable_reason


def test_importing_the_crewai_adapter_does_not_import_langchain() -> None:
    """The shared declared-schema ingestion lives in the LangChain adapter MODULE, and that is only
    acceptable while importing it costs a CrewAI-only install nothing. If someone ever adds a
    top-level `langchain_core` import there, a CrewAI user with no LangChain installed would stop
    being able to import this adapter at all — so the property is pinned rather than assumed."""
    result = subprocess.run(
        [sys.executable, "-c", "import sys, norviq.sdk.crewai.adapter as m; "
                               "print(any(n.startswith('langchain') for n in sys.modules))"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False", result.stdout


def test_a_crewai_schema_that_explodes_does_not_break_wrapping_or_enforcement(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """A tool that stops working because Norviq could not read its schema is the worse outcome."""

    class _Hostile(_FakeBaseTool):
        @property
        def args_schema(self) -> Any:
            raise RuntimeError("schema access exploded")

    interceptor = _FakeInterceptor()
    tool = _Hostile("hostile_tool")
    protected = protect([tool], interceptor, session_id="sess-3")  # type: ignore[arg-type]

    assert protected[0]._run(query="hello") == "ran:hostile_tool"
    assert interceptor.calls == [("hostile_tool", {"query": "hello"}, "crewai")]
    record = declared_tool_schemas()[("crewai", "hostile_tool")]
    assert record.schema_available is False
    assert record.param_keys is None
