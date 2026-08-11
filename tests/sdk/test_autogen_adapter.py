# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for AutoGen adapter interception behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
import structlog.testing

from pydantic import BaseModel

from norviq.exceptions import NorviqBlockError
from norviq.sdk.autogen.adapter import protect
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.langchain.adapter import declared_tool_schemas, forget_declared_tool_schemas


class _FakeBaseTool:
    """Mimic autogen-core's async BaseTool."""

    def __init__(self, name: str) -> None:
        """Store tool name and invocation count."""
        self.name = name
        self.calls = 0

    async def run(self, args: Any, cancellation_token: Any) -> str:
        """Execute and record call args."""
        self.calls += 1
        self.last_args = args
        return f"ran:{self.name}"


@dataclass
class _ArgsModel:
    """Pydantic-like args object exposing model_dump()."""

    query: str

    def model_dump(self) -> dict[str, Any]:
        """Return field dict, matching pydantic's model_dump()."""
        return {"query": self.query}


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
    monkeypatch.setattr("norviq.sdk.autogen.adapter._get_base_tool", lambda: _FakeBaseTool)
    return _FakeBaseTool


async def test_protect_allowed_tool_executes_with_model_dump_args(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Allowed tool call should run and interceptor should see model_dump() output as params."""
    interceptor = _FakeInterceptor()
    tool = _FakeBaseTool("search_kb")
    protected = protect([tool], interceptor, session_id="sess-1")  # type: ignore[arg-type]
    result = await protected[0].run(_ArgsModel(query="hello"), cancellation_token=None)
    assert result == "ran:search_kb"
    assert tool.calls == 1
    assert interceptor.calls == [("search_kb", {"query": "hello"}, "autogen")]


async def test_protect_blocked_tool_raises_and_skips_execution(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Blocked tool call should raise and the underlying tool must not execute."""
    interceptor = _FakeInterceptor(blocked={"execute_sql"})
    tool = _FakeBaseTool("execute_sql")
    protected = protect([tool], interceptor, session_id="sess-2")  # type: ignore[arg-type]
    with pytest.raises(NorviqBlockError):
        await protected[0].run(_ArgsModel(query="DROP TABLE users"), cancellation_token=None)
    assert tool.calls == 0


async def test_protect_passthrough_for_non_base_tool_when_allowed(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Non-BaseTool objects pass through unwrapped only when allow_unwrapped=True, loudly."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with structlog.testing.capture_logs() as cap_logs:
        protected = protect([sentinel], interceptor, allow_unwrapped=True)  # type: ignore[arg-type]
    assert protected == [sentinel]
    assert interceptor.calls == []
    assert any(
        entry["event"] == "nrvq.autogen.unwrapped"
        and entry["log_level"] == "warning"
        and entry["code"] == "NRVQ-SDK-1063"
        for entry in cap_logs
    )


async def test_protect_default_raises_on_non_base_tool_and_evaluates_nothing(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """Fail-closed default: an unrecognized item raises TypeError and nothing is evaluated."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with pytest.raises(TypeError, match="object"):
        protect([sentinel], interceptor)  # type: ignore[arg-type]
    assert interceptor.calls == []


async def test_protect_dict_args_used_as_is(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Plain dict args should be passed through as params unchanged."""
    interceptor = _FakeInterceptor()
    tool = _FakeBaseTool("lookup")
    protected = protect([tool], interceptor)  # type: ignore[arg-type]
    await protected[0].run({"key": "value"}, cancellation_token=None)
    assert interceptor.calls == [("lookup", {"key": "value"}, "autogen")]


async def test_protect_opaque_args_become_str_payload(fake_base_tool: type[_FakeBaseTool]) -> None:
    """Args with neither model_dump() nor dict shape fall back to a str payload."""
    interceptor = _FakeInterceptor()
    tool = _FakeBaseTool("lookup")
    protected = protect([tool], interceptor)  # type: ignore[arg-type]
    await protected[0].run(42, cancellation_token=None)
    assert interceptor.calls == [("lookup", {"args": "42"}, "autogen")]


# ── the DECLARED argument schema is ingested at wrap time ───────────────────────────────────────
#
# autogen-core's `BaseTool` publishes an OpenAI-style tool schema on `.schema`
# (`{"name": ..., "parameters": {"type": "object", "properties": {...}}}`) and the pydantic args
# model on `args_type()`. The adapter read `.name` and threw both away, so a rule authored for
# `issue_refund` could only ever name the tool.


@pytest.fixture(autouse=True)
def _isolate_declared_schemas() -> Any:
    """The declared-schema registry is process-global; no test may inherit another's entries."""
    forget_declared_tool_schemas()
    yield
    forget_declared_tool_schemas()


class _SchemaTool(_FakeBaseTool):
    """Mirrors autogen-core's real `.schema` shape (verified against autogen-core 0.7)."""

    def __init__(self) -> None:
        super().__init__("issue_refund")
        self.schema = {
            "name": "issue_refund",
            "description": "issues a refund",
            "parameters": {
                "type": "object",
                "properties": {
                    "txn_id": {"description": "txn_id", "title": "Txn Id", "type": "string"},
                    "amount": {"description": "amount", "title": "Amount", "type": "number"},
                },
                "required": ["txn_id", "amount"],
                "additionalProperties": False,
            },
            "strict": False,
        }


class _ArgsTypeTool(_FakeBaseTool):
    """A tool that exposes only the pydantic args model, via autogen's `args_type()`."""

    class _Args(BaseModel):
        matter_id: str
        q: str

    def __init__(self) -> None:
        super().__init__("search_matter")

    def args_type(self) -> type[BaseModel]:
        return self._Args


async def test_protect_ingests_the_openai_style_tool_schema(fake_base_tool: type[_FakeBaseTool]) -> None:
    """The `amount` argument is knowable from the framework's own declaration, before any traffic."""
    protect([_SchemaTool()], _FakeInterceptor(), session_id="sess-1")  # type: ignore[arg-type]
    record = declared_tool_schemas()[("autogen", "issue_refund")]
    assert record.schema_available is True
    assert record.param_keys == ("amount", "txn_id")
    assert record.param_keys_truncated is False


async def test_protect_falls_back_to_the_declared_args_model(fake_base_tool: type[_FakeBaseTool]) -> None:
    """`args_type()` is the other statement of the same fact — the legal operator's `matter_id`/`q`."""
    protect([_ArgsTypeTool()], _FakeInterceptor(), session_id="sess-2")  # type: ignore[arg-type]
    record = declared_tool_schemas()[("autogen", "search_matter")]
    assert record.schema_available is True
    assert record.param_keys == ("matter_id", "q")


async def test_an_autogen_tool_with_no_schema_is_recorded_as_UNKNOWN_not_as_empty(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """`_FakeBaseTool` publishes neither — unknown, which must not read as "takes no arguments"."""
    protect([_FakeBaseTool("lookup")], _FakeInterceptor(), session_id="sess-3")  # type: ignore[arg-type]
    record = declared_tool_schemas()[("autogen", "lookup")]
    assert record.schema_available is False
    assert record.param_keys is None
    assert record.unavailable_reason


async def test_an_autogen_schema_that_explodes_does_not_break_wrapping_or_enforcement(
    fake_base_tool: type[_FakeBaseTool],
) -> None:
    """Enforcement is the product; schema ingestion is never allowed to cost it."""

    class _Hostile(_FakeBaseTool):
        @property
        def schema(self) -> Any:
            raise RuntimeError("schema access exploded")

        def args_type(self) -> Any:
            raise RuntimeError("args_type exploded")

    interceptor = _FakeInterceptor()
    protected = protect([_Hostile("hostile_tool")], interceptor, session_id="sess-4")  # type: ignore[arg-type]
    assert await protected[0].run({"key": "value"}, cancellation_token=None) == "ran:hostile_tool"
    assert interceptor.calls == [("hostile_tool", {"key": "value"}, "autogen")]
    record = declared_tool_schemas()[("autogen", "hostile_tool")]
    assert record.schema_available is False
    assert record.param_keys is None
