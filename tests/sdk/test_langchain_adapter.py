# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangChain adapter wrappers."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
import os
from typing import Any
import uuid

import pytest
import structlog.testing

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _run_sync
from norviq.sdk.langchain.adapter import protect
from tests.conftest import flush_runtime

try:
    from langchain_core.tools import BaseTool
except ImportError:  # pragma: no cover - fallback for older langchain.
    from langchain.tools import BaseTool


class _TestTool(BaseTool):
    """Simple sync/async tool for adapter tests."""

    name: str = "search_kb"
    description: str = "test tool"

    def _run(self, query: str = "") -> str:
        """Execute sync tool body."""
        return f"sync:{query}"

    async def _arun(self, query: str = "") -> str:
        """Execute async tool body."""
        return f"async:{query}"


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def interceptor(redis_url: str, seeded_loader) -> AsyncIterator[ToolInterceptor]:
    """Create ToolInterceptor for adapter tests (comprehensive.rego cluster baseline)."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    await flush_runtime(cache)  # isolate trust/cache from the prior block test in this file
    evaluator = OPAEvaluator(cache)
    evaluator.bind_loader(seeded_loader)
    resolver = SPIFFEResolver()
    yield ToolInterceptor(evaluator=evaluator, resolver=resolver)
    # Sync-path tests evaluate on _run_sync's persistent background loop, so the evaluator's audit
    # tasks and the redis connections it used live THERE and can't be awaited/closed from the pytest
    # loop — drain each on the loop it was created on. (Same documented sharp edge as the adapter
    # docstring: loop-bound in-process evaluators prefer the async path.)
    try:
        await evaluator.close()
    except RuntimeError:
        _run_sync(evaluator.close())
    try:
        await cache.close()
    except RuntimeError:
        _run_sync(cache.close())


def _session() -> str:
    """Create isolated session id."""
    return uuid.uuid4().hex


@dataclass
class _FakeInterceptor:
    """Track intercepted tool calls without a real evaluator (used for the passthrough/raise tests,
    which never reach an evaluator and so don't need the Redis-backed fixture above)."""

    calls: list[tuple[str, dict[str, Any], str]] = field(default_factory=list)

    async def intercept_or_raise(
        self, tool_name: str, tool_params: dict[str, Any], session_id: str = "", framework: str = ""
    ) -> PolicyDecision:
        """Record call; never raises in this fake."""
        self.calls.append((tool_name, tool_params, framework))
        return PolicyDecision(decision="allow")


async def test_protect_blocked_tool_raises(interceptor: ToolInterceptor) -> None:
    """Blocked calls should raise before original tool body executes."""
    tool = _TestTool(name="execute_sql")
    wrapped = protect([tool], interceptor, session_id=_session())
    with pytest.raises(NorviqBlockError):
        await wrapped[0]._arun(query="DROP TABLE users")


async def test_protect_allowed_tool_executes(interceptor: ToolInterceptor) -> None:
    """Allowed calls should execute wrapped sync body."""
    tool = _TestTool(name="search_kb")
    wrapped = protect([tool], interceptor, session_id=_session())
    assert wrapped[0]._run(query="hello") == "sync:hello"


async def test_protect_async_tool_executes(interceptor: ToolInterceptor) -> None:
    """Allowed calls should execute wrapped async body."""
    tool = _TestTool(name="search_kb")
    wrapped = protect([tool], interceptor, session_id=_session())
    assert await wrapped[0]._arun(query="hello") == "async:hello"


def test_protect_passthrough_for_non_base_tool_when_allowed() -> None:
    """Non-BaseTool objects pass through unwrapped only when allow_unwrapped=True, loudly."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with structlog.testing.capture_logs() as cap_logs:
        protected = protect([sentinel], interceptor, allow_unwrapped=True)  # type: ignore[arg-type]
    assert protected == [sentinel]
    assert interceptor.calls == []
    assert any(
        entry["event"] == "nrvq.langchain.unwrapped"
        and entry["log_level"] == "warning"
        and entry["code"] == "NRVQ-SDK-1044"
        for entry in cap_logs
    )


def test_protect_default_raises_on_non_base_tool_and_evaluates_nothing() -> None:
    """Fail-closed default: an unrecognized item raises TypeError and nothing is evaluated."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with pytest.raises(TypeError, match="object"):
        protect([sentinel], interceptor)  # type: ignore[arg-type]
    assert interceptor.calls == []


# ── positional arguments reach the engine WITH THEIR NAMES ──────────────────────────────────────
#
# `_tool_params` returned `{"args": [...]}` for any positionally-invoked tool, and that is a hole in
# enforcement rather than a cosmetic difference. Every per-argument control Norviq offers addresses a
# parameter BY NAME — `param_paths.to`, a builder constraint on `query`, a `destinations.emails` fact
# derived from the value under a recipient key. Against `{"args": ["collector@attacker.example"]}`
# none of them can fire, whatever the operator wrote: the rule does not FAIL, it is simply never
# about this call, and under a tighten-only policy the call proceeds.


class _RecordingInterceptor:
    """Captures the params the engine WOULD have evaluated."""

    def __init__(self) -> None:
        self.params: dict[str, Any] = {}

    async def intercept_or_raise(self, *, tool_name: str, tool_params: dict, session_id: str,
                                 framework: str) -> None:
        self.params = tool_params


class _PositionalTool(BaseTool):
    """A tool whose arguments are POSITIONAL — the shape that lost its names."""

    name: str = "send_email"
    description: str = "sends mail"

    def _run(self, to: str = "", body: str = "") -> str:
        return f"sent:{to}"


class _VarargsTool(BaseTool):
    name: str = "varargs_tool"
    description: str = "takes anything"

    def _run(self, first: str = "", *rest: Any) -> str:
        return "ok"


def test_positional_arguments_are_bound_to_their_names() -> None:
    """The names come from the tool's OWN `_run`, so they are the names the tool itself uses."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", "quarterly figures")
    # NOT {"args": [...]} — the recipient is addressable, so `param_paths.to` can fire at all.
    assert rec.params == {"to": "ops@acme.com", "body": "quarterly figures"}


def test_an_explicit_keyword_wins_over_a_positional_binding() -> None:
    """Mixing the two must not let a positional silently overwrite what the caller named."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", body="figures")
    assert rec.params == {"to": "ops@acme.com", "body": "figures"}


def test_keyword_invocation_is_unchanged() -> None:
    """The path that always worked, pinned so the binding cannot regress it."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run(to="ops@acme.com")
    assert rec.params == {"to": "ops@acme.com"}


def test_arguments_beyond_the_known_names_keep_the_args_list() -> None:
    """`*args` genuinely has no name to bind to. Inventing `arg3` would let an operator scope a name
    the tool has never heard of — a rule that looks enforced and can never match."""
    rec = _RecordingInterceptor()
    wrapped = protect([_VarargsTool()], rec, session_id=_session())
    wrapped[0]._run("a", "b", "c")
    assert rec.params == {"first": "a", "args": ["b", "c"]}


# ── a WRONG name is worse than no name ──────────────────────────────────────────────────────────
#
# Binding positional args by zipping a name list against the argument tuple looked like the obvious
# implementation and is the dangerous one. A decorator that injects a leading argument — a tenant,
# retry or audit wrapper, all commonplace — shifts every name by one, and `functools.wraps` makes
# `inspect.signature` report the signature UNDERNEATH the decorator while the caller uses the
# decorated convention.
#
# The engine is then told `{"tenant": "collector@attacker.example", "to": "ops@acme.com"}` while the
# tool sends to the attacker: the operator's `param_paths.to` pin inspects a compliant value and
# ALLOWS. Under the deny-by-default policy the intent compiler emits, a MISSING name is fail-closed
# (the rule never matches); a WRONG name is fail-open, and it also lies to the near-miss explainer.
#
# So binding goes through `Signature.bind`, which REFUSES rather than guesses, and the signature is
# read with follow_wrapped=False so a wrapper's own `(self, *a, **k)` yields no usable names.

def _tenant_decorator(tenant: str):
    def deco(fn):
        @functools.wraps(fn)
        def inner(self, *a, **k):
            return fn(self, tenant, *a, **k)
        return inner
    return deco


class _ShiftedTool(BaseTool):
    """A tool whose decorator injects a leading argument the caller never passes."""

    name: str = "send_email"
    description: str = "sends mail"

    @_tenant_decorator("acme")
    def _run(self, tenant: str = "", to: str = "", body: str = "") -> str:
        return f"sent:{to}"


def test_a_shifted_signature_claims_no_name_rather_than_the_wrong_one() -> None:
    rec = _RecordingInterceptor()
    wrapped = protect([_ShiftedTool()], rec, session_id=_session())
    wrapped[0]._run("collector@attacker.example", "ops@acme.com")

    # The attacker's address must NOT be filed under some other name while a compliant value sits
    # under the one the operator pinned — that is the shape that turns a pin into a rubber stamp.
    assert rec.params.get("to") != "ops@acme.com", "a shifted signature produced a WRONG name binding"
    # Unnamed is the correct degradation: no per-argument rule can match, and under deny-by-default
    # that is a refusal rather than a silent allow.
    assert "args" in rec.params


def test_an_honest_tool_is_unaffected_by_the_stricter_binding() -> None:
    """The cost side: refusing to guess must not stop ordinary tools from being named."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", "quarterly figures")
    assert rec.params == {"to": "ops@acme.com", "body": "quarterly figures"}
