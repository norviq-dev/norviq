# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangChain adapter wrappers."""

from __future__ import annotations

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
