# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangChain adapter wrappers."""

from __future__ import annotations

from collections.abc import AsyncIterator
import os
import uuid

import pytest

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.langchain.adapter import protect

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
async def interceptor(redis_url: str) -> AsyncIterator[ToolInterceptor]:
    """Create ToolInterceptor for adapter tests."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    resolver = SPIFFEResolver()
    yield ToolInterceptor(evaluator=evaluator, resolver=resolver)
    await evaluator.close()
    await cache.close()


def _session() -> str:
    """Create isolated session id."""
    return uuid.uuid4().hex


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
