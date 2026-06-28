# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for generic ToolInterceptor behavior."""

from __future__ import annotations

from collections.abc import AsyncIterator
import os
import uuid

import pytest

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.events import AgentIdentity
from norviq.sdk.core.interceptor import ToolInterceptor
from tests.conftest import seed_low_trust


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def interceptor(redis_url: str, seeded_loader) -> AsyncIterator[ToolInterceptor]:
    """Create interceptor backed by Redis evaluator + comprehensive.rego cluster baseline."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    evaluator.bind_loader(seeded_loader)
    resolver = SPIFFEResolver()
    yield ToolInterceptor(evaluator=evaluator, resolver=resolver)
    await evaluator.close()
    await cache.close()


def _suffix() -> str:
    """Create unique test suffix."""
    return uuid.uuid4().hex


def _identity(suffix: str) -> AgentIdentity:
    """Build identity for isolated Redis keys."""
    return AgentIdentity(
        spiffe_id=f"spiffe://norviq/ns/tenant-a/sa/agent-{suffix}",
        namespace="tenant-a",
        agent_class="support",
    )


async def test_intercept_returns_allow_for_safe_tool(interceptor: ToolInterceptor) -> None:
    """Safe calls should return allow decision."""
    decision = await interceptor.intercept("search_kb", {"query": "hello"}, identity=_identity(_suffix()))
    assert decision.decision == "allow"


async def test_intercept_returns_block_for_sql_injection(interceptor: ToolInterceptor) -> None:
    """DROP TABLE should return block decision."""
    decision = await interceptor.intercept("execute_sql", {"query": "DROP TABLE users"}, identity=_identity(_suffix()))
    assert decision.decision == "block"


async def test_intercept_or_raise_raises_block(interceptor: ToolInterceptor) -> None:
    """Blocked decisions should raise NorviqBlockError."""
    with pytest.raises(NorviqBlockError):
        await interceptor.intercept_or_raise("execute_sql", {"query": "DROP TABLE users"}, identity=_identity(_suffix()))


async def test_intercept_or_raise_raises_escalate(interceptor: ToolInterceptor) -> None:
    """Low trust identities should raise NorviqEscalateError."""
    suffix = _suffix()
    identity = _identity(suffix)
    await seed_low_trust(interceptor._evaluator._cache, identity.spiffe_id)  # recomputed trust < 0.4
    with pytest.raises(NorviqEscalateError):
        await interceptor.intercept_or_raise("sensitive_tool", {"action": "approve"}, identity=identity)


async def test_intercept_or_raise_returns_decision_when_allowed(interceptor: ToolInterceptor) -> None:
    """Allowed calls should return the policy decision."""
    decision = await interceptor.intercept_or_raise("search_kb", {"query": "hello"}, identity=_identity(_suffix()))
    assert decision.is_allowed() is True


async def test_intercept_returns_policy_decision_on_evaluator_error(
    interceptor: ToolInterceptor, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evaluator errors should still return fallback PolicyDecision."""

    async def _raise(*_: object, **__: object) -> dict[str, str]:
        raise RuntimeError("forced-error")

    monkeypatch.setattr(interceptor._evaluator, "_evaluate_opa", _raise)
    decision = await interceptor.intercept("search_kb", {"query": f"hello-{_suffix()}"}, identity=_identity(_suffix()))
    assert decision.decision in {"audit", "block"}
