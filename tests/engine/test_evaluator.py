# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for OPAEvaluator with real Redis-backed cache."""

from __future__ import annotations

import os
import uuid

import pytest

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def evaluator(redis_url: str) -> OPAEvaluator:
    """Create evaluator with connected Redis cache."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    engine = OPAEvaluator(cache)
    yield engine
    await engine.close()
    await cache.close()


def _suffix() -> str:
    """Create random suffix for key isolation."""
    return uuid.uuid4().hex


def _event(suffix: str, tool_name: str, params: dict) -> ToolCallEvent:
    """Build a unique event for evaluator tests."""
    return ToolCallEvent(
        event_id=f"evt-{suffix}-{tool_name}",
        tool_name=tool_name,
        tool_params=params,
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/tenant-a/sa/agent-{suffix}",
            namespace="tenant-a",
            agent_class="support",
        ),
        session_id=f"sess-{suffix}",
    )


async def test_sql_injection_blocks(evaluator: OPAEvaluator) -> None:
    """DROP TABLE should return deny_sql_injection block."""
    decision = await evaluator.evaluate(_event(_suffix(), "execute_sql", {"query": "DROP TABLE users"}))
    assert decision.decision == "block"
    assert decision.rule_id == "deny_sql_injection"


async def test_cross_tenant_blocks(evaluator: OPAEvaluator) -> None:
    """Mismatched tenant should return deny_cross_tenant block."""
    decision = await evaluator.evaluate(_event(_suffix(), "get_customer", {"tenant_id": "tenant-b"}))
    assert decision.decision == "block"
    assert decision.rule_id == "deny_cross_tenant"


async def test_wildcard_delete_blocks(evaluator: OPAEvaluator) -> None:
    """Wildcard delete should return deny_wildcard_delete block."""
    decision = await evaluator.evaluate(_event(_suffix(), "delete_record", {"record_id": "*"}))
    assert decision.decision == "block"
    assert decision.rule_id == "deny_wildcard_delete"


async def test_rate_limit_blocks(evaluator: OPAEvaluator) -> None:
    """More than configured calls in window should block."""
    suffix = _suffix()
    event = _event(suffix, f"search_{suffix}", {"query": "status"})
    for index in range(60):
        next_event = event.model_copy(update={"event_id": f"{event.event_id}-{index}", "tool_name": f"search_{suffix}_{index}"})
        assert (await evaluator.evaluate(next_event)).decision in {"allow", "escalate"}
    over = event.model_copy(update={"event_id": f"{event.event_id}-limit", "tool_name": f"search_{suffix}_limit"})
    decision = await evaluator.evaluate(over)
    assert decision.decision == "block"
    assert decision.rule_id == "rate_limit_exceeded"


async def test_low_trust_escalates(evaluator: OPAEvaluator) -> None:
    """Low trust score should escalate if no deny rules match."""
    suffix = _suffix()
    spiffe_id = f"spiffe://norviq/ns/tenant-a/sa/agent-{suffix}"
    await evaluator._cache.set_trust(spiffe_id, TrustScore(score=0.3))
    decision = await evaluator.evaluate(
        ToolCallEvent(
            event_id=f"evt-{suffix}-low-trust",
            tool_name="sensitive_tool",
            tool_params={"action": "approve"},
            agent_identity=AgentIdentity(spiffe_id=spiffe_id, namespace="tenant-a", agent_class="support"),
            session_id=f"sess-{suffix}",
        )
    )
    assert decision.decision == "escalate"
    assert decision.rule_id == "escalate_low_trust"


async def test_happy_path_allows(evaluator: OPAEvaluator) -> None:
    """Benign tool calls should default to allow."""
    decision = await evaluator.evaluate(_event(_suffix(), "search_kb", {"query": "order status"}))
    assert decision.decision == "allow"
    assert decision.rule_id == "default_allow"


async def test_cache_hit_skips_opa(evaluator: OPAEvaluator, monkeypatch) -> None:
    """Second identical call should use cache and skip OPA."""
    suffix = _suffix()
    event = _event(suffix, "lookup_orders", {"query": "shipped"})
    first = await evaluator.evaluate(event)

    async def _boom(*_: object, **__: object) -> dict:
        raise AssertionError("OPA should not run on cache hit")

    monkeypatch.setattr(evaluator, "_evaluate_opa", _boom)
    second = await evaluator.evaluate(event.model_copy(update={"event_id": f"evt-{suffix}-cached"}))
    assert second.rule_id == first.rule_id
    assert second.reason == first.reason


async def test_fallback_on_error(evaluator: OPAEvaluator, monkeypatch) -> None:
    """Evaluator errors should return configured fallback decision."""
    async def _raise(*_: object, **__: object) -> dict:
        raise RuntimeError("forced-error")

    monkeypatch.setattr(evaluator, "_evaluate_opa", _raise)
    decision = await evaluator.evaluate(_event(_suffix(), "safe_tool", {"ok": True}))
    assert decision.decision in {"audit", "block"}
    assert decision.reason.startswith("Evaluation failed")


async def test_cached_block_still_applies_post_decision(evaluator: OPAEvaluator) -> None:
    """Cached block responses should still decrement trust for repeat attempts."""
    suffix = _suffix()
    event = _event(suffix, f"execute_sql_{suffix}", {"query": "DROP TABLE users"})
    spiffe_id = event.agent_identity.spiffe_id
    await evaluator._cache.set_trust(spiffe_id, TrustScore(score=0.8))
    first = await evaluator.evaluate(event)
    before = await evaluator._cache.get_trust(spiffe_id)
    second = await evaluator.evaluate(event.model_copy(update={"event_id": f"{event.event_id}-again"}))
    after = await evaluator._cache.get_trust(spiffe_id)
    assert first.decision == "block"
    assert second.decision == "block"
    assert before is not None and after is not None
    assert after.score < before.score


async def test_load_policy_updates_policy_map(evaluator: OPAEvaluator) -> None:
    """load_policy should atomically replace mapping with new key/value."""
    evaluator.load_policy("tenant-a", "support", "package norviq.allow")
    assert evaluator._policies["tenant-a:support"] == "package norviq.allow"
