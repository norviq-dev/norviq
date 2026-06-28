# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for OPAEvaluator with real Redis-backed cache."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
import uuid

import pytest

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore
from tests.conftest import seed_low_trust

_ISOLATE_PATTERNS = ("eval:*", "trust:*", "agent_history:*", "agent_profile:*", "agent_class:*", "agent_frozen:*", "trustcalc:*")


async def _flush(cache: RedisCache) -> None:
    """Clear per-agent runtime keys so evaluator tests don't see each other's cached state."""
    client = cache._client()
    for pattern in _ISOLATE_PATTERNS:
        keys = [key async for key in client.scan_iter(pattern)]
        if keys:
            await client.delete(*keys)


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def evaluator(redis_url: str, seeded_loader) -> OPAEvaluator:
    """Create evaluator with connected Redis cache + comprehensive.rego as cluster baseline."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    await _flush(cache)  # isolate from other tests' cached decisions / trust history
    engine = OPAEvaluator(cache)
    engine.bind_loader(seeded_loader)
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
    """Mismatched tenant must be blocked (comprehensive.rego rule cross_tenant_access)."""
    decision = await evaluator.evaluate(_event(_suffix(), "get_customer", {"tenant_id": "tenant-b"}))
    assert decision.decision == "block"
    assert decision.rule_id == "cross_tenant_access"


async def test_wildcard_delete_blocks(evaluator: OPAEvaluator) -> None:
    """Wildcard delete must be blocked (comprehensive.rego flags it as excessive agency)."""
    decision = await evaluator.evaluate(_event(_suffix(), "delete_record", {"record_id": "*"}))
    assert decision.decision == "block"
    assert decision.rule_id == "llm06_excessive_agency"


async def test_rate_limit_blocks(evaluator: OPAEvaluator) -> None:
    """More than configured calls in window should block.

    The per-agent rate counter is incremented on cache hits, so the call must repeat the SAME
    tool+params: the first call populates the eval cache (allow), each subsequent identical call
    cache-hits and increments the counter until it exceeds the window limit.
    """
    suffix = _suffix()
    event = _event(suffix, f"search_{suffix}", {"query": "status"})
    last = None
    for index in range(settings.evaluator_rate_limit_per_window + 5):
        next_event = event.model_copy(update={"event_id": f"{event.event_id}-{index}"})
        last = await evaluator.evaluate(next_event)
    assert last is not None
    assert last.decision == "block"
    assert last.rule_id == "rate_limit_exceeded"


async def test_low_trust_escalates(evaluator: OPAEvaluator) -> None:
    """Low trust score should escalate if no deny rules match."""
    suffix = _suffix()
    spiffe_id = f"spiffe://norviq/ns/tenant-a/sa/agent-{suffix}"
    await seed_low_trust(evaluator._cache, spiffe_id)  # recomputed trust < 0.4 → escalate
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

    # Patch _evaluate_single (the method the candidates path invokes) so the error reaches the
    # evaluate() fallback handler rather than _evaluate_single's internal evaluator_error catch.
    monkeypatch.setattr(evaluator, "_evaluate_single", _raise)
    decision = await evaluator.evaluate(_event(_suffix(), "safe_tool", {"ok": True}))
    assert decision.decision in {"audit", "block"}
    assert decision.reason.startswith("Evaluation failed")


async def test_timeout_returns_fail_closed_block(evaluator: OPAEvaluator, monkeypatch) -> None:
    """Evaluation timeout must return explicit fail-closed block decision."""

    async def _slow(*_: object, **__: object) -> dict:
        await asyncio.sleep(2.5)  # exceed the evaluate() wait_for timeout (2.0s)
        return {"decision": "allow", "rule_id": "unexpected", "reason": "should timeout first"}

    monkeypatch.setattr(evaluator, "_evaluate_single", _slow)
    decision = await evaluator.evaluate(_event(_suffix(), "safe_tool", {"ok": True}))
    assert decision.decision == "block"
    assert decision.reason == "Evaluation timed out, fallback=block"


async def test_cached_block_still_applies_post_decision(evaluator: OPAEvaluator) -> None:
    """Cached block responses should still decrement trust for repeat attempts."""
    suffix = _suffix()
    # tool_name must be exactly "execute_sql" so the deny_sql_injection rule matches.
    event = _event(suffix, "execute_sql", {"query": "DROP TABLE users"})
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
    assert evaluator._policies["tenant-a:support"]["rego"] == "package norviq.allow"


def test_cluster_priority_block_overrides_lower_allow() -> None:
    """Higher-priority cluster block must beat lower-priority tenant allow."""
    evaluator = OPAEvaluator(cache=None)  # type: ignore[arg-type]
    winner = evaluator._resolve_precedence(
        [
            {
                "priority": 200,
                "decision": PolicyDecision(decision="allow", rule_id="tenant_allow", reason="tenant allows"),
                "key": "default:tenant",
            },
            {
                "priority": 900,
                "decision": PolicyDecision(decision="block", rule_id="cluster_floor_block", reason="cluster baseline block"),
                "key": "__cluster__:__baseline__",
            },
        ]
    )
    assert winner["decision"].decision == "block"
    assert winner["decision"].rule_id == "cluster_floor_block"


def test_low_trust_allow_is_overridden_to_escalate() -> None:
    """Low trust must override allow decisions to escalate."""
    evaluator = OPAEvaluator(cache=None)  # type: ignore[arg-type]
    decision = PolicyDecision(
        decision="allow",
        rule_id="default_allow",
        reason="ok",
        trust_score=0.9,
        trust_category="high",
        decided_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    trust = TrustResult(
        score=0.2,
        category="low",
        signals={"violation_rate": 0.2},
        weights={"violation_rate": 0.25},
        dominant_signal="violation_rate",
        recommendation="escalate",
    )
    updated = evaluator._apply_trust_overrides(decision, trust, "evt-low")
    assert updated.decision == "escalate"
    assert updated.trust_score == 0.2
    assert updated.trust_category == "low"
    assert updated.trust_dominant_signal == "violation_rate"
    assert updated.decided_at > decision.decided_at


def test_frozen_trust_overrides_allow_to_block() -> None:
    """Frozen trust must force a block decision."""
    evaluator = OPAEvaluator(cache=None)  # type: ignore[arg-type]
    decision = PolicyDecision(
        decision="allow",
        rule_id="default_allow",
        reason="ok",
        trust_score=0.9,
        trust_category="high",
        decided_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    trust = TrustResult(
        score=0.0,
        category="frozen",
        signals={"violation_rate": 0.0},
        weights={"violation_rate": 0.25},
        dominant_signal="violation_rate",
        recommendation="freeze",
    )
    updated = evaluator._apply_trust_overrides(decision, trust, "evt-frozen")
    assert updated.decision == "block"
    assert updated.trust_score == 0.0
    assert updated.trust_category == "frozen"
    assert updated.trust_recommendation == "freeze"
    assert updated.decided_at > decision.decided_at


def test_cache_hit_decision_refreshes_trust_fields_without_enforcement_change() -> None:
    """Cache-hit decisions must refresh trust metadata even when action is unchanged."""
    evaluator = OPAEvaluator(cache=None)  # type: ignore[arg-type]
    decision = PolicyDecision(
        decision="block",
        rule_id="deny_sql_injection",
        reason="cached block",
        trust_score=0.95,
        trust_category="high",
        trust_signals={"violation_rate": 1.0},
        trust_dominant_signal="violation_rate",
        trust_recommendation="allow",
        decided_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    trust = TrustResult(
        score=0.33,
        category="low",
        signals={"violation_rate": 0.2},
        weights={"violation_rate": 0.25},
        dominant_signal="violation_rate",
        recommendation="escalate",
    )
    updated = evaluator._apply_trust_overrides(decision, trust, "evt-cache")
    assert updated.decision == "block"
    assert updated.rule_id == "deny_sql_injection"
    assert updated.trust_score == 0.33
    assert updated.trust_category == "low"
    assert updated.trust_signals == {"violation_rate": 0.2}
    assert updated.trust_dominant_signal == "violation_rate"
    assert updated.trust_recommendation == "escalate"
    assert updated.decided_at > decision.decided_at
