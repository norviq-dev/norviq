# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for RedisCache using a real Redis instance."""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from norviq.engine.cache import RedisCache
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.trust import TrustScore


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def cache(redis_url: str) -> RedisCache:
    """Create and connect cache instance."""
    client = RedisCache(url=redis_url)
    await client.connect()
    yield client
    await client.close()


def _suffix() -> str:
    """Return a random suffix for key isolation."""
    return uuid.uuid4().hex


async def test_connect_configures_pool_size(cache: RedisCache) -> None:
    """The pool must take its size from settings, not a literal duplicated here."""
    from norviq.config import settings

    assert cache._client().connection_pool.max_connections == settings.redis_max_connections


async def test_connect_uses_a_blocking_pool_that_queues_instead_of_refusing(cache: RedisCache) -> None:
    """Pool exhaustion must WAIT, never raise — the evaluator fails CLOSED on any exception.

    redis-py's default `ConnectionPool` raises `ConnectionError("Too many connections")` the instant it
    is exhausted. On the enforcement path that is not a slow tool call, it is a REFUSED one: measured at
    3/200 benign calls blocked with rule_id `evaluator_fallback` at concurrency 8. This pins the pool
    CLASS rather than the symptom, because the symptom only appears under concurrency and would sail
    through any hermetic suite.
    """
    from redis.asyncio import BlockingConnectionPool

    from norviq.config import settings

    pool = cache._client().connection_pool
    assert isinstance(pool, BlockingConnectionPool), (
        f"pool is {type(pool).__name__}; a non-blocking pool turns a momentary burst into a "
        "fail-closed block on legitimate agent traffic"
    )
    # The wait has to stay inside the evaluator's own 2.0s OPA budget, or a stuck Redis surfaces as an
    # anonymous `evaluator_fallback` instead of the named `evaluator_timeout`.
    assert 0 < settings.redis_pool_wait_s < 2.0


async def test_policy_get_set_and_warm(cache: RedisCache) -> None:
    """Policy cache should support get, set, and setnx warm."""
    suffix = _suffix()
    namespace = f"ns-{suffix}"
    agent_class = "planner"
    key = cache._policy_key(namespace, agent_class)  # keys are now hashed per-segment (collision defense)
    await cache._client().delete(key)
    assert await cache.get_policy(namespace, agent_class) is None
    assert await cache.warm_policy(namespace, agent_class, "package p1") is True
    assert await cache.warm_policy(namespace, agent_class, "package p2") is False
    await cache.set_policy(namespace, agent_class, "package p3")
    assert await cache.get_policy(namespace, agent_class) == "package p3"
    ttl = await cache._client().ttl(key)
    assert 1 <= ttl <= 66


async def test_trust_get_set_and_atomic_decrement(cache: RedisCache) -> None:
    """Trust cache should roundtrip and decrement atomically with Lua."""
    suffix = _suffix()
    spiffe_id = f"spiffe://norviq/ns/default/sa/agent-{suffix}"
    trust = TrustScore(score=0.8, violation_count=0)
    await cache.set_trust(spiffe_id, trust)
    cached = await cache.get_trust(spiffe_id)
    assert cached is not None
    assert cached.score == 0.8
    updated = await cache.decrement_trust(spiffe_id)
    assert updated is not None
    assert updated.score == pytest.approx(0.75, abs=1e-4)
    assert updated.violation_count == 1
    assert updated.category == "High"
    ttl = await cache._client().ttl(f"trust:{spiffe_id}")
    assert 1 <= ttl <= 33


async def test_eval_get_set(cache: RedisCache) -> None:
    """Eval cache should roundtrip PolicyDecision models."""
    suffix = _suffix()
    namespace = f"ns-{suffix}"
    decision = PolicyDecision(decision="allow", policy_id="P-1", reason="ok", event_id=f"evt-{suffix}")
    await cache.set_eval(namespace, "agent", "search", decision)
    loaded = await cache.get_eval(namespace, "agent", "search")
    assert loaded is not None
    assert loaded.decision == "allow"
    assert loaded.policy_id == "P-1"


async def test_incr_call_count_expires_window(cache: RedisCache) -> None:
    """Rate counter should increment atomically and reset after expiry."""
    suffix = _suffix()
    spiffe_id = f"spiffe://norviq/ns/default/sa/rate-{suffix}"
    assert await cache.incr_call_count(spiffe_id, window_s=1) == 1
    assert await cache.incr_call_count(spiffe_id, window_s=1) == 2
    await asyncio.sleep(1.2)
    assert await cache.incr_call_count(spiffe_id, window_s=1) == 1


async def test_jitter_ttl_within_expected_range(cache: RedisCache) -> None:
    """TTL jitter should stay within 0-10 percent window."""
    base = 60
    samples = [cache._jitter_ttl(base) for _ in range(100)]
    assert min(samples) >= 60
    assert max(samples) <= 66


async def test_session_get_set(cache: RedisCache) -> None:
    """Session payload should roundtrip through Redis JSON."""
    session_id = f"sess-{_suffix()}"
    assert await cache.get_session(session_id) is None
    payload = {"request_id": session_id, "count": 3}
    await cache.set_session(session_id, payload)
    assert await cache.get_session(session_id) == payload


async def test_revoke_token_sets_denylist_with_ttl(cache: RedisCache) -> None:
    """A revoked token hash is denylisted with TTL bounded by the token's remaining life."""
    token_hash = f"deadbeef{_suffix()}"
    assert await cache.is_token_revoked(token_hash) is False
    await cache.revoke_token(token_hash, ttl_s=120)
    assert await cache.is_token_revoked(token_hash) is True
    ttl = await cache._client().ttl(f"revoked:{token_hash}")
    assert 0 < ttl <= 120


async def test_revoked_token_entry_expires(cache: RedisCache) -> None:
    """The denylist self-cleans — an entry dies when the token itself would have expired."""
    token_hash = f"deadbeef{_suffix()}"
    await cache.revoke_token(token_hash, ttl_s=1)
    assert await cache.is_token_revoked(token_hash) is True
    await asyncio.sleep(1.2)
    assert await cache.is_token_revoked(token_hash) is False
