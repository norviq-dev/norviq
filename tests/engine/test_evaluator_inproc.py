# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluator-side in-process L1 for posture (_resolve_posture) and the stored trust score (_trust)."""

from __future__ import annotations

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.inproc_cache import TTLCache
from norviq.sdk.core.trust import TrustScore

pytestmark = pytest.mark.asyncio


class _CacheStub:
    def __init__(self) -> None:
        self.ns_calls = 0
        self.trust_get_calls = 0
        self.ns_settings: dict[str, dict] = {}
        self.trust: dict[str, TrustScore] = {}

    async def get_ns_settings(self, namespace: str):
        self.ns_calls += 1
        return self.ns_settings.get(namespace)

    async def get_trust(self, spiffe_id: str):
        self.trust_get_calls += 1
        return self.trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        self.trust[spiffe_id] = score


def _evaluator(ttl: float) -> tuple[OPAEvaluator, _CacheStub]:
    cache = _CacheStub()
    ev = OPAEvaluator(cache=cache)  # type: ignore[arg-type]
    # Size the L1s explicitly for the test rather than depending on process-wide settings.
    ev._posture_cache = TTLCache(ttl)
    ev._trust_score_cache = TTLCache(ttl)
    return ev, cache


async def test_posture_served_from_l1_on_second_call() -> None:
    ev, cache = _evaluator(ttl=30.0)
    cache.ns_settings["team-a"] = {"enforcement_mode": "audit", "trust_threshold": "0.8", "rate_limit": "40"}
    p1 = await ev._resolve_posture("team-a")
    p2 = await ev._resolve_posture("team-a")
    assert cache.ns_calls == 1                       # mirror read exactly once
    assert p1 == p2
    assert p1 == {"monitor": True, "trust_threshold": 0.8, "rate_limit": 40}


async def test_posture_per_namespace_keying() -> None:
    ev, cache = _evaluator(ttl=30.0)
    await ev._resolve_posture("team-a")
    await ev._resolve_posture("team-b")
    assert cache.ns_calls == 2                        # distinct namespaces don't share an entry


async def test_posture_ttl_zero_reads_fresh_every_call() -> None:
    ev, cache = _evaluator(ttl=0.0)
    await ev._resolve_posture("team-a")
    await ev._resolve_posture("team-a")
    assert cache.ns_calls == 2                        # no L1 -> byte-identical fresh reads


async def test_stored_trust_served_from_l1_on_second_call() -> None:
    ev, cache = _evaluator(ttl=30.0)
    cache.trust["spiffe://a"] = TrustScore(score=0.9)
    t1 = await ev._trust("spiffe://a")
    t2 = await ev._trust("spiffe://a")
    assert cache.trust_get_calls == 1                 # Redis GET skipped on the warm call
    assert t1.score == 0.9 and t2.score == 0.9


async def test_absent_trust_is_initialized_then_cached() -> None:
    ev, cache = _evaluator(ttl=30.0)
    t1 = await ev._trust("spiffe://new")              # miss -> init default + set_trust
    t2 = await ev._trust("spiffe://new")              # L1 hit
    assert cache.trust_get_calls == 1
    assert "spiffe://new" in cache.trust              # default persisted to Redis on first init
    assert t1.score == t2.score
