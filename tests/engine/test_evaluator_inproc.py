# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluator-side in-process L1 for posture (_resolve_posture) and the stored trust score (_trust)."""

from __future__ import annotations

import pytest

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.inproc_cache import TTLCache
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.trust import TrustScore

# NOTE: no module-level asyncio mark — this file mixes async (posture/trust L1) and sync (TTL clamp,
# invalidation) tests; pytest-asyncio AUTO mode runs the async ones without a mark, and leaving the
# sync tests unmarked avoids the "sync test marked asyncio" warning.


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


# --- L2: in-proc eval-decision cache TTL clamp + invalidation hook -------------------------------

def test_inproc_eval_ttl_is_clamped_to_redis_eval_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    # An operator sets a generous 30s inproc TTL, but the EVAL-decision L1 must never outlive the Redis
    # eval cache's own 5s self-heal bound (a dropped policy-invalidation event could otherwise serve a
    # stale decision longer than today's guarantee).
    monkeypatch.setattr(settings, "evaluator_inproc_cache_ttl_s", 30.0)
    monkeypatch.setattr(settings, "redis_ttl_eval_s", 5)
    ev = OPAEvaluator(cache=_CacheStub())  # type: ignore[arg-type]
    assert ev._inproc_eval_cache._ttl <= 5
    # ...while posture/trust L1s keep the full configured TTL.
    assert ev._posture_cache._ttl == 30.0


def test_on_eval_invalidated_clears_the_whole_inproc_eval_cache() -> None:
    ev = OPAEvaluator(cache=_CacheStub())  # type: ignore[arg-type]
    ev._inproc_eval_cache = TTLCache(30.0)
    ev._inproc_eval_cache.set(("ns", "cls", "tool"), PolicyDecision(decision="allow", rule_id="r", reason=""))
    ev._on_eval_invalidated("ns", "cls")             # scope args are ignored — the whole cache is dropped
    assert len(ev._inproc_eval_cache) == 0


def test_hook_is_registered_when_cache_supports_it() -> None:
    class _HookCache(_CacheStub):
        def __init__(self) -> None:
            super().__init__()
            self.hooks: list = []

        def register_eval_invalidation_hook(self, cb) -> None:
            self.hooks.append(cb)

    cache = _HookCache()
    ev = OPAEvaluator(cache=cache)  # type: ignore[arg-type]
    assert ev._on_eval_invalidated in cache.hooks    # the evaluator wired its in-proc clear to the cache
