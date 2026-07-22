# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OFFLINE guard for the L1+L2 security invariant: a freeze must beat a stale in-proc ALLOW.

The equivalent end-to-end test (test_evaluator_l1l2.py) needs a real Redis and SKIPS without
NRVQ_REDIS_URL — which CI does not set, so the single guarantee that makes the in-process cache
acceptable had no test that runs by default. This file closes that: it drives the real
`evaluate()` in-proc-hit branch with fakes, so it runs everywhere, every time.
"""

from __future__ import annotations

import pytest

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.inproc_cache import TTLCache
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore

pytestmark = pytest.mark.asyncio

SPIFFE = "spiffe://norviq/ns/default/sa/customer-support"


class _Cache:
    """Only what evaluate()'s in-proc-hit path touches. agent_flags is the freeze/cap read."""

    def __init__(self, frozen: bool = False, cap: float | None = None) -> None:
        self.frozen = frozen
        self.cap = cap
        self.agent_flag_reads = 0
        self.get_eval_calls = 0

    async def get_ns_settings(self, namespace: str):
        return None  # global posture

    async def get_trust(self, spiffe_id: str):
        return TrustScore(score=0.9)

    async def set_trust(self, spiffe_id: str, score) -> None:
        return None

    async def get_agent_flags(self, spiffe_id: str):
        self.agent_flag_reads += 1
        return self.frozen, self.cap

    async def get_eval(self, namespace: str, agent_class: str, tool_name: str):
        self.get_eval_calls += 1
        return None


def _evaluator(cache: _Cache, monkeypatch: pytest.MonkeyPatch) -> OPAEvaluator:
    monkeypatch.setattr(settings, "evaluator_inproc_cache_ttl_s", 5.0)
    ev = OPAEvaluator(cache=cache)  # type: ignore[arg-type]
    ev._inproc_eval_cache = TTLCache(5.0)
    ev._posture_cache = TTLCache(5.0)
    ev._trust_score_cache = TTLCache(5.0)

    # Trust inputs come from the (cached) stores; keep them trivial and offline. The freeze/cap are
    # NOT stubbed here — they flow from cache.get_agent_flags via prefetched_flags, which is the
    # whole point of the test.
    calc = ev._trust_calculator
    monkeypatch.setattr(calc, "_history_cached", lambda spiffe: _aval([]))
    monkeypatch.setattr(calc, "_profile_cached", lambda inp: _aval({"known_tools": ["search_kb"], "baseline_rpm": 20}))
    monkeypatch.setattr(calc, "_persist", lambda *a, **k: _aval(None))
    monkeypatch.setattr(ev, "_persist_behavior", lambda *a, **k: _aval(None))
    return ev


def _aval(value):
    async def _c():
        return value
    return _c()


def _event(tool: str = "search_kb") -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool,
        tool_params={"query": "refund policy"},
        agent_identity=AgentIdentity(spiffe_id=SPIFFE, namespace="default", agent_class="customer-support"),
        session_id="offline-l1l2",
    )


def _allow() -> PolicyDecision:
    return PolicyDecision(decision="allow", rule_id="default_allow", reason="ok")


async def test_freeze_beats_a_stale_inproc_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE invariant. A warm in-proc ALLOW plus an admin freeze must still block, because the freeze
    is read fresh on every call and applied on top of the cached base decision."""
    cache = _Cache(frozen=True)
    ev = _evaluator(cache, monkeypatch)
    key = ("default", "customer-support", ev._cache_tool_key(_event()))
    ev._inproc_eval_cache.set(key, _allow())  # pretend a previous call cached an allow

    decision = await ev.evaluate(_event())

    assert decision.decision == "block", f"freeze must override a cached allow, got {decision.decision}"
    assert "frozen" in decision.rule_id
    assert cache.agent_flag_reads == 1, "the freeze must be read FRESH on the in-proc-hit path"
    assert cache.get_eval_calls == 0, "an in-proc hit must not re-read the Redis eval cache"


async def test_unfrozen_warm_hit_still_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: same warm path, no freeze -> the cached allow stands (so the test above is not
    just asserting that everything blocks)."""
    cache = _Cache(frozen=False)
    ev = _evaluator(cache, monkeypatch)
    key = ("default", "customer-support", ev._cache_tool_key(_event()))
    ev._inproc_eval_cache.set(key, _allow())

    decision = await ev.evaluate(_event())

    assert decision.decision == "allow"
    assert cache.agent_flag_reads == 1


async def test_admin_cap_is_also_applied_from_the_fresh_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tighten-only trust cap rides the same fresh read as the freeze, so it must also bite
    through a warm in-proc allow."""
    cache = _Cache(frozen=False, cap=0.05)
    ev = _evaluator(cache, monkeypatch)
    key = ("default", "customer-support", ev._cache_tool_key(_event()))
    ev._inproc_eval_cache.set(key, _allow())

    decision = await ev.evaluate(_event())

    assert decision.trust_score == pytest.approx(0.05), "admin cap must be applied from the fresh read"
    assert decision.decision in {"block", "escalate"}, f"a 0.05-capped agent must not sail through: {decision}"
