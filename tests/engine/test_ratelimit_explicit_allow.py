# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Regression: the per-namespace rate_limit backstop must throttle EVERY allowed call in the
namespace, not only the no-policy ``default_allow`` class.

Before the fix, the cache-hit throttle gate keyed on ``cached.rule_id == "default_allow"`` and the
fresh-eval path had no throttle at all, so any class governed by an EXPLICIT allow policy (whose allow
branch names a rule_id like ``sc_allow`` / ``intent_allow_<token>``) was never rate-limited — the more a
class was governed, the less the ns-wide throttle applied to it (inverted from the operator's mental
model). These tests fail on the pre-fix code (the explicit-allow class returns allow forever) and pass
after (it is throttled with ``rate_limit_exceeded`` once the window is exceeded).
"""

from __future__ import annotations

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore

_NS = "sc-1050"
_RATE_LIMIT = 2


class _LoaderStub:
    """No loaded policies — `_evaluate_opa` is monkeypatched to stand in for the class's governing policy."""

    _policies: dict[str, dict] = {}

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return None


class _CountingCacheStub:
    """In-memory cache whose ``incr_call_count`` actually increments, so the rate limiter can engage."""

    def __init__(self, ns_settings: dict[str, dict]) -> None:
        self._eval: dict[tuple[str, str, str], object] = {}
        self._trust: dict[str, TrustScore] = {}
        self._counts: dict[str, int] = {}
        self._ns_settings = ns_settings

    async def get_eval(self, namespace: str, agent_class: str, tool_name: str):
        return self._eval.get((namespace, agent_class, tool_name))

    async def set_eval(self, namespace: str, agent_class: str, tool_name: str, decision) -> None:
        self._eval[(namespace, agent_class, tool_name)] = decision

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        return self._trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        self._trust[spiffe_id] = score

    async def incr_call_count(self, spiffe_id: str, window_s: int = 60) -> int:
        self._counts[spiffe_id] = self._counts.get(spiffe_id, 0) + 1
        return self._counts[spiffe_id]

    async def get_ns_settings(self, namespace: str):
        return self._ns_settings.get(namespace)


def _trust_result() -> TrustResult:
    """High trust so trust overrides never flip the allow — isolates the rate-limit behavior under test."""
    return TrustResult(
        score=0.9,
        category="high",
        signals={"violation_rate": 0.0},
        weights={"violation_rate": 1.0},
        dominant_signal="violation_rate",
        recommendation="allow",
    )


def _event(tool_name: str, index: int) -> ToolCallEvent:
    return ToolCallEvent(
        event_id=f"evt-def048-{tool_name}-{index}",
        tool_name=tool_name,
        tool_params={"target": "queue"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/sc-1050/sa/probe-agent",
            namespace=_NS,
            agent_class="probe",
        ),
        session_id="def048-session",
    )


@pytest.fixture
def evaluator(monkeypatch: pytest.MonkeyPatch) -> OPAEvaluator:
    engine = OPAEvaluator(_CountingCacheStub({_NS: {"rate_limit": _RATE_LIMIT}}))  # type: ignore[arg-type]
    engine.bind_loader(_LoaderStub())

    async def _fake_compute_trust(event: ToolCallEvent, trust: TrustScore, trust_threshold=None) -> TrustResult:
        return _trust_result()

    async def _fake_persist(event: ToolCallEvent, decision, trust: TrustResult) -> None:
        return None

    # Class governed by an EXPLICIT allow policy: its allow branch names rule_id "sc_allow" (NOT default_allow).
    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        return {"decision": "allow", "rule_id": "sc_allow", "reason": "explicit allow policy"}

    monkeypatch.setattr(engine, "_compute_trust", _fake_compute_trust)
    monkeypatch.setattr(engine, "_persist_behavior", _fake_persist)
    monkeypatch.setattr(engine, "_evaluate_opa", _fake_opa)
    return engine


@pytest.mark.asyncio
async def test_explicit_allow_class_is_throttled_past_the_window(evaluator: OPAEvaluator) -> None:
    """An agent under an explicit allow policy (rule_id "sc_allow") must be throttled once the per-ns
    rate_limit window is exceeded — NOT allowed forever. FAIL-ON-BUG: pre-fix, every call returns
    allow/sc_allow and this assertion never sees a rate_limit_exceeded block."""
    # Non-exempt (write-ish) tool name so the read carve-out does not apply.
    decisions = [await evaluator.evaluate(_event("provision_resource", i)) for i in range(_RATE_LIMIT + 3)]

    # The class IS governed by an explicit allow (never default_allow) — proves the gap the fix closes.
    assert any(d.rule_id == "sc_allow" for d in decisions)
    # Once the window (rate_limit=2) is exceeded, the throttle must engage on the explicit-allow class.
    blocked = [d for d in decisions if d.decision == "block" and d.rule_id == "rate_limit_exceeded"]
    assert blocked, f"explicit-allow class was never throttled: {[(d.decision, d.rule_id) for d in decisions]}"
    # The final call is past the window, so it must be the throttle block (not an allow leak).
    assert decisions[-1].decision == "block"
    assert decisions[-1].rule_id == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_first_call_counts_on_the_fresh_path(evaluator: OPAEvaluator) -> None:
    """The fresh-eval path (call #1, a cache MISS) must also count against the window — otherwise the ns-wide
    backstop only engages on cache-hit replays. With rate_limit=2: calls #1,#2 allow; call #3 throttled."""
    d1 = await evaluator.evaluate(_event("provision_resource", 0))  # cache miss, count -> 1
    d2 = await evaluator.evaluate(_event("provision_resource", 1))  # cache hit, count -> 2
    d3 = await evaluator.evaluate(_event("provision_resource", 2))  # cache hit, count -> 3 (> 2) -> throttle

    assert (d1.decision, d1.rule_id) == ("allow", "sc_allow")
    assert (d2.decision, d2.rule_id) == ("allow", "sc_allow")
    assert (d3.decision, d3.rule_id) == ("block", "rate_limit_exceeded")


@pytest.mark.asyncio
async def test_read_exempt_tool_under_explicit_allow_is_not_throttled(evaluator: OPAEvaluator) -> None:
    """Guard the read-like carve-out survives the broadened backstop: a read-like tool (search_*) under the same
    explicit allow policy is NEVER throttled, even well past the window."""
    decisions = [await evaluator.evaluate(_event("search_records", i)) for i in range(_RATE_LIMIT + 4)]
    assert all(d.decision == "allow" and d.rule_id == "sc_allow" for d in decisions)
