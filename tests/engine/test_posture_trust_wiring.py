# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Batch E regression (fail-on-bug): CFG-SETTINGS-INERT-01 + AGT-TRUST-02 wiring.

Pure-logic units for the two engine-side wirings — no Redis, no OPA. They fail on 1a7a3c9 (where the
methods/params don't exist) and pass on the fix.

- `_apply_posture`: namespace monitor (audit) mode softens a would-block/escalate to an allow-but-log `audit`
  decision, fires ONLY on an explicit per-ns override, exempts the incident-response/engine-health/rate rules,
  and NEVER tightens.
- `_categorize`/`_tiers`: per-ns trust_threshold moves the tiers; no-override keeps the bit-identical 0.7/0.4
  boundaries.
- the min() trust CAP (verified in calculator.calculate via a fake pipeline) only LOWERS effective trust.
"""

from __future__ import annotations

import pytest

from norviq.engine.evaluator import OPAEvaluator, _POSTURE_EXEMPT_RULES
from norviq.engine.trust.calculator import TrustCalculator
from norviq.sdk.core.decisions import PolicyDecision


def _ev() -> OPAEvaluator:
    return OPAEvaluator(cache=None)  # type: ignore[arg-type] — _apply_posture is pure


def _dec(decision: str, rule_id: str) -> PolicyDecision:
    return PolicyDecision(decision=decision, rule_id=rule_id, reason=f"{rule_id} reason")


# --- CFG-SETTINGS-INERT-01: monitor-mode softening (_apply_posture) ------------------------------

def test_monitor_softens_block_and_escalate_to_audit():
    ev = _ev()
    posture = {"monitor": True, "trust_threshold": None, "rate_limit": 60}
    for orig in ("block", "escalate"):
        out = ev._apply_posture(_dec(orig, "e_block_tool"), posture, "evt")
        assert out.decision == "audit"                              # allow-but-log
        assert out.rule_id == "monitor_would_block:e_block_tool"    # original rule preserved
        assert orig in out.reason                                   # would-<orig> recorded


def test_monitor_never_tightens_allow_or_audit():
    ev = _ev()
    posture = {"monitor": True, "trust_threshold": None, "rate_limit": 60}
    for orig in ("allow", "audit"):
        out = ev._apply_posture(_dec(orig, "default_allow"), posture, "evt")
        assert out.decision == orig                                 # only ever loosens


def test_no_override_does_not_soften():
    ev = _ev()
    # monitor False = no explicit per-ns audit override -> byte-identical to today (a block stays a block).
    out = ev._apply_posture(_dec("block", "e_block_tool"), {"monitor": False, "trust_threshold": None, "rate_limit": 60}, "evt")
    assert out.decision == "block" and out.rule_id == "e_block_tool"


@pytest.mark.parametrize("exempt", sorted(_POSTURE_EXEMPT_RULES))
def test_monitor_exempts_incident_and_engine_health_rules(exempt):
    ev = _ev()
    posture = {"monitor": True, "trust_threshold": None, "rate_limit": 60}
    out = ev._apply_posture(_dec("block", exempt), posture, "evt")
    assert out.decision == "block" and out.rule_id == exempt        # freeze / not-ready / rate-limit stay hard


def test_exempt_set_contents():
    assert _POSTURE_EXEMPT_RULES == {
        "trust_frozen", "policy_load_pending", "evaluator_error", "evaluator_invalid_payload", "rate_limit_exceeded"
    }


# --- CFG-SETTINGS-INERT-01: trust_threshold tiers (_categorize / _tiers) --------------------------

def _calc() -> TrustCalculator:
    return TrustCalculator(cache=None, history=None, profile=None)  # type: ignore[arg-type]


def test_no_override_uses_literal_070_040_boundaries():
    c = _calc()
    high, low = c._tiers(None)
    assert (high, low) == (None, None)                              # literal branch
    assert c._categorize(0.70) == "high"
    assert c._categorize(0.69) == "medium"
    assert c._categorize(0.40) == "medium"
    assert c._categorize(0.39) == "low"


def test_threshold_070_reproduces_today_exactly():
    c = _calc()
    high, low = c._tiers(0.70)
    assert high == 0.70 and abs(low - 0.40) < 1e-6                  # t=0.7 -> today's tiers (no-op re-save)


def test_higher_threshold_tightens_tiers():
    c = _calc()
    high, low = c._tiers(0.90)                                      # low = 0.9 * 0.4/0.7 ~= 0.5143
    assert high == 0.90
    assert c._categorize(0.85, high_thr=high, low_thr=low) == "medium"   # was 'high' at the default 0.7
    assert c._categorize(0.50, high_thr=high, low_thr=low) == "low"      # was 'medium' at the default 0.4


def test_frozen_and_zero_score_guards_survive_tiers():
    c = _calc()
    assert c._categorize(0.99, is_manually_frozen=True) == "frozen"
    assert c._categorize(0.0) == "low"                             # zero-score guard


# --- AGT-TRUST-02: the min() cap (tighten-only) via calculate() with a fake pipeline --------------

class _FakeCalc(TrustCalculator):
    """A calculator whose signal/history/frozen/override inputs are injected, so we exercise the real
    min()-cap + single categorize in calculate() without Redis."""

    def __init__(self, computed: float, override, frozen: bool = False):
        self._computed = computed
        self._override = override
        self._frozen = frozen
        self._tasks = set()

    async def _safe_history(self, spiffe_id):
        return []

    async def _safe_profile_and_frozen(self, input_data):
        return {}, self._frozen

    async def _safe_override_only(self, spiffe_id):
        return self._override

    async def _compute_signals(self, input_data, history, profile):
        return {"violation_rate": 1.0}

    def _weighted_sum(self, signals):
        return self._computed

    async def _persist(self, spiffe_id, result):
        return None


def _ti():
    from norviq.engine.trust.models import TrustInput
    from datetime import datetime, timezone
    return TrustInput(spiffe_id="spiffe://norviq/ns/x/sa/y", namespace="x", agent_class="y",
                      tool_name="t", tool_params={}, session_id="s", chain_depth=0,
                      timestamp=datetime.now(timezone.utc))


async def test_override_caps_trust_down_never_up():
    # computed 0.85 (high), admin cap 0.30 -> effective 0.30 (low) => escalate territory.
    r = await _FakeCalc(computed=0.85, override=0.30).calculate(_ti())
    assert r.score == 0.30 and r.category == "low"
    assert r.dominant_signal == "manual_override"                  # provenance so the operator isn't misled


async def test_override_above_computed_is_a_noop_never_raises():
    # admin sets 0.95 but behavior only earns 0.50 -> min() keeps 0.50 (never raised to 0.95).
    r = await _FakeCalc(computed=0.50, override=0.95).calculate(_ti())
    assert r.score == 0.50 and r.category == "medium"


async def test_no_override_leaves_computed_untouched():
    r = await _FakeCalc(computed=0.85, override=None).calculate(_ti())
    assert r.score == 0.85 and r.category == "high"


async def test_freeze_beats_override():
    r = await _FakeCalc(computed=0.85, override=0.60, frozen=True).calculate(_ti())
    assert r.score == 0.0 and r.category == "frozen"
