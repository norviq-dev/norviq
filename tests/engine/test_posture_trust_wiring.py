# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Posture + trust wiring regression (fail-on-bug).

Pure-logic units for the two engine-side wirings — no Redis, no OPA. They fail on code where the
methods/params don't exist and pass on the correct code.

- `_apply_posture`: namespace monitor (audit) mode softens a would-block/escalate to an allow-but-log `audit`
  decision, fires ONLY on an explicit per-ns override, exempts only the incident-response and resource-control
  rules, and NEVER tightens.
- `_categorize`/`_tiers`: per-ns trust_threshold moves the tiers; no-override keeps the bit-identical 0.7/0.4
  boundaries.
- the min() trust CAP (verified in calculator.calculate via a fake pipeline) only LOWERS effective trust.
"""

from __future__ import annotations

import pytest

from norviq.config import settings
from norviq.engine.evaluator import _BASE_POSTURE_EXEMPT_RULES, OPAEvaluator, _posture_exempt_rules
from norviq.engine.trust.calculator import TrustCalculator
from norviq.sdk.core.decisions import PolicyDecision


def _ev() -> OPAEvaluator:
    return OPAEvaluator(cache=None)  # type: ignore[arg-type] — _apply_posture is pure


def _dec(decision: str, rule_id: str) -> PolicyDecision:
    return PolicyDecision(decision=decision, rule_id=rule_id, reason=f"{rule_id} reason")


# --- Monitor-mode softening (_apply_posture) -----------------------------------------------------

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


@pytest.mark.parametrize("exempt", sorted(_posture_exempt_rules()))
def test_monitor_exempts_incident_response_and_resource_control(exempt):
    ev = _ev()
    posture = {"monitor": True, "trust_threshold": None, "rate_limit": 60}
    out = ev._apply_posture(_dec("block", exempt), posture, "evt")
    assert out.decision == "block" and out.rule_id == exempt        # freeze / throttle stay hard


# The behavioural change this stage exists for. These four USED to stay hard in monitor mode, which
# meant a namespace configured specifically to not drop customer traffic still dropped it whenever our
# own engine had a bad moment — a cold replica, an OPA fault, a malformed payload. Monitor mode is a
# promise that nothing is interrupted; an engine fault is our problem to raise, not their outage.
@pytest.mark.parametrize(
    "operational",
    ["policy_load_pending", "evaluator_error", "evaluator_invalid_payload", "evaluator_timeout"],
)
def test_monitor_softens_operational_blocks(operational):
    ev = _ev()
    posture = {"monitor": True, "trust_threshold": None, "rate_limit": 60}
    out = ev._apply_posture(_dec("block", operational), posture, "evt")
    assert out.decision == "audit", f"{operational} still interrupts traffic in monitor mode"
    assert out.rule_id == f"monitor_would_block:{operational}"   # recorded, not silently dropped


def test_exempt_set_contents():
    """Two rules, and each earns its place for a different reason than 'it is a block'.

    `trust_frozen` is an operator's incident-response kill switch and must outrank posture.
    `rate_limit_exceeded` protects the customer's own backend — "do not block on policy" is not a
    request for unbounded call volume.
    """
    assert _BASE_POSTURE_EXEMPT_RULES == {"trust_frozen"}
    assert _posture_exempt_rules() == {"trust_frozen", "rate_limit_exceeded"}  # default config
    for gone in ("policy_load_pending", "evaluator_error", "evaluator_invalid_payload"):
        assert gone not in _posture_exempt_rules(), f"{gone} must soften — monitor mode must not drop traffic"


def test_rate_limit_can_be_made_to_soften_too(monkeypatch):
    """For operators who want monitor mode to mean literally nothing is ever refused."""
    monkeypatch.setattr(settings, "monitor_exempt_rate_limit", False, raising=False)
    assert _posture_exempt_rules() == {"trust_frozen"}
    ev = _ev()
    out = ev._apply_posture(_dec("block", "rate_limit_exceeded"), {"monitor": True}, "evt")
    assert out.decision == "audit"


# --- trust_threshold tiers (_categorize / _tiers) ------------------------------------------------

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


# --- The min() cap (tighten-only) via calculate() with a fake pipeline ----------------------------

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

    def _weighted_sum(self, signals, sample_size=0):
        # `sample_size` mirrors the real signature (it carries len(history), for the violation cap's
        # minimum-observations bound). Accepted and ignored: this double exists to pin a FIXED
        # computed score so the override tests can assert the tighten-only rule, and honouring the
        # cap here would make the score depend on the fixture's history length instead.
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


# --- monitor mode on the EXCEPTION paths (the blocker the campaign found) -------------------------
#
# `_apply_posture` has only three call sites and all three are on the happy path, ABOVE the try. The
# three exception handlers in `evaluate()` built their decision and returned it directly, so monitor
# mode never ran on them. Narrowing the exempt set changed nothing for these: they were not softened
# because they were exempt, they were not softened because the softening never executed.
#
# That made monitor mode's promise false exactly where it matters most — a namespace configured to
# interrupt nothing still dropped customer traffic whenever OUR engine timed out or faulted.

class _StubCache:
    """Minimal cache: _resolve_posture only needs get_ns_settings."""

    def __init__(self, mode: str | None) -> None:
        self._mode = mode

    async def get_ns_settings(self, _ns: str):
        return {"enforcement_mode": self._mode} if self._mode else None


class _BoomCache:
    async def get_ns_settings(self, _ns: str):
        raise RuntimeError("redis down")


def _event():
    from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

    return ToolCallEvent(
        tool_name="get_order", tool_params={"order_id": "ORD-1"},
        agent_identity=AgentIdentity(spiffe_id="spiffe://n/ns/cmp/sa/a", namespace="cmp"),
    )


@pytest.mark.parametrize("rule_id", ["evaluator_timeout", "evaluator_fallback", "invalid_spiffe_identity"])
async def test_failure_path_decisions_soften_under_monitor(rule_id: str) -> None:
    ev = OPAEvaluator(_StubCache("audit"))  # type: ignore[arg-type]
    out = await ev._soften_failure_for_posture(_dec("block", rule_id), _event())
    assert out.decision == "audit", f"{rule_id} still interrupts traffic in a monitor namespace"
    assert out.rule_id == f"monitor_would_block:{rule_id}"


@pytest.mark.parametrize("rule_id", ["evaluator_timeout", "evaluator_fallback", "invalid_spiffe_identity"])
async def test_failure_path_decisions_stay_hard_without_monitor(rule_id: str) -> None:
    """An enforcing namespace is unchanged — this must not become a blanket fail-open."""
    ev = OPAEvaluator(_StubCache(None))  # type: ignore[arg-type]
    out = await ev._soften_failure_for_posture(_dec("block", rule_id), _event())
    assert out.decision == "block" and out.rule_id == rule_id


async def test_unreadable_posture_keeps_the_hard_verdict() -> None:
    """Redis is often the reason we are in the handler at all. If we cannot establish that the
    customer asked for monitor, we must not assume it."""
    ev = OPAEvaluator(_BoomCache())  # type: ignore[arg-type]
    out = await ev._soften_failure_for_posture(_dec("block", "evaluator_fallback"), _event())
    assert out.decision == "block"


def test_the_handlers_actually_call_the_softener() -> None:
    """Guards the WIRING, which is the half that was missing. The helper existing and being correct
    is worthless if `evaluate()`'s handlers still return their decision directly."""
    import inspect

    from norviq.engine import evaluator as mod

    src = inspect.getsource(mod.OPAEvaluator.evaluate)
    assert src.count("_soften_failure_for_posture") == 3, (
        "expected all three exception handlers (timeout, invalid identity, generic) to soften"
    )
