# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-033: violations must be able to drive a COMPUTED trust score into the escalation band.

The actuation was never broken — an agent held at 0.35 escalates on a benign call and one at 0.45
allows, against the 0.4 threshold. What could not happen is a computed score arriving there.

The reason is arithmetic rather than tuning, which is why this is a cap and not a reweighting.
`violation_rate` carries weight 0.25, so an agent blocked on EVERY call loses at most 0.25 while its
other six signals still read as ordinary — it floors out near 0.75, nearly double the threshold.
Measured from the other end: 10 consecutive violations moved trust 0.615 -> 0.605. No amount of
steepening the signal's own buckets reaches 0.4, because the weight IS the ceiling.

§4.4's caveat is the other half and is asserted here too: a compliant agent must never approach 0.4.
"""

from __future__ import annotations

import pytest

from norviq.engine.trust.calculator import TrustCalculator

ESCALATION_THRESHOLD = 0.4


def _calc() -> TrustCalculator:
    return TrustCalculator.__new__(TrustCalculator)


def _signals(violation: float) -> dict[str, float]:
    """One badly-behaving signal, everything else pristine — the case the weighting could not reach."""
    return {k: (violation if k == "violation_rate" else 1.0) for k in TrustCalculator.WEIGHTS}


def test_a_constantly_blocked_agent_reaches_the_escalation_band():
    """The headline. violation_rate 0.0 is the signal's output for a block rate above 20%."""
    score = _calc()._weighted_sum(_signals(0.0))
    assert score < ESCALATION_THRESHOLD, (
        f"an agent blocked on more than a fifth of its calls scored {score}, which still allows"
    )


def test_the_old_arithmetic_could_not_have_reached_it():
    """Pins WHY this needed a cap, so nobody 'simplifies' it back into a weight.

    Reproduces the pre-fix computation: the plain weighted sum with the worst possible violation
    signal is still far above the threshold.
    """
    weights = TrustCalculator.WEIGHTS
    uncapped = sum(weights[k] * _signals(0.0)[k] for k in weights)
    assert uncapped == pytest.approx(0.75, abs=0.01)
    assert uncapped > ESCALATION_THRESHOLD


@pytest.mark.parametrize(
    ("violation", "band", "expected_max"),
    [
        (0.0, "blocked >20% of calls", 0.30),
        (0.2, "blocked >10% of calls", 0.45),
        (0.4, "blocked >5% of calls", 0.60),
    ],
)
def test_degradation_is_graduated(violation, band, expected_max):
    """Not a cliff: an agent gets visibly worse before it escalates, so an operator can act first."""
    assert _calc()._weighted_sum(_signals(violation)) == pytest.approx(expected_max, abs=0.01), band


def test_a_compliant_agent_is_numerically_unchanged():
    """§4.4's caveat. A clean agent has violation_rate 1.0, gets no cap, and must score exactly as
    the weighted sum always did — this change must be invisible to it."""
    calc = _calc()
    signals = _signals(1.0)
    weights = TrustCalculator.WEIGHTS
    uncapped = round(sum(weights[k] * signals[k] for k in weights), 4)
    assert calc._weighted_sum(signals) == uncapped == 1.0


def test_a_lightly_blocked_agent_is_not_capped_into_the_band():
    """violation_rate 0.8 is a block rate at or under 2% — noise, not a pattern. It must not cap."""
    score = _calc()._weighted_sum(_signals(0.8))
    assert score > 0.9, score


def test_the_cap_never_raises_a_score():
    """A cap is a ceiling. If some other combination of signals is already lower, it stays lower."""
    calc = _calc()
    floor_signals = {k: 0.0 for k in TrustCalculator.WEIGHTS}
    assert calc._weighted_sum(floor_signals) == 0.0


def test_no_history_is_not_treated_as_violations():
    """ViolationRateSignal returns 1.0 for an agent with no history. A brand-new agent must not be
    capped for having done nothing yet — that would escalate every first call in a fresh namespace."""
    assert _calc()._violation_cap({"violation_rate": 1.0}) == 1.0
