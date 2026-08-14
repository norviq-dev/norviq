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

# Enough observations for a rate to mean something — see _MIN_OBSERVATIONS_FOR_CAP.
_ENOUGH = TrustCalculator._MIN_OBSERVATIONS_FOR_CAP


def _calc() -> TrustCalculator:
    return TrustCalculator.__new__(TrustCalculator)


def _signals(violation: float) -> dict[str, float]:
    """One badly-behaving signal, everything else pristine — the case the weighting could not reach."""
    return {k: (violation if k == "violation_rate" else 1.0) for k in TrustCalculator.WEIGHTS}


def test_a_constantly_blocked_agent_reaches_the_escalation_band():
    """The headline. violation_rate 0.0 is the signal's output for a block rate above 20%."""
    score = _calc()._weighted_sum(_signals(0.0), sample_size=_ENOUGH)
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
    assert _calc()._weighted_sum(_signals(violation), sample_size=_ENOUGH) == pytest.approx(expected_max, abs=0.01), band


def test_a_compliant_agent_is_numerically_unchanged():
    """§4.4's caveat. A clean agent has violation_rate 1.0, gets no cap, and must score exactly as
    the weighted sum always did — this change must be invisible to it."""
    calc = _calc()
    signals = _signals(1.0)
    weights = TrustCalculator.WEIGHTS
    uncapped = round(sum(weights[k] * signals[k] for k in weights), 4)
    assert calc._weighted_sum(signals, sample_size=_ENOUGH) == uncapped == 1.0


def test_a_lightly_blocked_agent_is_not_capped_into_the_band():
    """violation_rate 0.8 is a block rate at or under 2% — noise, not a pattern. It must not cap."""
    score = _calc()._weighted_sum(_signals(0.8), sample_size=_ENOUGH)
    assert score > 0.9, score


def test_the_cap_never_raises_a_score():
    """A cap is a ceiling. If some other combination of signals is already lower, it stays lower."""
    calc = _calc()
    floor_signals = {k: 0.0 for k in TrustCalculator.WEIGHTS}
    assert calc._weighted_sum(floor_signals, sample_size=_ENOUGH) == 0.0


def test_no_history_is_not_treated_as_violations():
    """ViolationRateSignal returns 1.0 for an agent with no history. A brand-new agent must not be
    capped for having done nothing yet — that would escalate every first call in a fresh namespace."""
    assert _calc()._violation_cap({"violation_rate": 1.0}, sample_size=_ENOUGH) == 1.0


# --- the bound the sidecar suite caught -------------------------------------------------------
#
# The first version of this cap keyed on the RATE alone, and a rate over a handful of calls is noise.
# An agent whose 2nd call tripped a control sat at 50% and was capped to 0.30 — inside the escalation
# band — on the strength of ONE block, after which every benign call escalated.
#
# Found by tests/sidecar/test_proxy.py, where an earlier test in the module blocks once for the same
# identity and the next benign call started dropping. A unit test written from the same assumption as
# the code would not have found it; the integration path did.


def test_a_single_block_in_a_short_history_does_not_cap():
    calc = _calc()
    for n in (1, 2, 5, 10, TrustCalculator._MIN_OBSERVATIONS_FOR_CAP - 1):
        score = calc._weighted_sum(_signals(0.0), sample_size=n)
        assert score > ESCALATION_THRESHOLD, (
            f"{n} observations was enough to force escalation — that is one unlucky call, not a pattern"
        )


def test_the_cap_applies_once_there_is_enough_evidence():
    assert _calc()._weighted_sum(_signals(0.0), sample_size=_ENOUGH) < ESCALATION_THRESHOLD


def test_the_signal_still_moves_the_score_below_the_bound():
    """Not capped is not ignored: violations still cost their 0.25 weight on a short history, so the
    score degrades — it just cannot be forced into the escalation band by a single event."""
    calc = _calc()
    clean = calc._weighted_sum(_signals(1.0), sample_size=3)
    dirty = calc._weighted_sum(_signals(0.0), sample_size=3)
    assert dirty < clean


def test_the_default_is_no_cap():
    """A caller that does not supply a sample size gets the pre-cap behaviour, never a surprise
    escalation from a default it did not choose."""
    assert _calc()._weighted_sum(_signals(0.0)) > ESCALATION_THRESHOLD
