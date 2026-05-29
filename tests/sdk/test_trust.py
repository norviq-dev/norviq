# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for TrustScore schema."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from norviq.config import settings
from norviq.sdk.core.trust import TrustScore


def test_default_trust_score_values() -> None:
    """TrustScore should use default score and derived category."""
    trust = TrustScore()
    assert trust.score == 0.8
    assert trust.category == "High"


def test_category_medium_boundary() -> None:
    """Score in middle band should map to Medium category."""
    trust = TrustScore(score=0.5)
    assert trust.category == "Medium"


def test_category_low_boundary() -> None:
    """Score below medium threshold should map to Low category."""
    trust = TrustScore(score=0.3)
    assert trust.category == "Low"


def test_score_below_range_raises_validation_error() -> None:
    """Score below zero should fail validation."""
    with pytest.raises(ValidationError):
        TrustScore(score=-0.1)


def test_score_above_range_raises_validation_error() -> None:
    """Score above one should fail validation."""
    with pytest.raises(ValidationError):
        TrustScore(score=1.5)


def test_after_violation_applies_penalty_and_count() -> None:
    """Violation should reduce score and increment count."""
    trust = TrustScore(score=0.8)
    updated = trust.after_violation()
    assert updated.score == round(0.8 - settings.trust_violation_penalty, 4)
    assert updated.violation_count == 1
    assert updated.factors["last_violation"] == "penalty_applied"


def test_after_violation_returns_new_object() -> None:
    """Violation operation should keep original instance unchanged."""
    trust = TrustScore(score=0.8)
    updated = trust.after_violation()
    assert updated is not trust
    assert trust.score == 0.8
    assert trust.violation_count == 0


def test_is_trusted_matches_threshold() -> None:
    """is_trusted should reflect configured trust threshold."""
    assert TrustScore(score=settings.trust_threshold).is_trusted() is True
    assert TrustScore(score=0.3).is_trusted() is False


def test_model_is_frozen() -> None:
    """Frozen model should reject mutation."""
    trust = TrustScore()
    with pytest.raises(ValidationError):
        trust.score = 0.1


def test_score_rounds_to_four_decimals() -> None:
    """Score should be rounded to four decimal places."""
    trust = TrustScore(score=0.123456)
    assert trust.score == 0.1235
