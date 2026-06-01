# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for PolicyDecision schema."""

from __future__ import annotations

import json
from datetime import timezone

import pytest
from pydantic import ValidationError

from norviq.sdk.core.decisions import PolicyDecision


def make_decision(decision: str = "allow") -> PolicyDecision:
    """Build a valid PolicyDecision with defaults."""
    return PolicyDecision(decision=decision)


def test_policy_decision_creates_with_defaults() -> None:
    """PolicyDecision should set defaults for optional fields."""
    result = make_decision()
    assert result.decision == "allow"
    assert result.policy_id == ""
    assert result.policy_version == 0
    assert result.rule_id == ""
    assert result.reason == ""
    assert result.trust_score == 0.0
    assert result.latency_ms == 0.0
    assert result.event_id == ""


def test_policy_decision_block_sets_fields() -> None:
    """PolicyDecision should preserve explicit field values."""
    result = PolicyDecision(decision="block", reason="high risk", rule_id="R-1")
    assert result.decision == "block"
    assert result.reason == "high risk"
    assert result.rule_id == "R-1"


def test_invalid_decision_raises_validation_error() -> None:
    """PolicyDecision should reject invalid decision literals."""
    with pytest.raises(ValidationError):
        make_decision(decision="invalid")


@pytest.mark.parametrize(
    ("decision", "expected"),
    [("allow", False), ("audit", False), ("escalate", False), ("block", True)],
)
def test_is_blocked_returns_expected(decision: str, expected: bool) -> None:
    """is_blocked should only be true for block decisions."""
    assert make_decision(decision=decision).is_blocked() is expected


@pytest.mark.parametrize(
    ("decision", "expected"),
    [("allow", True), ("audit", True), ("escalate", False), ("block", False)],
)
def test_is_allowed_returns_expected(decision: str, expected: bool) -> None:
    """is_allowed should be true for allow and audit decisions."""
    assert make_decision(decision=decision).is_allowed() is expected


@pytest.mark.parametrize(
    ("decision", "expected"),
    [("allow", False), ("audit", False), ("escalate", True), ("block", False)],
)
def test_is_escalated_returns_expected(decision: str, expected: bool) -> None:
    """is_escalated should only be true for escalate decisions."""
    assert make_decision(decision=decision).is_escalated() is expected


def test_policy_decision_is_frozen() -> None:
    """PolicyDecision should reject mutation after creation."""
    result = make_decision()
    with pytest.raises(ValidationError):
        result.policy_id = "P-2"


def test_model_dump_and_json_work() -> None:
    """model_dump and model_dump_json should serialize successfully."""
    result = PolicyDecision(decision="audit", policy_id="P-1")
    dumped = result.model_dump()
    assert dumped["decision"] == "audit"
    assert dumped["policy_id"] == "P-1"
    loaded = json.loads(result.model_dump_json())
    assert loaded["decision"] == "audit"
    assert loaded["policy_id"] == "P-1"


def test_decided_at_is_auto_generated_and_timezone_aware() -> None:
    """decided_at should default to an aware UTC datetime."""
    result = make_decision()
    assert result.decided_at.tzinfo is not None
    assert result.decided_at.tzinfo == timezone.utc
