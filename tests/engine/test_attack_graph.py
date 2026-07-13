# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Unit tests for AttackGraphEngine."""

import pytest

from norviq.engine.attack_graph import AttackGraphEngine
from norviq.engine.attack_graph_models import AttackStep


class TestRiskScoring:
    def test_score_increases_for_sensitive_target(self):
        engine = AttackGraphEngine(evaluator=None)
        score = engine._compute_risk_score(
            steps=[],
            target={"type": "data", "name": "customers_db"},
            agent={"properties": {"trust_score": 0.5}},
        )
        # Base 0.3 + sensitive 0.2 = 0.5
        assert score == 0.5

    def test_score_decreases_when_blocked(self):
        engine = AttackGraphEngine(evaluator=None)
        steps = [
            AttackStep(
                step_num=1,
                node_id="t1",
                node_name="delete_record",
                node_type="tool",
                action="call_delete_record",
                policy_check="would_block",
            )
        ]
        score = engine._compute_risk_score(
            steps=steps,
            target={"type": "tool", "name": "delete_record"},
            agent={"properties": {"trust_score": 0.5}},
        )
        # Base 0.3 + dangerous_target 0.2 - blocked 0.3 = 0.2
        assert score == pytest.approx(0.2, abs=0.01)

    def test_score_increases_for_low_trust_agent(self):
        engine = AttackGraphEngine(evaluator=None)
        score = engine._compute_risk_score(
            steps=[],
            target={"type": "data", "name": "regular_data"},
            agent={"properties": {"trust_score": 0.2}},  # low trust
        )
        # Base 0.3 + low_trust 0.1 = 0.4
        assert score == pytest.approx(0.4, abs=0.01)


class TestSeverityClassification:
    def test_critical_above_075(self):
        engine = AttackGraphEngine(evaluator=None)
        assert engine._severity_from_score(0.9) == "critical"
        assert engine._severity_from_score(0.75) == "critical"

    def test_high_between_05_and_075(self):
        engine = AttackGraphEngine(evaluator=None)
        assert engine._severity_from_score(0.6) == "high"
        assert engine._severity_from_score(0.5) == "high"

    def test_medium_between_025_and_05(self):
        engine = AttackGraphEngine(evaluator=None)
        assert engine._severity_from_score(0.4) == "medium"

    def test_low_below_025(self):
        engine = AttackGraphEngine(evaluator=None)
        assert engine._severity_from_score(0.1) == "low"


class TestMITREMapping:
    def test_delete_record_mapped_to_destruction(self):
        engine = AttackGraphEngine(evaluator=None)
        steps = [
            AttackStep(
                step_num=1,
                node_id="t1",
                node_name="delete_record",
                node_type="tool",
                action="call_delete_record",
                policy_check="would_allow",
            )
        ]
        techniques = engine._extract_mitre_techniques(steps)
        assert "AML.T0048" in techniques

    def test_empty_for_unknown_tools(self):
        engine = AttackGraphEngine(evaluator=None)
        steps = [
            AttackStep(
                step_num=1,
                node_id="t1",
                node_name="search_kb",
                node_type="tool",
                action="call_search_kb",
                policy_check="would_allow",
            )
        ]
        techniques = engine._extract_mitre_techniques(steps)
        assert techniques == []
