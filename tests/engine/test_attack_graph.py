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


class TestStepVerdictMapsOnWhetherTheCallProceeds:
    """`_evaluate_step` must bucket on whether the call RUNS, not on the literal decision string.

    It used to test `== "block"` then `== "allow"`, dropping everything else into `no_policy`. That
    put `audit` — the shape every baseline control emits, because they all ship on `monitor` — into
    the least alarming of the three buckets, so a control that fired and recorded a dangerous call was
    reported as "nothing evaluated this". It also silently disarmed the dangerous-tool risk check,
    which keys on `would_allow and node_name in DANGEROUS_TOOLS`: an audited dangerous tool matched
    neither arm and raised nothing. Same defect as BUG-011 and C2-021, on a third surface.

    `escalate` groups with `block` (call held for a human, path not traversable unattended) — the same
    convention `redteam_efficacy._ENFORCED_DECISIONS` already uses.
    """

    @staticmethod
    async def _verdict(decision: str, rule_id: str = "some_rule"):
        from norviq.engine.attack_graph import AttackGraphEngine
        from norviq.sdk.core.decisions import PolicyDecision

        class _Ev:
            async def evaluate(self, event):
                return PolicyDecision(decision=decision, rule_id=rule_id, reason="t")

        eng = AttackGraphEngine.__new__(AttackGraphEngine)
        eng.evaluator = _Ev()
        return await eng._evaluate_step(
            {"id": "agent::a", "properties": {"agent_class": "c", "trust_score": 0.5, "spiffe_id": "spiffe://norviq/ns/analytics/sa/a"}, "name": "a"},
            {"id": "tool::delete_record", "type": "tool", "name": "delete_record", "properties": {}},
            "analytics",
        )

    async def test_audit_is_would_allow_because_the_call_runs(self):
        check, rule = await self._verdict("audit", "deny_shell_execution")
        assert check == "would_allow", "a monitored detection still lets the call through"
        assert rule == "deny_shell_execution", "the control that fired must stay attributable"

    async def test_escalate_is_would_block_because_a_human_holds_it(self):
        check, _ = await self._verdict("escalate")
        assert check == "would_block"

    async def test_block_and_allow_are_unchanged(self):
        assert (await self._verdict("block"))[0] == "would_block"
        assert (await self._verdict("allow", "default_allow")) == ("would_allow", "default_allow")
