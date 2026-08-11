# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A policy saved in audit mode must not hard-block (B-03).

The Catalog renders each policy's `enforcement_mode` as a badge, and the API persists it — but the
engine only ever consulted the NAMESPACE posture, so a policy saved as `audit` displayed an AUDIT chip
and blocked anyway. That is the damaging kind of UI lie: the operator believes they are trialling a
rule safely while it breaks production traffic.

Found by creating an audit-mode policy live on AKS and watching it block.

The softening is applied to the WINNER before the eval-cache write. That is safe here even though
namespace posture deliberately is not cached: a policy write calls `_invalidate_eval_for_policy_scope`
and publishes `norviq:policy:invalidated` to peers, so flipping a mode clears the affected decisions.
Posture has no such hook, which is why it stays a per-call override.
"""

from __future__ import annotations

from norviq.engine.evaluator import OPAEvaluator, _posture_exempt_rules
from norviq.sdk.core.decisions import PolicyDecision


def _soften(decision: str, rule_id: str, mode: str) -> PolicyDecision:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    winner = {"decision": PolicyDecision(decision=decision, rule_id=rule_id), "enforcement_mode": mode}
    return ev._apply_policy_mode(winner, "evt-1")


def test_audit_mode_softens_a_block() -> None:
    d = _soften("block", "deny_sql_injection", "audit")
    assert d.decision == "audit"


def test_audit_mode_softens_an_escalate() -> None:
    assert _soften("escalate", "llm06_excessive_agency", "audit").decision == "audit"


def test_the_would_block_rule_is_preserved_in_the_rule_id() -> None:
    """Softening must not erase WHAT would have blocked — that is the entire value of monitor mode."""
    d = _soften("block", "deny_sql_injection", "audit")
    assert d.rule_id == "policy_audit_would_block:deny_sql_injection"


def test_block_mode_is_untouched() -> None:
    """The default path must be byte-identical to before — this is the hot path for every install."""
    d = _soften("block", "deny_sql_injection", "block")
    assert (d.decision, d.rule_id) == ("block", "deny_sql_injection")


def test_a_missing_mode_defaults_to_block() -> None:
    """An entry predating the field must fail CLOSED, never soften by accident."""
    ev = OPAEvaluator.__new__(OPAEvaluator)
    winner = {"decision": PolicyDecision(decision="block", rule_id="x")}  # no enforcement_mode key
    assert ev._apply_policy_mode(winner, "evt").decision == "block"


def test_allows_are_never_touched() -> None:
    for verdict in ("allow", "audit"):
        assert _soften(verdict, "default_allow", "audit").decision == verdict


def test_exempt_rules_stay_hard_even_in_audit_mode() -> None:
    """An admin trust freeze is an incident-response kill switch — a policy's own mode must not be able
    to monitor it away, exactly as namespace posture cannot."""
    assert _posture_exempt_rules(), "exempt set is empty — nothing would be protected"
    for rule in _posture_exempt_rules():
        d = _soften("block", rule, "audit")
        assert d.decision == "block", f"{rule} was softened away"
        assert d.rule_id == rule


def test_operational_blocks_soften_under_a_policys_own_audit_mode() -> None:
    """Parity with namespace posture: a policy trialled in audit mode must not still drop traffic
    because the engine had a bad moment. These four used to be exempt here too."""
    for rule in ("policy_load_pending", "evaluator_error", "evaluator_invalid_payload", "evaluator_timeout"):
        d = _soften("block", rule, "audit")
        assert d.decision == "audit", f"{rule} still interrupts traffic under an audit-mode policy"
        assert d.rule_id == f"policy_audit_would_block:{rule}"
