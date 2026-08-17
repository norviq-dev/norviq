# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`apply_pep_denial` — the tighten-only property the pep_decision field rests on.

A PEP may report that it REFUSED a call, never that it permitted one. The field exists so a refusal
made before policy ran (MCP Gate A, schema conformance, the tool-header guard) reaches an audit row
instead of vanishing; it must be structurally incapable of doing anything else.

Pure-function tests, kept out of tests/mcp so they carry no asyncio marker — the property belongs to
the SDK contract, not to the MCP proxy that happens to be its first caller.
"""

from __future__ import annotations

import pytest

from norviq.sdk.core.decisions import PEP_UNATTRIBUTED_RULE, PolicyDecision, apply_pep_denial
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

# ── tighten-only: the field can never loosen a decision ────────────────────────────────────────────

class TestApplyPepDenialIsTightenOnly:
    """The security property the whole field rests on."""

    def test_it_blocks_an_allow(self):
        d = PolicyDecision(decision="allow", rule_id="default_allow", reason="Allowed")
        out = apply_pep_denial(d, "block", "mcp_gate_a_flagged", "definition flagged")
        assert out.decision == "block"
        assert out.rule_id == "mcp_gate_a_flagged"

    def test_a_policy_block_keeps_its_own_attribution(self):
        """An authored control that fired is the better audit attribution — it maps to a
        compliance requirement in a way "the proxy refused" does not."""
        d = PolicyDecision(decision="block", rule_id="pii_detection", reason="PII (SSN) detected")
        assert apply_pep_denial(d, "block", "mcp_gate_a_flagged", "x").rule_id == "pii_detection"

    def test_escalate_is_not_promoted_to_block(self):
        """Escalation is a human-in-the-loop outcome. Quietly converting a hold-for-approval into a
        hard denial would change enforcement under cover of an audit-fidelity change."""
        d = PolicyDecision(decision="escalate", rule_id="mcp_definition_drift", reason="drift")
        assert apply_pep_denial(d, "block", "x", "y").decision == "escalate"

    @pytest.mark.parametrize("value", ["allow", "audit", "ALLOW", "escalate", "unblock", "none"])
    def test_no_value_other_than_block_is_accepted_by_the_event(self, value):
        """The "cannot loosen" property is a property of the TYPE, not of one call site."""
        with pytest.raises(ValueError):
            ToolCallEvent(tool_name="t", tool_params={},
                          agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/a/sa/b",
                                                       namespace="a", agent_class="c"),
                          pep_decision=value)

    def test_an_absent_report_changes_nothing(self):
        d = PolicyDecision(decision="allow", rule_id="default_allow", reason="Allowed")
        assert apply_pep_denial(d, "") is d

    def test_an_unattributed_refusal_still_gets_a_name(self):
        """A block with a blank rule_id is unattributable in the audit log."""
        d = PolicyDecision(decision="allow", rule_id="default_allow", reason="Allowed")
        assert apply_pep_denial(d, "block").rule_id == PEP_UNATTRIBUTED_RULE
