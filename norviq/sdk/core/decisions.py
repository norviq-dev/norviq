# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy decision schema for tool-call evaluation."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    """Result of evaluating a tool call against policy."""

    decision: Literal["allow", "block", "escalate", "audit"]
    policy_id: str = ""
    policy_version: int = 0
    rule_id: str = ""
    reason: str = ""
    trust_score: float = 0.0
    trust_category: str = ""
    trust_signals: dict[str, float] = Field(default_factory=dict)
    trust_dominant_signal: str = ""
    trust_recommendation: str = ""
    latency_ms: float = 0.0
    event_id: str = ""
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"frozen": True}

    def is_blocked(self) -> bool:
        """Check if the decision blocks the tool call."""
        return self.decision == "block"

    def is_allowed(self) -> bool:
        """Check if the decision allows the tool call."""
        return self.decision in ("allow", "audit")

    def is_escalated(self) -> bool:
        """Check if the decision requires escalation."""
        return self.decision == "escalate"


#: Rule id recorded when a PEP reports a refusal but names no control of its own. Mirrors the
#: existing convention that a block with an empty rule_id is an unattributable gate refusal — this
#: gives that case a name instead, so the audit log never carries a blank.
PEP_UNATTRIBUTED_RULE = "pep_refused"


def apply_pep_denial(
    decision: PolicyDecision,
    pep_decision: str,
    pep_rule_id: str = "",
    pep_reason: str = "",
) -> PolicyDecision:
    """Fold a PEP's own refusal into the recorded decision. TIGHTEN-ONLY, by construction.

    A PEP enforces controls that are not policy — the MCP firewall's Gate A withholds a tool whose
    definition scanned as an injection, refuses one whose hash drifted after approval, rejects
    arguments the tool's own schema forbids. Those return before any policy runs, so the control
    plane never heard about them and the console could show nothing. This is how they get recorded.

    WHY THIS CANNOT BECOME A BYPASS, in three independent ways:

    1. The only accepted value is "block" (validated on `ToolCallEvent.pep_decision`), so there is no
       value that means "allow".
    2. The result is only ever written when it TIGHTENS. A policy that already blocked keeps its own
       decision and — deliberately — its own `rule_id`: an authored control that fired is the better
       audit attribution, and it maps to a compliance requirement in a way "the proxy refused" does
       not. The PEP's report is preserved separately by the caller.
    3. `escalate` is left alone rather than being promoted to `block`. Escalation is a human-in-the-
       loop outcome, and quietly converting a hold-for-approval into a hard denial would change
       enforcement behaviour under cover of an audit-fidelity change.

    APPLIED LAST, after namespace posture and per-policy audit mode. That ordering is the point: the
    call was ALREADY refused at the PEP, so softening the record to "audit" would state that the call
    would have been blocked when in fact it was. Monitor mode governs what the ENGINE does to traffic
    it is deciding on; it cannot un-happen something that already happened upstream of it.
    """
    if pep_decision != "block":
        return decision
    if decision.decision in ("block", "escalate"):
        return decision
    return decision.model_copy(update={
        "decision": "block",
        "rule_id": pep_rule_id or PEP_UNATTRIBUTED_RULE,
        "reason": pep_reason or "the enforcement point refused this call before policy evaluation",
    })
