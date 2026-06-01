# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Audit schema combining tool event and policy decision."""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent


class AuditRecord(BaseModel):
    """Immutable audit trail entry combining event and decision."""

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    tool_name: str
    decision: str
    agent_id: str
    agent_class: str = ""
    namespace: str = ""
    policy_id: str = ""
    policy_version: int = 0
    rule_id: str = ""
    reason: str = ""
    session_id: str = ""
    trust_score: float = 0.0
    latency_ms: float = 0.0
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict | None = None

    model_config = {"frozen": True}

    @classmethod
    def from_event_and_decision(
        cls, event: ToolCallEvent, decision: PolicyDecision, payload: dict | None = None
    ) -> "AuditRecord":
        """Create an AuditRecord from event and policy decision."""
        return cls(
            event_id=event.event_id,
            tool_name=event.tool_name,
            decision=decision.decision,
            agent_id=event.agent_identity.spiffe_id,
            agent_class=event.agent_identity.agent_class,
            namespace=event.agent_identity.namespace,
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            rule_id=decision.rule_id,
            reason=decision.reason,
            session_id=event.session_id,
            trust_score=decision.trust_score,
            latency_ms=decision.latency_ms,
            payload=payload,
        )
