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
