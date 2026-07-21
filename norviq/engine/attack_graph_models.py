# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Dataclasses for attack graph paths and steps."""

from dataclasses import dataclass, field
from typing import Literal


PolicyCheck = Literal["would_block", "would_allow", "no_policy"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass
class AttackStep:
    """One hop in a computed attack path: a node reached and how policy would rule on it."""

    step_num: int
    node_id: str
    node_name: str
    node_type: str
    action: str  # e.g. "call_tool", "access_data"
    policy_check: PolicyCheck
    matched_rule: str = ""


@dataclass
class AttackPath:
    """An ordered chain of steps from a source agent to a target asset, scored and MITRE-tagged."""

    path_id: str  # UUID
    namespace: str
    source_id: str  # agent node
    target_id: str  # data or tool node
    steps: list[AttackStep] = field(default_factory=list)
    risk_score: float = 0.0
    severity: Severity = "low"
    mitre_techniques: list[str] = field(default_factory=list)
    blocked_by_policy: bool = False
