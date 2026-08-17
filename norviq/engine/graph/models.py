# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Typed models for graph nodes, edges, and analysis results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    """Supported graph node types."""

    AGENT = "agent"
    TOOL = "tool"
    DATA = "data"
    # The MCP server a tool was SERVED BY. A distinct kind rather than a property on the tool node
    # because the estate question — "which integrations is my agent estate talking to" — is asked of
    # the server, and because one server serves many tools while one tool name may be served by
    # several (`read_file` on `filesystem` and on `runbooks` are different definitions).
    MCP_SERVER = "mcp_server"


class EdgeType(str, Enum):
    """Supported graph edge types."""

    CALLS = "calls"
    ACCESSES = "accesses"
    DELEGATES = "delegates"
    # server -> tool. Directed that way because the server is what PROVIDES the definition; the agent
    # still `calls` the tool, so an existing agent->tool path is unchanged by this edge existing.
    SERVES = "serves"


class RiskLevel(str, Enum):
    """Tool risk categories for path scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GraphNode:
    """Node payload for network graph storage."""

    id: str
    type: NodeType
    label: str
    namespace: str = ""
    properties: dict[str, object] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """Edge payload for network graph storage."""

    source: str
    target: str
    type: EdgeType
    weight: float = 1.0
    properties: dict[str, object] = field(default_factory=dict)


@dataclass
class AttackPath:
    """Computed path metadata for attack traversal."""

    source: str
    target: str
    path: list[str]
    path_risk: float
    trust_scores: list[float]
    min_trust: float
    edge_types: list[str]
    length: int


@dataclass
class BlastRadius:
    """Reachability summary for a compromised source."""

    source: str
    reachable_agents: list[str]
    reachable_tools: list[str]
    reachable_data: list[str]
    total_reachable: int
    critical_data: list[str]
    attack_paths: list[AttackPath]
    risk_score: float
