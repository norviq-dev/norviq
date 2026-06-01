# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Attack graph computations on top of runtime asset graph."""

from __future__ import annotations

from dataclasses import asdict

import networkx as nx
import structlog

from norviq.engine.graph.models import AttackPath, BlastRadius, NodeType

log = structlog.get_logger()

RISK_WEIGHTS = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


class AttackGraphEngine:
    """Compute attack paths, blast radius, and graph risk metrics."""

    def __init__(self, graph: nx.DiGraph) -> None:
        """Store graph reference for path analysis."""
        self._graph = graph

    def compute_blast_radius(self, source_agent: str) -> BlastRadius:
        """Compute nodes and paths reachable from compromised source."""
        if source_agent not in self._graph:
            log.warning("nrvq.graph.agent_not_found", agent=source_agent, code="NRVQ-GRP-11010")
            return BlastRadius(source_agent, [], [], [], 0, [], [], 0.0)
        reachable = nx.descendants(self._graph, source_agent)
        agents = self._nodes_of_type(reachable, NodeType.AGENT)
        tools = self._nodes_of_type(reachable, NodeType.TOOL)
        data = self._nodes_of_type(reachable, NodeType.DATA)
        critical = [node for node in data if self._sensitivity(node) == "critical"]
        paths = self._all_paths_to_data(source_agent, data)
        risk = self._compute_risk_score(data, paths)
        log.info("nrvq.graph.blast_radius_computed", agent=source_agent, reachable=len(reachable), code="NRVQ-GRP-11011")
        return BlastRadius(source_agent, agents, tools, data, len(reachable), critical, paths, risk)

    def find_attack_paths(self, source: str, target: str, max_paths: int = 5) -> list[AttackPath]:
        """Find attack paths between arbitrary source and target."""
        return self._find_attack_paths(source, target, max_paths)

    def find_critical_paths(self) -> list[AttackPath]:
        """Find paths that include low-trust nodes."""
        critical_paths: list[AttackPath] = []
        for agent in self._all_nodes_of_type(NodeType.AGENT):
            for target in self._all_nodes_of_type(NodeType.DATA):
                critical_paths.extend([path for path in self._find_attack_paths(agent, target, 2) if path.min_trust < 0.4])
        log.info("nrvq.graph.critical_paths_found", count=len(critical_paths), code="NRVQ-GRP-11012")
        return critical_paths

    def find_chokepoints(self) -> list[dict[str, object]]:
        """Find tools that gate access to many data targets."""
        chokepoints: list[dict[str, object]] = []
        for tool in self._all_nodes_of_type(NodeType.TOOL):
            data_targets = [target for _, target in self._graph.out_edges(tool) if self._type(target) == NodeType.DATA]
            agents = [source for source, _ in self._graph.in_edges(tool) if self._type(source) == NodeType.AGENT]
            if data_targets and agents:
                chokepoints.append(
                    {
                        "tool": tool,
                        "agents_count": len(agents),
                        "data_count": len(data_targets),
                        "risk_level": self._risk_level(tool),
                    }
                )
        chokepoints.sort(key=lambda item: int(item["data_count"]), reverse=True)
        log.info("nrvq.graph.chokepoints_found", count=len(chokepoints), code="NRVQ-GRP-11013")
        return chokepoints

    def compute_risk_matrix(self) -> dict[str, dict[str, float]]:
        """Build agent-by-data matrix with best path risk."""
        matrix: dict[str, dict[str, float]] = {}
        for agent in self._all_nodes_of_type(NodeType.AGENT):
            matrix[agent] = {}
            for data in self._all_nodes_of_type(NodeType.DATA):
                paths = self._find_attack_paths(agent, data, 1)
                matrix[agent][data] = paths[0].path_risk if paths else 0.0
        return matrix

    def get_summary(self) -> dict[str, object]:
        """Return summary metrics for topology and trust posture."""
        agents = self._all_nodes_of_type(NodeType.AGENT)
        tools = self._all_nodes_of_type(NodeType.TOOL)
        data = self._all_nodes_of_type(NodeType.DATA)
        critical_tools = [tool for tool in tools if self._risk_level(tool) == "critical"]
        low_trust_agents = [agent for agent in agents if self._trust_score(agent) < 0.4]
        return {
            "total_nodes": self._graph.number_of_nodes(),
            "total_edges": self._graph.number_of_edges(),
            "agents": len(agents),
            "tools": len(tools),
            "data_resources": len(data),
            "critical_tools": len(critical_tools),
            "low_trust_agents": len(low_trust_agents),
            "has_cycles": not nx.is_directed_acyclic_graph(self._graph),
        }

    def _find_attack_paths(self, source: str, target: str, max_paths: int = 5) -> list[AttackPath]:
        """Find ordered simple paths up to max_paths limit."""
        if source not in self._graph or target not in self._graph:
            return []
        try:
            raw = list(nx.all_simple_paths(self._graph, source, target, cutoff=6))
        except nx.NetworkXError:
            return []
        raw.sort(key=len)
        return [self._to_attack_path(source, target, path) for path in raw[:max_paths]]

    def _to_attack_path(self, source: str, target: str, path: list[str]) -> AttackPath:
        """Convert raw path ids into attack-path model."""
        trust_scores = [self._trust_score(node) for node in path]
        edge_types = [str(self._graph.get_edge_data(path[idx], path[idx + 1], {}).get("type", "unknown")) for idx in range(len(path) - 1)]
        min_trust = min(trust_scores) if trust_scores else 1.0
        path_risk = self._compute_path_risk(path, trust_scores)
        return AttackPath(source, target, path, path_risk, trust_scores, min_trust, edge_types, len(path) - 1)

    def _compute_path_risk(self, path: list[str], trust_scores: list[float]) -> float:
        """Compute path risk from trust, tool risk, and path length."""
        if not path:
            return 0.0
        trust_factor = 1.0 - min(trust_scores or [1.0])
        tool_factor = max([RISK_WEIGHTS.get(self._risk_level(node), 0.5) for node in path if self._type(node) == NodeType.TOOL] or [0.5])
        length_factor = 1.0 / (1.0 + max(0, len(path) - 2) * 0.1)
        return round(trust_factor * tool_factor * length_factor, 3)

    def _compute_risk_score(self, data_nodes: list[str], paths: list[AttackPath]) -> float:
        """Compute aggregate blast radius risk score."""
        if not paths:
            return 0.0
        avg = sum(path.path_risk for path in paths) / len(paths)
        scale = min(1.0, len(data_nodes) / 10.0)
        return round(avg * (0.5 + 0.5 * scale), 3)

    def _all_paths_to_data(self, source: str, data_nodes: list[str]) -> list[AttackPath]:
        """Collect all bounded attack paths from source to data targets."""
        paths: list[AttackPath] = []
        for target in data_nodes:
            paths.extend(self._find_attack_paths(source, target))
        return paths

    def _nodes_of_type(self, nodes: set[str], node_type: NodeType) -> list[str]:
        """Filter node ids by type from provided set."""
        return [node for node in nodes if self._type(node) == node_type]

    def _all_nodes_of_type(self, node_type: NodeType) -> list[str]:
        """List all graph node ids for one type."""
        return [node for node in self._graph if self._type(node) == node_type]

    def _type(self, node: str) -> NodeType | None:
        """Return node type metadata."""
        return self._graph.nodes[node].get("type")

    def _trust_score(self, node: str) -> float:
        """Return trust score metadata with default."""
        return float(self._graph.nodes[node].get("properties", {}).get("trust_score", 1.0))

    def _risk_level(self, node: str) -> str:
        """Return tool risk metadata with default."""
        return str(self._graph.nodes[node].get("properties", {}).get("risk_level", "medium"))

    def _sensitivity(self, node: str) -> str:
        """Return data sensitivity metadata with default."""
        return str(self._graph.nodes[node].get("properties", {}).get("sensitivity", "medium"))

    @staticmethod
    def path_to_dict(path: AttackPath) -> dict[str, object]:
        """Convert attack path dataclass to dictionary."""
        return asdict(path)
