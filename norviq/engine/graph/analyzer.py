# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""High-level graph analyzer combining topology and risk views."""

from __future__ import annotations

from dataclasses import asdict

import structlog

from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.attack_graph import AttackGraphEngine

log = structlog.get_logger()


class GraphAnalyzer:
    """Coordinate asset and attack graph computations."""

    def __init__(self, asset_graph: AssetGraphBuilder) -> None:
        """Build attack engine from asset graph snapshot."""
        self._asset = asset_graph
        self._attack = AttackGraphEngine(asset_graph.graph)

    def full_analysis(self) -> dict[str, object]:
        """Run complete graph analysis payload."""
        summary = self._attack.get_summary()
        chokepoints = self._attack.find_chokepoints()[:10]
        critical_paths = [self._critical_path_row(path) for path in self._attack.find_critical_paths()[:20]]
        riskiest_agents = self._agent_risk_rows()[:5]
        log.info("nrvq.graph.full_analysis_complete", code="NRVQ-GRP-11014")
        return {
            "summary": summary,
            "chokepoints": chokepoints,
            "critical_paths": critical_paths,
            "riskiest_agents": riskiest_agents,
        }

    def _agent_risk_rows(self) -> list[dict[str, object]]:
        """Build sorted agent risk list from blast radius results."""
        rows = []
        for agent in self._asset.get_agents():
            agent_id = str(agent.get("id", ""))
            blast = self._attack.compute_blast_radius(agent_id)
            rows.append(self._agent_row(agent_id, agent, blast))
        rows.sort(key=lambda row: float(row["risk_score"]), reverse=True)
        return rows

    def _agent_row(self, agent_id: str, agent: dict[str, object], blast) -> dict[str, object]:
        """Convert one agent blast result to report row."""
        props = agent.get("properties", {})
        trust = float(props.get("trust_score", 0.8)) if isinstance(props, dict) else 0.8
        return {
            "agent": agent_id,
            "trust_score": trust,
            "reachable_data": len(blast.reachable_data),
            "critical_data": len(blast.critical_data),
            "risk_score": blast.risk_score,
        }

    def _critical_path_row(self, path) -> dict[str, object]:
        """Convert critical attack path to compact output row."""
        data = asdict(path)
        return {
            "source": data["source"],
            "target": data["target"],
            "length": data["length"],
            "risk": data["path_risk"],
            "min_trust": data["min_trust"],
        }
