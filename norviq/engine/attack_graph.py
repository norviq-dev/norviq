# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Attack Graph Engine — computes attack paths through asset graph."""

import uuid
from dataclasses import asdict
import json
from datetime import datetime, timezone

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.engine.attack_graph_models import (
    AttackPath,
    AttackStep,
    PolicyCheck,
    Severity,
)
from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

log = structlog.get_logger()

# Tools considered high-risk for path scoring
DANGEROUS_TOOLS = {
    "delete_record",
    "drop_table",
    "truncate",
    "execute_sql",
    "send_email",
    "transfer_funds",
    "modify_config",
}

# Data resources considered sensitive
SENSITIVE_DATA_PATTERNS = ["customers", "users", "payments", "pii", "secrets"]

# MITRE ATLAS technique mapping (basic heuristic)
MITRE_BY_TOOL_TYPE = {
    "delete_record": ["AML.T0048"],  # Data Destruction
    "drop_table": ["AML.T0048"],
    "execute_sql": ["AML.T0049"],  # Discovery
    "send_email": ["AML.T0040"],  # ML Model Inference API
    "search_kb": [],
}


class AttackGraphEngine:
    """Walks asset graph and computes attack paths through it."""

    def __init__(self, evaluator: OPAEvaluator):
        self.evaluator = evaluator

    async def compute_paths_for_namespace(
        self, session: AsyncSession, namespace: str
    ) -> int:
        """Compute all attack paths for a namespace. Returns count."""
        log.info(
            "nrvq.attack_graph.compute_started",
            namespace=namespace,
            code="NRVQ-ENG-2050",
        )

        # 1. Load latest asset graph snapshot for namespace
        graph_id = await self._load_graph_id(session, namespace)
        nodes_by_id = await self._load_nodes(session, namespace)
        edges = await self._load_edges(session, namespace)

        if not graph_id or not nodes_by_id:
            log.info(
                "nrvq.attack_graph.no_assets",
                namespace=namespace,
                code="NRVQ-ENG-2051",
            )
            return 0

        # 2. Find agents (path sources)
        agents = [n for n in nodes_by_id.values() if n["type"] == "agent"]
        if not agents:
            return 0

        # 3. Build adjacency list for traversal
        adjacency = self._build_adjacency(edges)

        # 4. For each agent, find paths to data/sensitive tools
        all_paths: list[AttackPath] = []
        for agent in agents:
            paths = await self._find_paths_from_agent(
                agent, nodes_by_id, adjacency, namespace
            )
            all_paths.extend(paths)

        # 5. Clear old paths for this namespace
        await session.execute(
            text(
                """
            DELETE FROM attack_paths
            WHERE graph_id IN (
                SELECT id FROM asset_graph WHERE namespace = :ns
            )
        """
            ),
            {"ns": namespace},
        )

        # 6. Insert new paths
        inserted = 0
        for path in all_paths:
            await session.execute(
                text(
                    """
                INSERT INTO attack_paths
                    (id, graph_id, source_node, target_node, path_json, risk_score, computed_at)
                VALUES
                    (:id, :graph_id, :source_node, :target_node, CAST(:path_json AS jsonb), :risk_score, :computed_at)
            """
                ),
                {
                    "id": path.path_id,
                    "graph_id": graph_id,
                    "source_node": path.source_id,
                    "target_node": path.target_id,
                    "path_json": json.dumps(
                        {
                            "path_id": path.path_id,
                            "source_id": path.source_id,
                            "target_id": path.target_id,
                            "steps": [asdict(s) for s in path.steps],
                            "risk_score": path.risk_score,
                            "severity": path.severity,
                            "mitre_techniques": path.mitre_techniques,
                            "blocked_by_policy": path.blocked_by_policy,
                        }
                    ),
                    "risk_score": path.risk_score,
                    "computed_at": datetime.now(timezone.utc),
                },
            )
            inserted += 1

        await session.commit()

        log.info(
            "nrvq.attack_graph.compute_completed",
            namespace=namespace,
            paths_computed=inserted,
            code="NRVQ-ENG-2052",
        )
        return inserted

    async def compute_all_namespaces(self, session: AsyncSession) -> dict:
        """Compute paths for every namespace with assets."""
        result = await session.execute(
            text(
                """
            SELECT DISTINCT namespace AS ns
            FROM asset_graph
            WHERE namespace IS NOT NULL
        """
            )
        )
        namespaces = [r.ns for r in result if r.ns]

        counts = {}
        for ns in namespaces:
            counts[ns] = await self.compute_paths_for_namespace(session, ns)

        return counts

    # ── Helpers ───────────────────────────────────────────────────

    async def _load_graph_id(self, session: AsyncSession, namespace: str) -> str | None:
        """Load latest graph snapshot ID for a namespace."""
        row = (
            await session.execute(
                text(
                    """
                SELECT id
                FROM asset_graph
                WHERE namespace = :ns
                ORDER BY built_at DESC
                LIMIT 1
            """
                ),
                {"ns": namespace},
            )
        ).first()
        return str(row.id) if row else None

    async def _load_nodes(self, session: AsyncSession, namespace: str) -> dict:
        """Load all nodes for a namespace, keyed by id."""
        row = (
            await session.execute(
                text(
                    """
                SELECT graph_json
                FROM asset_graph
                WHERE namespace = :ns
                ORDER BY built_at DESC
                LIMIT 1
            """
                ),
                {"ns": namespace},
            )
        ).mappings().first()
        graph_json = row.get("graph_json") if row else {}
        raw_nodes = graph_json.get("nodes", []) if isinstance(graph_json, dict) else []
        nodes: dict[str, dict] = {}
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id", ""))
            if not node_id:
                continue
            nodes[node_id] = {
                "id": node_id,
                "type": str(node.get("type", "data")),
                "name": str(node.get("name", node_id)),
                "properties": dict(node.get("properties") or {}),
            }
        return nodes

    async def _load_edges(self, session: AsyncSession, namespace: str) -> list:
        """Load all edges for a namespace."""
        row = (
            await session.execute(
                text(
                    """
                SELECT graph_json
                FROM asset_graph
                WHERE namespace = :ns
                ORDER BY built_at DESC
                LIMIT 1
            """
                ),
                {"ns": namespace},
            )
        ).mappings().first()
        graph_json = row.get("graph_json") if row else {}
        raw_edges = graph_json.get("edges", []) if isinstance(graph_json, dict) else []
        edges: list[dict[str, object]] = []
        for edge in raw_edges:
            if not isinstance(edge, dict):
                continue
            source_id = str(edge.get("source", ""))
            target_id = str(edge.get("target", ""))
            if not source_id or not target_id:
                continue
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "type": str(edge.get("type", "calls")),
                    "weight": float(edge.get("weight") or 1.0),
                }
            )
        return edges

    def _build_adjacency(self, edges: list) -> dict:
        """Build adjacency list: source_id -> [target_ids]."""
        adj: dict[str, list[str]] = {}
        for e in edges:
            adj.setdefault(e["source"], []).append(e["target"])
        return adj

    async def _find_paths_from_agent(
        self, agent: dict, nodes_by_id: dict, adjacency: dict, namespace: str
    ) -> list[AttackPath]:
        """DFS from agent to all reachable data/sensitive nodes (max depth 4)."""
        paths: list[AttackPath] = []
        agent_id = agent["id"]
        visited = {agent_id}

        async def dfs(current_id: str, path_nodes: list[str], depth: int):
            if depth > 4:
                return

            for next_id in adjacency.get(current_id, []):
                if next_id in visited:
                    continue
                if next_id not in nodes_by_id:
                    continue

                new_path = path_nodes + [next_id]
                next_node = nodes_by_id[next_id]

                # Terminal: data node or dangerous tool
                if next_node["type"] == "data" or (
                    next_node["type"] == "tool" and next_node["name"] in DANGEROUS_TOOLS
                ):
                    path = await self._build_attack_path(
                        agent, new_path, nodes_by_id, namespace
                    )
                    paths.append(path)

                visited.add(next_id)
                await dfs(next_id, new_path, depth + 1)
                visited.remove(next_id)

        await dfs(agent_id, [agent_id], 0)
        return paths

    async def _build_attack_path(
        self, agent: dict, node_ids: list[str], nodes_by_id: dict, namespace: str
    ) -> AttackPath:
        """Build an AttackPath from a list of node IDs."""
        source_id = node_ids[0]
        target_id = node_ids[-1]
        target_node = nodes_by_id[target_id]

        # Evaluate each step (after source) against policies
        steps: list[AttackStep] = []
        for i, node_id in enumerate(node_ids[1:], start=1):
            node = nodes_by_id[node_id]
            policy_check, matched_rule = await self._evaluate_step(agent, node, namespace)

            steps.append(
                AttackStep(
                    step_num=i,
                    node_id=node_id,
                    node_name=node["name"],
                    node_type=node["type"],
                    action=self._action_for_node(node),
                    policy_check=policy_check,
                    matched_rule=matched_rule,
                )
            )

        # Score the path
        risk_score = self._compute_risk_score(steps, target_node, agent)
        severity = self._severity_from_score(risk_score)
        blocked_by_policy = any(s.policy_check == "would_block" for s in steps)
        mitre = self._extract_mitre_techniques(steps)

        return AttackPath(
            path_id=str(uuid.uuid4()),
            namespace=namespace,
            source_id=source_id,
            target_id=target_id,
            steps=steps,
            risk_score=risk_score,
            severity=severity,
            mitre_techniques=mitre,
            blocked_by_policy=blocked_by_policy,
        )

    async def _evaluate_step(
        self, agent: dict, node: dict, namespace: str
    ) -> tuple[PolicyCheck, str]:
        """Run evaluator to check what would happen for this step."""
        if node["type"] != "tool":
            return ("no_policy", "")  # data/namespace nodes not policy-evaluated

        # Build minimal event for evaluation
        event = ToolCallEvent(
            event_id=f"attack-path-sim-{node['id']}",
            tool_name=node["name"],
            tool_params={},  # empty — we're checking policy not data
            agent_identity=AgentIdentity(
                spiffe_id=agent["properties"].get("spiffe_id", ""),
                namespace=namespace,
                agent_class=agent["properties"].get("agent_class", ""),
            ),
            session_id="attack-graph-engine",
            trust_score=agent["properties"].get("trust_score", 0.5),
        )

        try:
            decision = await self.evaluator.evaluate(event)
            if decision.decision == "block":
                return ("would_block", decision.rule_id or "")
            if decision.decision == "allow":
                return ("would_allow", decision.rule_id or "default_allow")
            return ("no_policy", decision.rule_id or "")
        except Exception as exc:
            log.warning(
                "nrvq.attack_graph.eval_failed",
                node=node["name"],
                error=str(exc),
                code="NRVQ-ENG-2053",
            )
            return ("no_policy", "evaluator_error")

    def _action_for_node(self, node: dict) -> str:
        if node["type"] == "tool":
            return f"call_{node['name']}"
        if node["type"] == "data":
            return f"access_{node['name']}"
        return "traverse"

    def _compute_risk_score(
        self, steps: list[AttackStep], target: dict, agent: dict
    ) -> float:
        """Compute 0.0-1.0 risk score for a path."""
        # Base: 0.3 for every path
        score = 0.3

        # +0.2 if target is sensitive data
        if target["type"] == "data":
            name_lower = target["name"].lower()
            if any(p in name_lower for p in SENSITIVE_DATA_PATTERNS):
                score += 0.2

        # +0.2 if target is a dangerous tool
        if target["type"] == "tool" and target["name"] in DANGEROUS_TOOLS:
            score += 0.2

        # +0.1 per unblocked dangerous tool in path
        for s in steps:
            if s.policy_check == "would_allow" and s.node_name in DANGEROUS_TOOLS:
                score += 0.1

        # -0.3 if any step is blocked (policy intervenes)
        if any(s.policy_check == "would_block" for s in steps):
            score -= 0.3

        # +0.1 if agent has low trust
        agent_trust = agent["properties"].get("trust_score", 0.5)
        if agent_trust < 0.4:
            score += 0.1

        return max(0.0, min(1.0, score))

    def _severity_from_score(self, score: float) -> Severity:
        if score >= 0.75:
            return "critical"
        if score >= 0.5:
            return "high"
        if score >= 0.25:
            return "medium"
        return "low"

    def _extract_mitre_techniques(self, steps: list[AttackStep]) -> list[str]:
        techniques = set()
        for s in steps:
            for t in MITRE_BY_TOOL_TYPE.get(s.node_name, []):
                techniques.add(t)
        return sorted(techniques)
