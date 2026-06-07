# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Read-only endpoints for Asset Graph and Attack Graph UI."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.schemas.graphs import (
    AssetEdge,
    AssetGraphResponse,
    AssetNode,
    AttackPath,
    AttackPathsResponse,
    AttackStep,
)

log = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["graphs"])
RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}


def _safe_json(value: object) -> dict:
    return dict(value or {}) if isinstance(value, dict) else {}


@router.get("/asset-graph", response_model=AssetGraphResponse)
async def get_asset_graph(
    namespace: str = Query("default"),
    range: str = Query("24h"),
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(get_current_user),
):
    """Return nodes + edges for a namespace."""
    try:
        _ = _user
        hours = RANGE_HOURS.get(range, 24)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = (
            await session.execute(
                text("SELECT graph_json FROM asset_graph WHERE namespace = :ns ORDER BY built_at DESC LIMIT 1"),
                {"ns": namespace},
            )
        ).mappings().first()
        if not rows or not isinstance(rows.get("graph_json"), dict):
            log.info("nrvq.api.asset_graph.served", namespace=namespace, range=range, node_count=0, edge_count=0, code="NRVQ-API-7050")
            return AssetGraphResponse(nodes=[], edges=[])
        graph_json = rows["graph_json"]
        raw_nodes = graph_json.get("nodes", [])
        raw_edges = graph_json.get("edges", [])
        nodes: list[AssetNode] = []
        for node in raw_nodes:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id", ""))
            if not node_id:
                continue
            nodes.append(
                AssetNode(
                    id=node_id,
                    type=str(node.get("type", "data")),
                    name=str(node.get("name", node_id)),
                    properties=_safe_json(node.get("properties")),
                )
            )
        edges: list[AssetEdge] = []
        for edge in raw_edges:
            if not isinstance(edge, dict):
                continue
            source_id = str(edge.get("source", ""))
            target_id = str(edge.get("target", ""))
            if not source_id or not target_id:
                continue
            decision_history = {"allow": 0, "block": 0, "escalate": 0}
            tool_name = str(edge.get("target_name", ""))
            if tool_name:
                history_row = (
                    await session.execute(
                        text(
                            """
                            SELECT
                                COUNT(*) FILTER (WHERE decision = 'allow') AS allow_count,
                                COUNT(*) FILTER (WHERE decision = 'block') AS block_count,
                                COUNT(*) FILTER (WHERE decision = 'escalate') AS escalate_count
                            FROM audit_log
                            WHERE namespace = :ns
                              AND agent_id = :agent_id
                              AND tool_name = :tool_name
                              AND timestamp_utc >= :since
                            """
                        ),
                        {"ns": namespace, "agent_id": source_id, "tool_name": tool_name, "since": since},
                    )
                ).mappings().first()
                if history_row:
                    decision_history = {
                        "allow": int(history_row.get("allow_count") or 0),
                        "block": int(history_row.get("block_count") or 0),
                        "escalate": int(history_row.get("escalate_count") or 0),
                    }
            props = _safe_json(edge.get("properties"))
            props["decision_history"] = decision_history
            edges.append(
                AssetEdge(
                    source=source_id,
                    target=target_id,
                    type=str(edge.get("type", "calls")),
                    weight=float(edge.get("weight") or 1.0),
                    properties=props,
                )
            )
        log.info(
            "nrvq.api.asset_graph.served",
            namespace=namespace,
            range=range,
            node_count=len(nodes),
            edge_count=len(edges),
            code="NRVQ-API-7050",
        )
        return AssetGraphResponse(nodes=nodes, edges=edges)
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        log.error(
            "nrvq.api.asset_graph.error",
            error=str(exc),
            error_type=type(exc).__name__,
            traceback=tb,
            code="NRVQ-API-7050-ERR",
        )
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")


@router.get("/attack-paths", response_model=AttackPathsResponse)
async def get_attack_paths(
    namespace: str = Query("default"),
    severity: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(get_current_user),
):
    """Return precomputed attack paths sorted by risk score plus referenced nodes."""
    try:
        _ = _user
        sql = "SELECT path_json, risk_score FROM attack_paths ORDER BY computed_at DESC LIMIT 200"
        rows = (await session.execute(text(sql))).mappings().all()
        paths: list[AttackPath] = []
        referenced_nodes: set[str] = set()
        for row in rows:
            path_json = row.get("path_json") or {}
            if not isinstance(path_json, dict):
                continue
            source_id = str(path_json.get("source_id", ""))
            target_id = str(path_json.get("target_id", ""))
            if not source_id or not target_id:
                continue
            steps = []
            for idx, step in enumerate(path_json.get("steps", []), start=1):
                if not isinstance(step, dict):
                    continue
                node_id = str(step.get("node_id") or step.get("node") or "")
                if node_id:
                    referenced_nodes.add(node_id)
                steps.append(
                    AttackStep(
                        step_num=int(step.get("step_num", idx)),
                        node_id=node_id,
                        action=str(step.get("action", step.get("tool", "traverse"))),
                        policy_check=str(step.get("policy_check", "no_policy")),
                    )
                )
            sev = str(path_json.get("severity", "medium"))
            if severity and sev != severity:
                continue
            risk = float(path_json.get("risk_score", row.get("risk_score") or 0.0))
            p = AttackPath(
                path_id=str(path_json.get("path_id", uuid4())),
                source_id=source_id,
                target_id=target_id,
                steps=steps,
                risk_score=risk,
                severity=sev,
                mitre_techniques=[str(v) for v in path_json.get("mitre_techniques", []) if isinstance(v, str)],
                blocked_by_policy=bool(path_json.get("blocked_by_policy", False)),
            )
            paths.append(p)
            referenced_nodes.add(source_id)
            referenced_nodes.add(target_id)
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        nodes: list[AssetNode] = [
            AssetNode(id=node_id, type="data", name=node_id, properties={"namespace": namespace}) for node_id in sorted(referenced_nodes)
        ]
        log.info(
            "nrvq.api.attack_paths.served",
            namespace=namespace,
            path_count=len(paths),
            node_count=len(nodes),
            code="NRVQ-API-7051",
        )
        return AttackPathsResponse(paths=paths[:100], nodes=nodes)
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        log.error(
            "nrvq.api.attack_paths.error",
            error=str(exc),
            error_type=type(exc).__name__,
            traceback=tb,
            code="NRVQ-API-7051-ERR",
        )
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")
