# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Console-facing fleet reads: cluster list + status, aggregated agents, audit summaries, trust
distribution. Every read is cluster-scoped — a caller only sees clusters their token is scoped to."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, scoped_cluster
from norviq.config import settings
from norviq.fleet.db import fleet_get_session
from norviq.fleet.models import AgentRollup, AuditRollup, Cluster

log = structlog.get_logger()
router = APIRouter()

_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}


def _allowed_clusters(user: dict) -> str | None:
    """Resolve the caller's cluster scope: None = all clusters (admin/"*"), else a single cluster id."""
    cluster = scoped_cluster(user, None)
    return None if cluster in (None, "", "*") else cluster


@router.get("/fleet/clusters")
async def list_clusters(
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List clusters the caller may see, with a computed healthy/stale status."""
    only = _allowed_clusters(user)
    stmt = select(Cluster)
    if only is not None:
        stmt = stmt.where(Cluster.id == only)
    rows = (await session.execute(stmt)).scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for c in rows:
        age = (now - c.last_heartbeat).total_seconds() if c.last_heartbeat else 1e9
        out.append({
            "id": c.id, "name": c.name, "region": c.region, "endpoint": c.endpoint,
            "last_heartbeat": c.last_heartbeat.isoformat() if c.last_heartbeat else None,
            "status": "healthy" if age <= settings.fleet_stale_after_s else "stale",
        })
    log.debug("nrvq.fleet.clusters_listed", count=len(out), code="NRVQ-FLT-15004")
    return out


@router.get("/fleet/agents")
async def list_agents(
    cluster: str | None = Query(default=None),
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Aggregated agent rollups across the caller's allowed cluster(s)."""
    cluster = scoped_cluster(user, cluster)
    stmt = select(AgentRollup)
    if cluster not in (None, "", "*"):
        stmt = stmt.where(AgentRollup.cluster_id == cluster)
    rows = (await session.execute(stmt)).scalars().all()
    return [{
        "cluster_id": a.cluster_id, "spiffe_id": a.spiffe_id, "namespace": a.namespace,
        "agent_class": a.agent_class, "trust_score": a.trust_score, "trust_category": a.trust_category,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
    } for a in rows]


@router.get("/fleet/audit/summary")
async def audit_summary(
    cluster: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Per-cluster audit decision counts over a time range (summed from audit_rollup)."""
    cluster = scoped_cluster(user, cluster)
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range, 24))
    stmt = (
        select(AuditRollup.cluster_id, AuditRollup.decision, func.sum(AuditRollup.count).label("count"))
        .where(AuditRollup.bucket_ts >= since)
        .group_by(AuditRollup.cluster_id, AuditRollup.decision)
    )
    if cluster not in (None, "", "*"):
        stmt = stmt.where(AuditRollup.cluster_id == cluster)
    rows = (await session.execute(stmt)).all()
    by_cluster: dict[str, dict] = {}
    for cid, decision, count in rows:
        entry = by_cluster.setdefault(cid, {"cluster_id": cid, "allow": 0, "block": 0, "escalate": 0, "audit": 0, "total": 0})
        entry[decision] = entry.get(decision, 0) + int(count)
        entry["total"] += int(count)
    log.debug("nrvq.fleet.audit_summary", clusters=len(by_cluster), code="NRVQ-FLT-15005")
    return list(by_cluster.values())


@router.get("/fleet/trust/distribution")
async def trust_distribution(
    cluster: str | None = Query(default=None),
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Per-cluster agent counts by trust category."""
    cluster = scoped_cluster(user, cluster)
    stmt = (
        select(AgentRollup.cluster_id, AgentRollup.trust_category, func.count().label("count"))
        .group_by(AgentRollup.cluster_id, AgentRollup.trust_category)
    )
    if cluster not in (None, "", "*"):
        stmt = stmt.where(AgentRollup.cluster_id == cluster)
    rows = (await session.execute(stmt)).all()
    by_cluster: dict[str, dict] = {}
    for cid, category, count in rows:
        entry = by_cluster.setdefault(cid, {"cluster_id": cid, "total": 0})
        entry[category] = entry.get(category, 0) + int(count)
        entry["total"] += int(count)
    return list(by_cluster.values())
