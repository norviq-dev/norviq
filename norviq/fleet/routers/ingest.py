# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Relay-facing fleet ingest: heartbeat + rollup upserts. Requires a service/admin token whose
cluster scope matches the path cluster_id (a relay can only write its OWN cluster's data)."""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin_or_service, scoped_cluster
from norviq.fleet.db import fleet_get_session
from norviq.fleet.models import AgentRollup, AuditRollup, Cluster
from norviq.fleet.schemas import HeartbeatBody, RollupBody

log = structlog.get_logger()
router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/fleet/clusters/{cluster_id}/heartbeat")
async def heartbeat(
    cluster_id: str,
    body: HeartbeatBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Register/refresh a cluster (upsert by id, bump last_heartbeat)."""
    require_admin_or_service(user)
    scoped_cluster(user, cluster_id)
    now = _utcnow()
    # S3: bind the cluster to its attested SPIFFE identity (defense-in-depth atop the bearer). Warn on a
    # change of a previously-bound SVID — the bearer remains the authoritative transport auth.
    existing = (await session.execute(select(Cluster).where(Cluster.id == cluster_id))).scalar_one_or_none()
    if existing is not None and existing.spiffe_id and body.spiffe_id and existing.spiffe_id != body.spiffe_id:
        log.warning("nrvq.fleet.spiffe_id_changed", cluster_id=cluster_id, old=existing.spiffe_id,
                    new=body.spiffe_id, code="NRVQ-FLT-15024")
    stmt = insert(Cluster).values(
        id=cluster_id, name=body.name, endpoint=body.endpoint, console_url=body.console_url, region=body.region,
        labels=body.labels, residency=body.residency, spiffe_id=body.spiffe_id, status="healthy", last_heartbeat=now,
    ).on_conflict_do_update(
        index_elements=["id"],
        set_={"name": body.name, "endpoint": body.endpoint, "console_url": body.console_url, "region": body.region,
               "labels": body.labels, "residency": body.residency, "spiffe_id": body.spiffe_id,
               "status": "healthy", "last_heartbeat": now},
    )
    await session.execute(stmt)
    await session.commit()
    log.info("nrvq.fleet.heartbeat", cluster_id=cluster_id, code="NRVQ-FLT-15002")
    return {"cluster_id": cluster_id, "last_heartbeat": now.isoformat(), "status": "healthy"}


@router.post("/fleet/clusters/{cluster_id}/rollup")
async def rollup(
    cluster_id: str,
    body: RollupBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Upsert agent + audit rollups for this cluster (cluster_id from the PATH, never the body)."""
    require_admin_or_service(user)
    scoped_cluster(user, cluster_id)
    now = _utcnow()
    for a in body.agents:
        stmt = insert(AgentRollup).values(
            cluster_id=cluster_id, spiffe_id=a.spiffe_id, namespace=a.namespace, agent_class=a.agent_class,
            trust_score=a.trust_score, trust_category=a.trust_category, last_seen=a.last_seen or now, updated_at=now,
        ).on_conflict_do_update(
            index_elements=["cluster_id", "spiffe_id"],
            set_={"namespace": a.namespace, "agent_class": a.agent_class, "trust_score": a.trust_score,
                  "trust_category": a.trust_category, "last_seen": a.last_seen or now, "updated_at": now},
        )
        await session.execute(stmt)
    for r in body.audit:
        # SET-absolute (NOT increment): the relay re-sends the full count per bucket each cycle, so a
        # retried/duplicate POST converges instead of double-counting.
        stmt = insert(AuditRollup).values(
            cluster_id=cluster_id, namespace=r.namespace, bucket_ts=r.bucket_ts, decision=r.decision,
            count=r.count, updated_at=now,
        ).on_conflict_do_update(
            index_elements=["cluster_id", "namespace", "bucket_ts", "decision"],
            set_={"count": r.count, "updated_at": now},
        )
        await session.execute(stmt)
    await session.commit()
    log.info("nrvq.fleet.rollup_received", cluster_id=cluster_id, agents=len(body.agents),
             audit=len(body.audit), code="NRVQ-FLT-15003")
    return {"cluster_id": cluster_id, "agents_upserted": len(body.agents), "audit_upserted": len(body.audit)}
