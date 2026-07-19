# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Console-facing fleet reads: cluster list + status, aggregated agents, audit summaries, trust
distribution. Every read is cluster-scoped — a caller only sees clusters their token is scoped to."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import delete as sql_delete
from sqlalchemy import update as sql_update
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_admin_or_service, scoped_cluster
from norviq.config import settings
from norviq.fleet.db import fleet_get_session
from norviq.fleet.join_token import derive_bundle_pubkey, mint_join_token
from norviq.fleet.models import AgentRollup, AuditRollup, Cluster, PolicyRollout, UsedJoinToken
from norviq.fleet.ssrf_guard import SSRFBlockedError, assert_safe_url_async

log = structlog.get_logger()
router = APIRouter()


class JoinTokenBody(BaseModel):
    """Mint a join token for a NEW spoke (single-cluster-first enrollment)."""

    cluster_id: str
    hub_url: str = ""          # the externally-reachable hub URL the spoke will pull from (defaults to fleet_api_url)
    name: str = ""
    region: str = ""
    labels: dict = {}
    ttl_s: int = 600


class ClaimBody(BaseModel):
    """A spoke claims its join token (single-use) during enrollment."""

    jti: str
    cluster_id: str

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
            "console_url": c.console_url,  # drives the hub console's "open <cluster>'s console" deep-link
            "last_heartbeat": c.last_heartbeat.isoformat() if c.last_heartbeat else None,
            "status": "healthy" if age <= settings.fleet_stale_after_s else "stale",
        })
    log.debug("nrvq.fleet.clusters_listed", count=len(out), code="NRVQ-FLT-15004")
    return out


@router.post("/fleet/clusters/join-token")
async def mint_cluster_join_token(
    body: JoinTokenBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Single-cluster-first enrollment: MINT a short-lived, scoped, single-use join token for a new spoke. Admin
    only. The token carries the hub endpoint + cluster_id + the bundle PUBLIC key (trust root) — the spoke runs one
    `norviq fleet join <token>`, no per-spoke Helm wiring. The private signing key never leaves the hub."""
    require_admin(user)
    if not settings.fleet_signing_key:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="hub signing key not configured")
    pubkey = derive_bundle_pubkey(settings.fleet_signing_key)
    hub_url = body.hub_url or settings.fleet_api_url
    if not hub_url:
        raise HTTPException(status_code=400, detail="hub_url required (the spoke-reachable hub endpoint)")
    # SSRF-01: hub_url is embedded (signed) into the join token and later DIALED by the enrolling
    # spoke (norviq/api/routers/fleet_enroll.py::fleet_join) with the spoke's own service bearer
    # attached, and persisted as the ongoing relay/puller target. Guard it here, before it is ever
    # minted into a token or written to the join-token row, not just when the spoke dials it.
    try:
        await assert_safe_url_async(hub_url, context="fleet join-token hub_url")
    except SSRFBlockedError as exc:
        raise HTTPException(status_code=400, detail=f"hub_url failed the SSRF safety check: {exc}") from exc
    token, payload = mint_join_token(
        secret=settings.api_secret_key, hub_url=hub_url, cluster_id=body.cluster_id, bundle_pubkey=pubkey,
        ttl_s=body.ttl_s, cluster_name=body.name, cluster_region=body.region, labels=body.labels,
    )
    session.add(UsedJoinToken(
        jti=payload["jti"], cluster_id=body.cluster_id,
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc), claimed=False,
    ))
    await session.commit()
    log.info("nrvq.fleet.join_token_minted", cluster_id=body.cluster_id, jti=payload["jti"],
             actor=user.get("sub"), code="NRVQ-FLT-15030")
    return {
        "cluster_id": body.cluster_id, "token": token,
        "join_command": f"norviq fleet join {token}",
        "expires_at": datetime.fromtimestamp(payload["exp"], tz=timezone.utc).isoformat(),
    }


@router.post("/fleet/clusters/join-token/claim")
async def claim_join_token(
    body: ClaimBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Single-use guard: a spoke claims its jti during enrollment. Rejects an unknown/expired/already-claimed jti
    or a cluster_id mismatch (so a leaked token can't be redeemed twice or for another cluster)."""
    require_admin_or_service(user)
    row = (await session.execute(select(UsedJoinToken).where(UsedJoinToken.jti == body.jti))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown join token")
    if row.cluster_id != body.cluster_id:
        raise HTTPException(status_code=403, detail="join token is not scoped to this cluster")
    if row.expires_at and row.expires_at < now:
        raise HTTPException(status_code=410, detail="join token expired")
    # Single-use is enforced by an ATOMIC conditional UPDATE (WHERE claimed=false) — not a check-then-set — so
    # two concurrent claims of the same jti can never both succeed (the DB row-locks; exactly one flips claimed).
    result = await session.execute(
        sql_update(UsedJoinToken)
        .where(UsedJoinToken.jti == body.jti, UsedJoinToken.claimed.is_(False))
        .values(claimed=True, claimed_at=now)
    )
    await session.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=409, detail="join token already used")
    log.info("nrvq.fleet.join_token_claimed", cluster_id=body.cluster_id, jti=body.jti, code="NRVQ-FLT-15031")
    return {"ok": True, "cluster_id": body.cluster_id}


@router.delete("/fleet/clusters/{cluster_id}")
async def remove_cluster(
    cluster_id: str,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """REMOVE/deregister a cluster from the hub (admin). Deletes the cluster + its rollups/rollout, so it drops out
    of the fleet table and its bundle endpoint 404s. The spoke's `norviq fleet leave` stops it pulling + sheds the
    pushed policy (reusing the retract/reconcile machinery)."""
    require_admin(user)
    row = (await session.execute(select(Cluster).where(Cluster.id == cluster_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"cluster '{cluster_id}' not registered")
    # Also delete the cluster's join-token rows (UsedJoinToken) — otherwise removing a cluster leaves stale
    # single-use records behind (unbounded growth + confusing audit). Cluster/rollups/rollout as before.
    for model in (AgentRollup, AuditRollup, PolicyRollout, UsedJoinToken):
        await session.execute(sql_delete(model).where(model.cluster_id == cluster_id))
    await session.execute(sql_delete(Cluster).where(Cluster.id == cluster_id))
    await session.commit()
    log.info("nrvq.fleet.cluster_removed", cluster_id=cluster_id, actor=user.get("sub"), code="NRVQ-FLT-15032")
    return {"removed": cluster_id}


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
