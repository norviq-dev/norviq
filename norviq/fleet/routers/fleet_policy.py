# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Hub fleet policy distribution (F045 P2): author policies (admin), build+sign a per-cluster bundle for
the relay to pull, and track per-cluster rollout state. Authoring is admin-only — the source of allow/deny
rules is privileged; the spoke/relay only PULLS (it never authors)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from jose import jwt
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_admin_or_service, scoped_cluster
from norviq.config import settings
from norviq.fleet.bundle import rfc3339_z, sign_bundle
from norviq.fleet.db import fleet_get_session
from norviq.fleet.models import Cluster, FleetPolicy, PolicyRollout
from norviq.fleet.schemas import PolicyAuthorBody, RolloutReportBody

log = structlog.get_logger()
router = APIRouter()

# F-40: scopes a fleet push must NEVER replace — a cluster's baseline (comprehensive) and its materialized sector
# pack are managed PER-CLUSTER (the seed / packs-enable path), not by fleet distribution. A push that targeted
# __baseline__ once wiped comprehensive across all three prod clusters.
_RESERVED_SCOPES = {"__baseline__", "__pack__"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/fleet/policies")
async def author_policy(
    body: PolicyAuthorBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Create/update a fleet policy (admin only). Re-authoring the same name bumps its version."""
    require_admin(user)  # authoring allow/deny rules is admin-only (service/viewer -> 403)
    # F-40 (1): a fleet push must not replace a managed per-cluster scope (baseline/pack) fleet-wide.
    if body.agent_class in _RESERVED_SCOPES:
        log.warning("nrvq.fleet.policy.reserved_scope", name=body.name, agent_class=body.agent_class,
                    actor=user.get("sub"), code="NRVQ-FLT-15023")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"'{body.agent_class}' is a managed per-cluster scope and cannot be fleet-pushed — change a "
                   "cluster's baseline via its seed and sector packs via the packs API (POST /policy-packs/{id}/enable).",
        )
    # F-40 (2): a fleet-WIDE push (no cluster_id -> matches >1 cluster) needs an explicit confirm.
    if not body.target_selector.get("cluster_id") and not body.confirm_fleet_wide:
        log.warning("nrvq.fleet.policy.confirm_required", name=body.name, selector=body.target_selector,
                    actor=user.get("sub"), code="NRVQ-FLT-15027")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="fleet-wide push (no cluster_id in target_selector — matches more than one cluster) requires "
                   "confirm_fleet_wide=true.",
        )
    # If the policy targets a specific cluster (override), enforce cluster scope on that target.
    if body.target_selector.get("cluster_id"):
        scoped_cluster(user, body.target_selector["cluster_id"])
    existing = (await session.execute(select(FleetPolicy).where(FleetPolicy.name == body.name))).scalar_one_or_none()
    version = (existing.version + 1) if existing else 1
    now = _utcnow()
    stmt = insert(FleetPolicy).values(
        name=body.name, namespace=body.namespace, agent_class=body.agent_class, rego_source=body.rego_source,
        priority=body.priority, enforcement_mode=body.enforcement_mode, target_selector=body.target_selector,
        version=version, created_at=now, updated_at=now,
    ).on_conflict_do_update(
        index_elements=["name"],
        set_={"namespace": body.namespace, "agent_class": body.agent_class, "rego_source": body.rego_source,
               "priority": body.priority, "enforcement_mode": body.enforcement_mode,
               "target_selector": body.target_selector, "version": version, "updated_at": now},
    )
    await session.execute(stmt)
    await session.commit()
    log.info("nrvq.fleet.policy_authored", name=body.name, version=version, actor=user.get("sub"),
             code="NRVQ-FLT-15021")
    return {"name": body.name, "version": version}


def _resolve_for_cluster(policies: list[FleetPolicy], cluster: Cluster) -> list[dict]:
    """Selector match (target_selector subset of cluster.labels) + per-cluster override precedence."""
    labels = cluster.labels or {}
    chosen: dict[tuple[str, str], tuple[bool, FleetPolicy]] = {}  # (ns,class) -> (is_override, policy)
    for p in policies:
        # F-40 defense-in-depth: a reserved-scope policy already in the DB (e.g. a pre-guard or neutralized row)
        # must never be distributed in a bundle — baseline/pack are per-cluster managed, never fleet-pushed.
        if p.agent_class in _RESERVED_SCOPES:
            continue
        sel = p.target_selector or {}
        is_override = sel.get("cluster_id") == cluster.id
        if is_override:
            matched = True
        elif "cluster_id" in sel:
            continue  # an override for a DIFFERENT cluster
        else:
            matched = all(labels.get(k) == v for k, v in sel.items())  # {} selector matches all
        if not matched:
            continue
        key = (p.namespace, p.agent_class)
        prev = chosen.get(key)
        if prev is None or (is_override and not prev[0]):  # override replaces a selector-matched policy
            chosen[key] = (is_override, p)
    out = [{
        "namespace": p.namespace, "agent_class": p.agent_class, "rego_source": p.rego_source,
        "priority": p.priority, "enforcement_mode": p.enforcement_mode, "version": p.version,
    } for _, p in chosen.values()]
    return sorted(out, key=lambda d: (d["namespace"], d["agent_class"]))


@router.get("/fleet/clusters/{cluster_id}/bundle")
async def get_bundle(
    cluster_id: str,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Build + SIGN the per-cluster desired-state bundle (relay pulls this). Bump-on-change version."""
    require_admin_or_service(user)
    scoped_cluster(user, cluster_id)
    if not settings.fleet_signing_key:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="fleet signing key not configured")
    cluster = (await session.execute(select(Cluster).where(Cluster.id == cluster_id))).scalar_one_or_none()
    if cluster is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="cluster not registered")
    policies = list((await session.execute(select(FleetPolicy))).scalars().all())
    resolved = _resolve_for_cluster(policies, cluster)
    # bump-on-change: version is stable while the resolved set is unchanged (so re-pull no-ops on the spoke).
    digest = hashlib.sha256(repr(resolved).encode()).hexdigest()
    rollout = (await session.execute(select(PolicyRollout).where(PolicyRollout.cluster_id == cluster_id))).scalar_one_or_none()
    version = cluster.bundle_version
    if rollout is None or rollout.detail != digest or version == 0:
        version = cluster.bundle_version + 1
        cluster.bundle_version = version
        now = _utcnow()
        await session.execute(insert(PolicyRollout).values(
            cluster_id=cluster_id, policy_bundle_version=version, state="pending", detail=digest, updated_at=now,
        ).on_conflict_do_update(
            index_elements=["cluster_id"],
            set_={"policy_bundle_version": version, "state": "pending", "detail": digest, "updated_at": now},
        ))
        await session.commit()
    now = _utcnow()
    payload = {
        "cluster_id": cluster_id,
        "bundle_version": version,
        "issued_at": rfc3339_z(now),
        "not_before": rfc3339_z(now),
        "expires_at": rfc3339_z(now + timedelta(seconds=settings.fleet_bundle_ttl_s)),
        "prev_bundle_version": version - 1,
        "policies": resolved,
    }
    body = sign_bundle(payload, settings.fleet_signing_key)
    log.info("nrvq.fleet.bundle_signed", cluster_id=cluster_id, version=version, policies=len(resolved),
             code="NRVQ-FLT-15015")
    return body


@router.post("/fleet/clusters/{cluster_id}/rollout")
async def report_rollout(
    cluster_id: str,
    body: RolloutReportBody,
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Spoke reports the apply outcome; drives the pending->applied/failed + diverged state machine."""
    require_admin_or_service(user)
    scoped_cluster(user, cluster_id)
    rollout = (await session.execute(select(PolicyRollout).where(PolicyRollout.cluster_id == cluster_id))).scalar_one_or_none()
    expected = rollout.policy_bundle_version if rollout else body.bundle_version
    if body.state == "applied":
        state = "applied" if body.applied_version == expected else "diverged"
    else:
        state = "failed"
    now = _utcnow()
    await session.execute(insert(PolicyRollout).values(
        cluster_id=cluster_id, policy_bundle_version=expected, state=state,
        applied_version=body.applied_version, detail=body.detail, updated_at=now,
    ).on_conflict_do_update(
        index_elements=["cluster_id"],
        set_={"state": state, "applied_version": body.applied_version, "detail": body.detail, "updated_at": now},
    ))
    await session.commit()
    log.info("nrvq.fleet.rollout_reported", cluster_id=cluster_id, state=state,
             applied_version=body.applied_version, code="NRVQ-FLT-15020")
    return {"cluster_id": cluster_id, "state": state}


@router.get("/fleet/clusters/{cluster_id}/audit/records")
async def drilldown(
    cluster_id: str,
    range: str = Query(default="24h"),
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """P3 drill-down: live-query ONE cluster's raw audit (Option-B). P4 residency BLOCKS it (raw logs
    never leave). The hot aggregate path stays on the hub rollups; this is on-demand only."""
    scoped_cluster(user, cluster_id)
    cluster = (await session.execute(select(Cluster).where(Cluster.id == cluster_id))).scalar_one_or_none()
    if cluster is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="cluster not registered")
    if cluster.residency:
        # P4: this cluster keeps raw logs in-cluster -> the hub must NOT pull them.
        log.info("nrvq.fleet.drilldown_residency_blocked", cluster_id=cluster_id, code="NRVQ-FLT-15026")
        return {"cluster_id": cluster_id, "records": [], "residency_blocked": True}
    if not cluster.endpoint:
        return {"cluster_id": cluster_id, "records": [], "error": "no endpoint registered"}
    # Mint a short-lived service token to query the spoke's audit API (shared-secret in the local POC;
    # per-cluster drill-down credentials are a prod follow-up).
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": "fleet-drilldown", "role": "admin", "cluster": cluster_id,
                        "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=2)).timestamp())},
                       settings.api_secret_key, algorithm="HS256")
    url = cluster.endpoint.rstrip("/") + f"/api/v1/audit/records?range={range}&limit={limit}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            resp.raise_for_status()
            rows = resp.json()
    except Exception as exc:
        log.warning("nrvq.fleet.drilldown_failed", cluster_id=cluster_id, error=str(exc), code="NRVQ-FLT-15025")
        return {"cluster_id": cluster_id, "records": [], "error": "cluster unreachable"}
    records = [{"timestamp": r.get("timestamp"), "tool_name": r.get("tool_name"), "decision": r.get("decision"),
                "agent_class": r.get("agent_class"), "namespace": r.get("namespace"), "rule_id": r.get("rule_id")}
               for r in (rows if isinstance(rows, list) else [])]
    log.info("nrvq.fleet.drilldown_served", cluster_id=cluster_id, count=len(records), code="NRVQ-FLT-15025")
    return {"cluster_id": cluster_id, "records": records}


@router.get("/fleet/rollout")
async def list_rollout(
    session: AsyncSession = Depends(fleet_get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Per-cluster rollout status for the console (cluster-scoped)."""
    only = scoped_cluster(user, None)
    stmt = select(PolicyRollout)
    if only not in (None, "", "*"):
        stmt = stmt.where(PolicyRollout.cluster_id == only)
    rows = (await session.execute(stmt)).scalars().all()
    return [{
        "cluster_id": r.cluster_id, "bundle_version": r.policy_bundle_version, "state": r.state,
        "applied_version": r.applied_version, "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    } for r in rows]
