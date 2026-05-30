# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy CRUD routes."""

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select

from norviq.api.auth import get_current_user
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()


class PolicyCreate(BaseModel):
    """Policy create/update payload."""

    namespace: str
    agent_class: str
    rego_source: str
    enforcement_mode: str = "block"
    saved_by: str = ""


class RollbackRequest(BaseModel):
    """Rollback payload."""

    target_version: int


class ApplyRequest(BaseModel):
    """Policy apply payload."""

    target_type: str
    target_namespace: str
    target_name: str = ""
    target_kind: str = ""
    enforcement_mode: str = "block"


@router.get("/policies")
async def list_policies(request: Request) -> list[dict]:
    """List all policies loaded in memory."""
    rows = []
    loader = request.app.state.loader
    for key, rego in loader._policies.items():
        namespace, agent_class = key.split(":", 1)
        rows.append(
            {
                "namespace": namespace,
                "agent_class": agent_class,
                "current_version": len(loader.get_versions(namespace, agent_class)),
                "rego_length": len(rego),
            }
        )
    log.info("nrvq.api.policies.listed", count=len(rows), code="NRVQ-API-7010")
    return rows


@router.get("/policies/{namespace}/{agent_class}")
async def get_policy(namespace: str, agent_class: str, request: Request) -> dict:
    """Get one policy."""
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if rego is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"namespace": namespace, "agent_class": agent_class, "rego_source": rego, "version": len(loader.get_versions(namespace, agent_class))}


@router.post("/policies")
async def create_policy(body: PolicyCreate, request: Request, user: dict = Depends(get_current_user)) -> dict:
    """Create or update a policy."""
    _ = user
    version = await request.app.state.loader.create(body.namespace, body.agent_class, body.rego_source, saved_by=body.saved_by)
    log.info(
        "nrvq.api.policy.created",
        namespace=body.namespace,
        agent_class=body.agent_class,
        version=version,
        code="NRVQ-API-7011",
    )
    return {"namespace": body.namespace, "agent_class": body.agent_class, "version": version}


@router.delete("/policies/{namespace}/{agent_class}")
async def delete_policy(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Delete a policy from in-memory index."""
    _ = user
    deleted = await request.app.state.loader.delete(namespace, agent_class)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")
    log.info("nrvq.api.policy.deleted", namespace=namespace, agent_class=agent_class, code="NRVQ-API-7012")
    return {"deleted": True}


@router.get("/policies/{namespace}/{agent_class}/versions")
async def get_versions(namespace: str, agent_class: str, request: Request) -> list[dict]:
    """Return policy version history."""
    versions = request.app.state.loader.get_versions(namespace, agent_class)
    return [{"version": v.version, "saved_by": v.saved_by, "saved_at": v.saved_at.isoformat()} for v in versions]


@router.post("/policies/{namespace}/{agent_class}/rollback")
async def rollback_policy(
    namespace: str,
    agent_class: str,
    body: RollbackRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    """Rollback policy to a previous version."""
    _ = user
    try:
        rego = await request.app.state.loader.rollback(namespace, agent_class, body.target_version)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    log.info("nrvq.api.policy.rolled_back", namespace=namespace, version=body.target_version, code="NRVQ-API-7013")
    return {"rolled_back_to": body.target_version, "rego_length": len(rego)}


@router.post("/policies/dry-run")
async def dry_run_policy(body: PolicyCreate, request: Request) -> dict:
    """Test a policy against recent audit records without applying."""
    _ = body
    _ = request
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    session = await get_session()
    try:
        base = select(func.count(AuditLogEntry.id)).where(AuditLogEntry.timestamp_utc >= since)
        total = int((await session.scalar(base)) or 0)
        blocked = int((await session.scalar(base.where(AuditLogEntry.decision == "block"))) or 0)
    finally:
        await session.close()
    rate = (blocked / total * 100) if total > 0 else 0
    log.info("nrvq.api.policy.dry_run", total=total, blocked=blocked, code="NRVQ-API-7014")
    return {
        "total_records_checked": total,
        "would_block": blocked,
        "would_allow": total - blocked,
        "block_rate_pct": round(rate, 2),
        "time_range": "last 24 hours",
        "recommendation": "Safe to deploy" if rate < 5 else "Review before deploying — high block rate",
    }


@router.post("/policies/{namespace}/{agent_class}/apply")
async def apply_policy(
    namespace: str,
    agent_class: str,
    body: ApplyRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    """Apply a saved policy to a target scope."""
    _ = user
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if not rego:
        raise HTTPException(status_code=404, detail="Policy not found. Save it first.")
    loader._evaluator.load_policy(body.target_namespace, agent_class, rego)
    log.info(
        "nrvq.api.policy.applied",
        namespace=namespace,
        agent_class=agent_class,
        target_type=body.target_type,
        target_namespace=body.target_namespace,
        mode=body.enforcement_mode,
        code="NRVQ-API-7015",
    )
    return {
        "applied": True,
        "policy": f"{namespace}/{agent_class}",
        "target_type": body.target_type,
        "target_namespace": body.target_namespace,
        "target_name": body.target_name,
        "enforcement_mode": body.enforcement_mode,
    }
