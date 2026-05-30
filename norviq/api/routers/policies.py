# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy CRUD routes."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from norviq.api.auth import get_current_user

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
