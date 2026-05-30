# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from norviq.api.auth import get_current_user
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()
router = APIRouter()


class TrustUpdate(BaseModel):
    """Manual trust update payload."""

    score: float = Field(ge=0.0, le=1.0)


@router.get("/agents")
async def list_agents(request: Request) -> list[dict]:
    """List all agents with trust scores in cache."""
    cache = request.app.state.cache
    rows = []
    async for key in cache._client().scan_iter("trust:*"):
        spiffe_id = str(key).replace("trust:", "", 1)
        trust = await cache.get_trust(spiffe_id)
        if trust:
            rows.append(
                {
                    "spiffe_id": spiffe_id,
                    "score": trust.score,
                    "category": trust.category,
                    "violation_count": trust.violation_count,
                }
            )
    log.debug("nrvq.api.agents.listed", count=len(rows), code="NRVQ-API-7030")
    return rows


@router.get("/agents/{spiffe_id:path}")
async def get_agent(spiffe_id: str, request: Request) -> dict:
    """Get one agent trust score."""
    trust = await request.app.state.cache.get_trust(spiffe_id)
    if trust is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"spiffe_id": spiffe_id, "score": trust.score, "category": trust.category, "violation_count": trust.violation_count}


@router.put("/agents/{spiffe_id:path}/trust")
async def update_trust(
    spiffe_id: str, body: TrustUpdate, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Set an agent trust score manually."""
    _ = user
    trust = TrustScore(score=body.score)
    await request.app.state.cache.set_trust(spiffe_id, trust)
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": trust.score, "category": trust.category}
