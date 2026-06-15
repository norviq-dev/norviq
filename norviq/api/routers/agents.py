# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import json

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from norviq.api.auth import get_current_user, require_admin
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()
router = APIRouter()


def _namespace_from_spiffe(spiffe_id: str) -> str | None:
    """Extract the namespace from spiffe://.../ns/{namespace}/sa/... ."""
    parts = spiffe_id.split("/")
    if "ns" in parts:
        idx = parts.index("ns")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


class TrustUpdate(BaseModel):
    """Manual trust update payload."""

    score: float = Field(ge=0.0, le=1.0)


@router.get("/agents")
async def list_agents(
    request: Request,
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List agents with trust scores in cache, scoped to one namespace."""
    _ = user
    cache = request.app.state.cache
    rows = []
    async for key in cache._client().scan_iter("trust:*"):
        spiffe_id = str(key).replace("trust:", "", 1)
        if _namespace_from_spiffe(spiffe_id) != namespace:
            continue
        trust = await cache.get_trust(spiffe_id)
        if trust:
            details = await _trust_details(request, spiffe_id, trust.factors)
            rows.append(
                {
                    "spiffe_id": spiffe_id,
                    "score": trust.score,
                    "category": trust.category.lower(),
                    "violation_count": trust.violation_count,
                    "signals": details["signals"],
                    "dominant_signal": details["dominant_signal"],
                    "recommendation": details["recommendation"],
                }
            )
    log.debug("nrvq.api.agents.listed", count=len(rows), code="NRVQ-API-7030")
    return rows


@router.get("/agents/{spiffe_id:path}")
async def get_agent(spiffe_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    """Get one agent trust score."""
    _ = user
    trust = await request.app.state.cache.get_trust(spiffe_id)
    if trust is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    details = await _trust_details(request, spiffe_id, trust.factors)
    return {
        "spiffe_id": spiffe_id,
        "score": trust.score,
        "category": trust.category.lower(),
        "violation_count": trust.violation_count,
        "signals": details["signals"],
        "dominant_signal": details["dominant_signal"],
        "recommendation": details["recommendation"],
    }


@router.put("/agents/{spiffe_id:path}/trust")
async def update_trust(
    spiffe_id: str, body: TrustUpdate, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Set an agent trust score manually."""
    require_admin(user)
    if body.score == 0:
        await request.app.state.cache._client().set(f"agent_frozen:{spiffe_id}", "1")
    else:
        await request.app.state.cache._client().delete(f"agent_frozen:{spiffe_id}")
    trust = TrustScore(score=body.score, category="frozen" if body.score == 0 else "")
    await request.app.state.cache.set_trust(spiffe_id, trust)
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": trust.score, "category": trust.category.lower()}


async def _trust_details(request: Request, spiffe_id: str, factors: dict) -> dict:
    """Return latest trust signal breakdown for one agent."""
    raw = await request.app.state.cache._client().get(f"trustcalc:{spiffe_id}")
    if raw:
        payload = json.loads(raw)
        return {
            "signals": payload.get("signals", {}),
            "dominant_signal": payload.get("dominant_signal", ""),
            "recommendation": payload.get("recommendation", ""),
        }
    return {
        "signals": factors.get("signals", {}),
        "dominant_signal": factors.get("dominant_signal", ""),
        "recommendation": factors.get("recommendation", ""),
    }
