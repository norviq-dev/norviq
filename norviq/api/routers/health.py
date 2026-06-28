# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Health and readiness routes."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.db.session import get_session
from norviq.config import settings

router = APIRouter()


@router.get("/healthz")
async def health() -> dict:
    """Return process liveness."""
    return {"status": "ok"}


@router.get("/readyz")
async def ready(request: Request, session: AsyncSession = Depends(get_session)) -> dict:
    """Check Redis and DB readiness."""
    redis_ok = bool(getattr(request.app.state, "cache", None) and getattr(request.app.state.cache, "_redis", None))
    db_ok = True
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    payload = {"status": "ready", "redis": redis_ok, "db": db_ok}
    if settings.opa_mode == "server":
        # In server mode the evaluator depends on a reachable OPA; surface it in readiness.
        evaluator = getattr(request.app.state, "evaluator", None)
        payload["opa"] = bool(evaluator and await evaluator.opa.health())
    return payload
