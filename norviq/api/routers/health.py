# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Health and readiness routes."""

import structlog
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.db.session import get_session
from norviq.config import settings

log = structlog.get_logger()
router = APIRouter()


@router.get("/healthz")
async def health() -> dict:
    """Liveness: process is up. Lenient by design — a transient dependency outage must NOT kill the
    pod (the readiness probe drains traffic instead), so the API never CrashLoops on a dep blip."""
    return {"status": "ok"}


@router.get("/readyz")
async def ready(request: Request, response: Response, session: AsyncSession = Depends(get_session)) -> dict:
    """Readiness: actively probe the hard dependencies and return **503** if any is unreachable, so a
    Postgres/Redis/OPA restart flips the pod NotReady (drains traffic) and back to Ready once they
    recover — no manual restart. The DB probe also recycles a dead pooled connection (pool_pre_ping)."""
    db_ok = True
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    redis_ok = False
    cache = getattr(request.app.state, "cache", None)
    if cache is not None and getattr(cache, "_redis", None) is not None:
        try:
            redis_ok = bool(await cache._client().ping())
        except Exception:
            redis_ok = False

    # HA-CRITICAL: a scaled-up / freshly-restarted pod must NOT take traffic until its policy cache is
    # WARM — otherwise it would evaluate the first tool calls against an empty policy set (a wrong/deny-all
    # decision) during the load window. Gate readiness on the loader's warm flag so the Service only routes
    # to pods that can enforce correctly. (warm_cache sets _warmed True at the end of startup.)
    loader = getattr(request.app.state, "loader", None)
    warmed = bool(getattr(loader, "_warmed", False)) if loader is not None else True
    payload = {"status": "ready", "redis": redis_ok, "db": db_ok, "policies_warm": warmed}
    healthy = db_ok and redis_ok and warmed
    if settings.opa_mode == "server":
        evaluator = getattr(request.app.state, "evaluator", None)
        opa_ok = bool(evaluator and await evaluator.opa.health())
        payload["opa"] = opa_ok
        healthy = healthy and opa_ok

    if not healthy:
        payload["status"] = "not-ready"
        log.warning("nrvq.api.not_ready", **{k: v for k, v in payload.items() if k != "status"}, code="NRVQ-API-7002")
        return JSONResponse(status_code=503, content=payload)
    return payload
