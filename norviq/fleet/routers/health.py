# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet hub health/readiness (probes the fleet store)."""

import structlog
from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.fleet.db import fleet_get_session

log = structlog.get_logger()
router = APIRouter()


@router.get("/healthz")
async def health() -> dict:
    """Liveness: process up."""
    return {"status": "ok"}


@router.get("/readyz")
async def ready(response: Response, session: AsyncSession = Depends(fleet_get_session)) -> dict:
    """Readiness: 503 if the fleet store is unreachable (drains traffic, never CrashLoops)."""
    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:
        log.warning("nrvq.fleet.not_ready", error=str(exc), code="NRVQ-FLT-15012")
        return JSONResponse(status_code=503, content={"status": "not-ready", "db": False})
    return {"status": "ready", "db": True}
