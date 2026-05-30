# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Health and readiness routes."""

from fastapi import APIRouter, Request
from sqlalchemy import text

from norviq.api.db.session import get_session

router = APIRouter()


@router.get("/healthz")
async def health() -> dict:
    """Return process liveness."""
    return {"status": "ok"}


@router.get("/readyz")
async def ready(request: Request) -> dict:
    """Check Redis and DB readiness."""
    redis_ok = bool(getattr(request.app.state, "cache", None) and getattr(request.app.state.cache, "_redis", None))
    db_ok = True
    session = None
    try:
        session = await get_session()
        await session.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    finally:
        if session is not None:
            await session.close()
    return {"status": "ready", "redis": redis_ok, "db": db_ok}
