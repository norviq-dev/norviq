# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet hub control-plane app. A SEPARATE FastAPI app over the dedicated fleet store; reuses
the spoke's token validation (norviq.api.auth) but never imports the spoke DB. Read-only: cluster
registry + heartbeat + agent/audit rollups + aggregated reads. Started as its own pod from the SAME
api image with command `uvicorn norviq.fleet.main:app`."""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

if sys.platform == "win32":  # pragma: no cover
    import asyncio

    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from norviq.config import settings
from norviq.fleet.db import fleet_close_db, fleet_create_tables, fleet_init_db
from norviq.fleet.routers import fleet, fleet_policy, health, ingest

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Fleet startup/shutdown: own DB only (no OPA/cache/SIEM)."""
    # Same weak-secret guard as the spoke: a forgeable HS256 token must not be mintable against the hub.
    secret = settings.api_secret_key or ""
    if (secret == "change-me-in-production" or len(secret) < 16):
        log.warning("nrvq.fleet.insecure_default_secret", code="NRVQ-FLT-15013")
        if settings.require_strong_secret:
            raise RuntimeError("Refusing to start fleet-api: api_secret_key is weak (default/empty/<16 chars).")
    await fleet_init_db()
    await fleet_create_tables()
    log.info("nrvq.fleet.started", code="NRVQ-FLT-15011")
    yield
    await fleet_close_db()
    log.info("nrvq.fleet.stopped", code="NRVQ-FLT-15014")


def create_fleet_app() -> FastAPI:
    """Create the fleet hub FastAPI app."""
    app = FastAPI(title="Norviq Fleet API", version="0.1.0",
                  description="Multi-cluster fleet control plane (read-only)", lifespan=lifespan)
    app.include_router(health.router)
    app.include_router(ingest.router, prefix="/api/v1", tags=["fleet-ingest"])
    app.include_router(fleet.router, prefix="/api/v1", tags=["fleet"])
    app.include_router(fleet_policy.router, prefix="/api/v1", tags=["fleet-policy"])
    return app


app = create_fleet_app()
