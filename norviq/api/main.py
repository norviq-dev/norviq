# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI application entrypoint for Norviq."""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from norviq.api.db.session import close_db, create_tables, get_session, init_db
from norviq.api.routers import agents, audit, evaluate, graph, health, policies, redteam
from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.store import GraphStore
from norviq.engine.policy_loader import PolicyLoader
from norviq.telemetry.exporter import mount_metrics_endpoint
from norviq.telemetry.middleware import TelemetryMiddleware
from norviq.telemetry.provider import setup_telemetry, shutdown_telemetry

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run API startup and shutdown lifecycle."""
    setup_telemetry()
    await init_db()
    await create_tables()
    app.state.cache = RedisCache()
    await app.state.cache.connect()
    app.state.evaluator = OPAEvaluator(app.state.cache)
    app.state.graph_store = GraphStore(app.state.cache, session_factory=get_session)
    app.state.evaluator.bind_graph_store(app.state.graph_store)
    app.state.emitter = AuditEmitter()
    await app.state.emitter.init()
    app.state.loader = PolicyLoader(app.state.cache, app.state.evaluator)
    app.state.evaluator.bind_loader(app.state.loader)
    log.info("nrvq.api.started", port=settings.api_port, code="NRVQ-API-7000")
    yield
    await app.state.emitter.close()
    await app.state.cache.close()
    await close_db()
    shutdown_telemetry()
    log.info("nrvq.api.stopped", code="NRVQ-API-7001")


def create_app() -> FastAPI:
    """Create the Norviq FastAPI app."""
    app = FastAPI(
        title="Norviq API",
        version="0.1.0",
        description="Runtime security for LLM agent tool calls",
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(evaluate.router, prefix="/api/v1", tags=["evaluate"])
    app.include_router(policies.router, prefix="/api/v1", tags=["policies"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(agents.router, prefix="/api/v1", tags=["agents"])
    app.include_router(graph.router, prefix="/api/v1")
    app.include_router(redteam.router, prefix="/api/v1", tags=["redteam"])
    app.add_middleware(TelemetryMiddleware)
    mount_metrics_endpoint(app)
    return app


app = create_app()
