# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI application entrypoint for Norviq."""

import asyncio
from contextlib import asynccontextmanager
import sys

import structlog
from fastapi import FastAPI

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from norviq.api.db.session import close_db, create_tables, ensure_schema_compatibility, get_session, init_db
from norviq.api.routers import agents, audit, evaluate, graph, graphs, health, policies, redteam
from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.store import GraphStore
from norviq.engine.policy_loader import PolicyLoader
from norviq.telemetry.exporter import mount_metrics_endpoint
from norviq.telemetry.middleware import TelemetryMiddleware
from norviq.telemetry.provider import setup_telemetry, shutdown_telemetry
from norviq.api.db.models import Base

log = structlog.get_logger()
log.info(
    "nrvq.startup.tables_in_metadata",
    tables=list(Base.metadata.tables.keys()),
    count=len(Base.metadata.tables),
    code="NRVQ-DB-DEBUG-METADATA",
)


async def run_migrations() -> None:
    """Apply pending Alembic migrations before cache warm-up."""
    try:
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        db_url = settings.pg_url.strip().strip("\"'")
        cfg.set_main_option("sqlalchemy.url", db_url.replace("+asyncpg", ""))
        command.upgrade(cfg, "head")
        log.info("nrvq.db.migrations_applied", code="NRVQ-DB-9032")
    except Exception as exc:  # pragma: no cover - startup best-effort
        log.error("nrvq.db.migration_failed", error=str(exc), code="NRVQ-DB-9033")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run API startup and shutdown lifecycle."""
    setup_telemetry()
    log.info("nrvq.startup.db_engine_creating", code="NRVQ-DB-DEBUG-1")
    await init_db()
    log.info("nrvq.startup.db_engine_created", code="NRVQ-DB-DEBUG-2")
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
    log.info("nrvq.startup.migrations_starting", code="NRVQ-DB-DEBUG-3")
    await run_migrations()
    log.info("nrvq.startup.migrations_done", code="NRVQ-DB-DEBUG-4")
    await ensure_schema_compatibility()
    if hasattr(app.state, "loader") and app.state.loader:
        log.info("nrvq.startup.warm_cache_starting", code="NRVQ-DB-DEBUG-5")
        await app.state.loader.warm_cache()
        log.info("nrvq.startup.warm_cache_done", code="NRVQ-DB-DEBUG-6")
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
    app.include_router(graphs.router)
    app.include_router(redteam.router, prefix="/api/v1", tags=["redteam"])
    app.add_middleware(TelemetryMiddleware)
    mount_metrics_endpoint(app)
    return app


app = create_app()
