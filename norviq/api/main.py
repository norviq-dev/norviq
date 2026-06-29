# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI application entrypoint for Norviq."""

import asyncio
from contextlib import asynccontextmanager
import sys

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from norviq.api.audit_hub import AuditHub
from norviq.api.db.session import close_db, create_tables, ensure_schema_compatibility, get_session, init_db
from norviq.api.siem import AuditForwarder
from norviq.fleet_relay import FleetRelayForwarder
from norviq.fleet_puller import FleetPolicyPuller
from norviq.api.routers import attack_graph_compute, agents, audit, cluster_info, coverage, deployments, evaluate, graph, graphs, health, keys, me, mitre, policies, redteam, settings_router, version
from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.store import GraphStore
from norviq.engine.opa_client import shutdown_managed_opa
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


async def _connect_with_backoff(coro_factory, name: str, retry_code: str, fail_code: str, attempts: int = 5):
    """Retry a startup connection with exponential backoff (1,2,4,8,16s).

    Defense-in-depth atop the initContainers: a backend may accept TCP before it is
    query-ready, so retry rather than crash. Raises after the final attempt so the pod
    restarts (initContainers should normally prevent reaching that).
    """
    delay = 1
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except Exception as exc:
            if attempt == attempts:
                log.error(f"nrvq.startup.{name}_failed", attempts=attempt, error=str(exc), code=fail_code)
                raise
            log.warning(f"nrvq.startup.{name}_retry", attempt=attempt, delay=delay, error=str(exc), code=retry_code)
            await asyncio.sleep(delay)
            delay *= 2


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
    # A weak JWT secret means forgeable admin tokens. "Weak" = the shipped default, empty, or too
    # short — checking all three so an unset/blank NRVQ_API_SECRET_KEY can't silently ship a forgeable
    # key when require_strong_secret is on (fail-safe: refuse to start rather than run insecure).
    secret = settings.api_secret_key or ""
    if secret == "change-me-in-production" or len(secret) < 16:
        log.warning(
            "nrvq.api.insecure_default_secret",
            detail="JWT secret is the shipped default, empty, or too short — tokens are forgeable. "
            "Set NRVQ_API_SECRET_KEY to a strong value.",
            code="NRVQ-API-7099",
        )
        if settings.require_strong_secret:
            raise RuntimeError(
                "Refusing to start: api_secret_key is weak (default/empty/<16 chars). "
                "Set NRVQ_API_SECRET_KEY to a strong secret (NRVQ_REQUIRE_STRONG_SECRET is enabled)."
            )
    log.info("nrvq.startup.db_engine_creating", code="NRVQ-DB-DEBUG-1")
    await _connect_with_backoff(init_db, "init_db", retry_code="NRVQ-DB-9035", fail_code="NRVQ-DB-9034")
    log.info("nrvq.startup.db_engine_created", code="NRVQ-DB-DEBUG-2")
    await create_tables()
    app.state.cache = RedisCache()
    await _connect_with_backoff(
        app.state.cache.connect, "cache_connect", retry_code="NRVQ-REG-9035", fail_code="NRVQ-REG-9034"
    )
    app.state.evaluator = OPAEvaluator(app.state.cache)
    if settings.opa_mode == "server":
        await app.state.evaluator.opa.start()
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
    app.state.siem_forwarder = AuditForwarder()
    await app.state.siem_forwarder.start()  # no-op unless settings.siem_enabled
    app.state.fleet_relay = FleetRelayForwarder()
    await app.state.fleet_relay.start()  # no-op unless settings.fleet_enabled (F045; fire-and-forget)
    app.state.fleet_puller = FleetPolicyPuller(loader=app.state.loader)
    await app.state.fleet_puller.start()  # P2: pull+verify+apply signed bundles (no-op unless configured)
    log.info("nrvq.api.started", port=settings.api_port, code="NRVQ-API-7000")
    yield
    await app.state.fleet_puller.stop()
    await app.state.fleet_relay.stop()
    await app.state.siem_forwarder.stop()
    if settings.opa_mode == "server":
        await app.state.evaluator.opa.stop()
        shutdown_managed_opa()
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
    app.include_router(me.router, prefix="/api/v1", tags=["me"])
    app.include_router(cluster_info.router, prefix="/api/v1", tags=["cluster-info"])
    app.include_router(deployments.router, prefix="/api/v1", tags=["deployments"])
    app.include_router(mitre.router, prefix="/api/v1", tags=["mitre"])
    app.include_router(coverage.router, prefix="/api/v1", tags=["coverage"])
    app.include_router(graph.router, prefix="/api/v1")
    app.include_router(graphs.router)
    app.include_router(attack_graph_compute.router)
    app.include_router(redteam.router, prefix="/api/v1", tags=["redteam"])
    app.include_router(settings_router.router, prefix="/api/v1", tags=["settings"])
    app.include_router(version.router, prefix="/api/v1", tags=["version"])
    app.include_router(keys.router, prefix="/api/v1", tags=["keys"])
    app.state.audit_hub = AuditHub()

    @app.websocket("/ws/audit")
    async def ws_audit(websocket: WebSocket) -> None:
        """Stream live decisions to the Audit Log feed, scoped by the token's namespace claim."""
        # Authenticate BEFORE accepting the socket (token via ?token= or Authorization header).
        from jose import JWTError

        from norviq.api.auth import decode_token, scoped_namespace

        raw = websocket.query_params.get("token") or ""
        if not raw:
            header = websocket.headers.get("authorization", "")
            raw = header[7:] if header.lower().startswith("bearer ") else ""
        try:
            user = await decode_token(raw)
        except JWTError:
            await websocket.close(code=1008)  # policy violation: invalid/missing token
            return
        requested_ns = websocket.query_params.get("namespace", "")
        try:
            namespace = scoped_namespace(user, requested_ns) or ""
        except Exception:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        hub: AuditHub = websocket.app.state.audit_hub
        queue = hub.subscribe()
        log.info("nrvq.api.ws_audit.open", namespace=namespace, code="NRVQ-API-7040")
        try:
            while True:
                record = await queue.get()
                if namespace and namespace != "all" and record.get("namespace") not in (namespace, "", None):
                    continue
                await websocket.send_json(record)
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(queue)
            log.info("nrvq.api.ws_audit.close", code="NRVQ-API-7041")

    app.add_middleware(TelemetryMiddleware)
    mount_metrics_endpoint(app)
    return app


app = create_app()
