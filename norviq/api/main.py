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
from norviq.api.audit_retention import RetentionPruner
from norviq.api.db.session import close_db, create_tables, ensure_schema_compatibility, get_session, init_db
from norviq.api.rate_limit import RateLimitMiddleware
from norviq.api.siem import AuditForwarder
from norviq.fleet_relay import FleetRelayForwarder
from norviq.fleet_puller import FleetPolicyPuller
from norviq.api.routers import attack_graph_compute, agents, audit, auth_login, cluster_info, coverage, deployments, evaluate, fleet_enroll, graph, graphs, health, keys, me, mitre, packs, policies, redteam, search, settings_router, threats, version
from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.store import GraphStore
from norviq.engine.opa_client import shutdown_managed_opa
from norviq.engine.policy_loader import PolicyLoader
from norviq.telemetry.exporter import mount_metrics_endpoint
from norviq.api.body_limit import BodySizeLimitMiddleware
from norviq.telemetry.middleware import TelemetryMiddleware
from norviq.telemetry.provider import setup_telemetry, shutdown_telemetry
from norviq.api.db.models import Base

# Sec-WebSocket-Protocol marker carrying the audit-stream JWT out of the URL (see ws_audit): the client
# offers ["nrvq-audit-jwt", "<token>"]; the server reads the token from the handshake header and echoes
# ONLY this marker back on accept() — never the token — so the credential never lands in an access log.
_WS_JWT_SUBPROTOCOL = "nrvq-audit-jwt"

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
    # No-default-in-prod: the seeded admin password must not still be the shipped default when
    # strong-secret enforcement is on. Warn always; refuse to start under require_strong_secret (fail-safe).
    if settings.auth_login_enabled and settings.auth_admin_password == settings.auth_default_admin_password:
        log.warning(
            "nrvq.auth.default_admin_password",
            detail="The local admin is using the shipped default password. Set auth.adminPassword "
            "(NRVQ_AUTH_ADMIN_PASSWORD) before production.",
            code="NRVQ-AUTH-14014",
        )
        if settings.require_strong_secret:
            raise RuntimeError(
                "Refusing to start: the local admin password is the shipped default. "
                "Set NRVQ_AUTH_ADMIN_PASSWORD (NRVQ_REQUIRE_STRONG_SECRET is enabled)."
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
    # RETENTION: unified background pruner — audit_log, coverage snapshots, expired drafts, stale
    # agent-registry rows, and old asset-graph snapshots; each table's window has its own <=0 disable.
    app.state.audit_retention_pruner = RetentionPruner()
    await app.state.audit_retention_pruner.start()
    app.state.loader = PolicyLoader(app.state.cache, app.state.evaluator)
    app.state.evaluator.bind_loader(app.state.loader)
    log.info("nrvq.startup.migrations_starting", code="NRVQ-DB-DEBUG-3")
    await run_migrations()
    log.info("nrvq.startup.migrations_done", code="NRVQ-DB-DEBUG-4")
    await ensure_schema_compatibility()
    # Seed the default admin (must_change=True) after the schema exists so a fresh install can log in.
    await auth_login.ensure_default_admin()
    if hasattr(app.state, "loader") and app.state.loader:
        log.info("nrvq.startup.warm_cache_starting", code="NRVQ-DB-DEBUG-5")
        await app.state.loader.warm_cache()
        log.info("nrvq.startup.warm_cache_done", code="NRVQ-DB-DEBUG-6")

    # HA: every API replica subscribes to the policy-mutation stream so a create/apply/delete on ANY replica
    # propagates to all of them within pub/sub latency (~ms) — without this, a peer replica keeps enforcing
    # the stale/deleted rego until a restart (the H1/H2 multi-replica correctness gap). Skip our own echoes
    # (Redis broadcasts to every subscriber incl. self); the mutating call already updated local state.
    async def _on_remote_policy_event(operation: str, namespace: str, agent_class: str, origin: str) -> None:
        if origin and origin == getattr(app.state.loader, "_origin", None):
            return  # our own publish — local state is already current
        await app.state.loader.apply_remote_event(operation, namespace, agent_class)

    async def _policy_sync_loop() -> None:
        # Reconnect-on-error so a transient Redis blip doesn't silently stop cross-replica sync for the pod's life.
        while True:
            try:
                await app.state.cache.listen_policy_mutations(_on_remote_policy_event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.error("nrvq.startup.policy_sync_dropped", error=str(exc), code="NRVQ-API-7064")
                await asyncio.sleep(2)

    app.state.policy_sync_task = asyncio.create_task(_policy_sync_loop())
    # Seed the per-ns posture mirror from persisted NamespaceSettings so pre-existing rows
    # enforce after a restart / Redis flush (best-effort; the evaluator falls back to global config on a miss).
    try:
        await settings_router.warm_ns_settings(app.state.cache)
    except Exception as exc:  # noqa: BLE001 — advisory warm; never block startup
        log.error("nrvq.startup.ns_settings_warm_failed", error=str(exc), code="NRVQ-API-7063")
    # SECURITY (trust fail-open fix): re-seed durable admin freeze/cap from the DB into Redis so a Redis
    # restart/flush cannot leave a killed/capped agent running unpoliced.
    try:
        from norviq.api.routers.agents import warm_agent_overrides
        await warm_agent_overrides(app.state.cache)
    except Exception as exc:  # noqa: BLE001 — advisory warm; never block startup
        log.error("nrvq.startup.agent_overrides_warm_failed", error=str(exc), code="NRVQ-API-7035")
    app.state.siem_forwarder = AuditForwarder()
    await app.state.siem_forwarder.start()  # no-op unless settings.siem_enabled
    # Single-cluster-first: a token-joined spoke persists its enrollment in FleetJoinState; re-apply it over env
    # BEFORE the relay/puller start so a `norviq fleet join` survives restarts (and a `leave` keeps fleet off).
    try:
        provider = get_session()
        _sess = await provider.__anext__()
        try:
            await fleet_enroll.configure_from_join_state(_sess)
        finally:
            await provider.aclose()
    except Exception as exc:  # pragma: no cover - best-effort; never block startup on join-state load
        log.warning("nrvq.startup.join_state_load_failed", error=str(exc), code="NRVQ-FLT-15034")
    app.state.fleet_relay = FleetRelayForwarder()
    await app.state.fleet_relay.start()  # no-op unless settings.fleet_enabled (fire-and-forget)
    app.state.fleet_puller = FleetPolicyPuller(loader=app.state.loader)
    await app.state.fleet_puller.start()  # pull+verify+apply signed bundles (no-op unless configured)
    log.info("nrvq.api.started", port=settings.api_port, code="NRVQ-API-7000")
    yield
    sync_task = getattr(app.state, "policy_sync_task", None)
    if sync_task is not None:
        sync_task.cancel()
        try:
            await sync_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 — shutdown best-effort
            pass
    await app.state.fleet_puller.stop()
    await app.state.fleet_relay.stop()
    await app.state.siem_forwarder.stop()
    await app.state.audit_retention_pruner.stop()
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
    app.include_router(auth_login.router, prefix="/api/v1", tags=["auth"])  # local username/password login
    app.include_router(cluster_info.router, prefix="/api/v1", tags=["cluster-info"])
    app.include_router(deployments.router, prefix="/api/v1", tags=["deployments"])
    app.include_router(mitre.router, prefix="/api/v1", tags=["mitre"])
    app.include_router(coverage.router, prefix="/api/v1", tags=["coverage"])
    app.include_router(graph.router, prefix="/api/v1")
    app.include_router(graphs.router)
    app.include_router(threats.router)
    app.include_router(attack_graph_compute.router)
    app.include_router(redteam.router, prefix="/api/v1", tags=["redteam"])
    app.include_router(settings_router.router, prefix="/api/v1", tags=["settings"])
    app.include_router(version.router, prefix="/api/v1", tags=["version"])
    app.include_router(keys.router, prefix="/api/v1", tags=["keys"])
    app.include_router(search.router, prefix="/api/v1", tags=["search"])  # ⌘K backing endpoint
    app.include_router(packs.router, prefix="/api/v1", tags=["packs"])
    app.include_router(fleet_enroll.router, prefix="/api/v1", tags=["fleet-enroll"])
    app.state.audit_hub = AuditHub()

    @app.websocket("/ws/audit")
    async def ws_audit(websocket: WebSocket) -> None:
        """Stream live decisions to the Audit Log feed, scoped by the token's namespace claim."""
        # Authenticate BEFORE accepting the socket. Preferred: the JWT rides in the
        # Sec-WebSocket-Protocol handshake header as ["nrvq-audit-jwt", "<token>"] — browsers can't set
        # Authorization on a WS handshake, and a `?token=` query string leaks the credential into access
        # logs / browser history / Referer (SEC). Read the subprotocol first; keep the query-param and
        # Authorization paths as a deprecated fallback for non-browser clients (curl, the integration
        # harness). We echo ONLY the marker back on accept() below, never the token value.
        from jwt import PyJWTError as JWTError

        from norviq.api.auth import decode_token, scoped_namespace

        offered = list(websocket.scope.get("subprotocols") or [])
        raw = ""
        if _WS_JWT_SUBPROTOCOL in offered:
            i = offered.index(_WS_JWT_SUBPROTOCOL)
            if i + 1 < len(offered):
                raw = offered[i + 1]
        if not raw:
            raw = websocket.query_params.get("token") or ""
        if not raw:
            header = websocket.headers.get("authorization", "")
            raw = header[7:] if header.lower().startswith("bearer ") else ""
        try:
            # Pass the app cache so a logged-out (revoked) token cannot open a new stream.
            user = await decode_token(raw, cache=getattr(websocket.app.state, "cache", None))
        except JWTError:
            await websocket.close(code=1008)  # policy violation: invalid/missing/revoked token
            return
        # H1 (WS parity): decode_token only checks signature + revocation, not must_change — mirror
        # get_current_user's fail-closed gate here too, or a token minted with must_change=True (the
        # seeded default admin / any account post admin_reset, i.e. still on a KNOWN password) could
        # stream live namespace-scoped audit data while every REST route correctly locks it out.
        if user.get("must_change"):
            log.info(
                "nrvq.auth.must_change_blocked",
                sub=user.get("sub"),
                path="/ws/audit",
                code="NRVQ-AUTH-14018",
            )
            await websocket.close(code=1008)  # policy violation: password change required
            return
        requested_ns = websocket.query_params.get("namespace", "")
        try:
            namespace = scoped_namespace(user, requested_ns) or ""
        except Exception:
            await websocket.close(code=1008)
            return
        # RFC 6455: the selected subprotocol MUST be one the client offered — echo the marker back only
        # when it was offered, and never echo the token value.
        accept_proto = _WS_JWT_SUBPROTOCOL if _WS_JWT_SUBPROTOCOL in offered else None
        await websocket.accept(subprotocol=accept_proto)
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
    # Cap request-body size (413) before evaluation — bounds the base64 fan-out DoS amplifier.
    app.add_middleware(BodySizeLimitMiddleware)
    # Added LAST so it is OUTERMOST (Starlette wraps user middleware in reverse add-order) —
    # a flooded/over-limit caller gets 429'd before the API spends any effort buffering the body or
    # recording telemetry for the request.
    app.add_middleware(RateLimitMiddleware)
    mount_metrics_endpoint(app)
    return app


app = create_app()
