# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async SQLAlchemy session lifecycle for Norviq API."""

from __future__ import annotations

from datetime import datetime, timezone
import traceback
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from sqlalchemy import text
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from norviq.config import settings

log = structlog.get_logger()
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _async_pg_url() -> str:
    """Return SQLAlchemy asyncpg URL."""
    raw = settings.pg_url.strip().strip("\"'").replace("postgresql://", "postgresql+asyncpg://")
    split = urlsplit(raw)
    filtered = [(k, v) for k, v in parse_qsl(split.query, keep_blank_values=True) if k.lower() not in {"ssl", "sslmode"}]
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(filtered), split.fragment))


def _build_connect_args() -> dict:
    """Build asyncpg connect args from settings."""
    pg_query = dict(parse_qsl(urlsplit(settings.pg_url).query, keep_blank_values=True))
    ssl_mode = str(
        pg_query.get("sslmode")
        or pg_query.get("ssl")
        or getattr(settings, "db_ssl_mode", "prefer")
    ).lower()
    if ssl_mode in {"disable", "false", "0"}:
        ssl = False
    elif ssl_mode in {"require", "verify-ca", "verify-full"}:
        ssl = ssl_mode
    else:
        ssl = "prefer"
    connect_args = {"command_timeout": settings.db_command_timeout, "ssl": ssl}
    log.info(
        "nrvq.db.connect_args_resolved",
        ssl_mode=ssl_mode,
        ssl=ssl,
        pg_query=pg_query,
        code="NRVQ-DB-DEBUG-CONNECT-ARGS",
    )
    return connect_args


# How many months of audit partitions to keep provisioned AHEAD of now. Creating only the current
# month is a time bomb: the first write after the month rolls over has no partition to land in, the
# INSERT raises, and the sidecar's audit emit swallows the error (proxy.py) — so the audit trail of a
# security product dies SILENTLY while tool calls keep flowing. A look-ahead window means a pod that
# runs across a boundary, or a cluster nobody redeploys for a while, keeps writing.
PARTITION_LOOKAHEAD_MONTHS = 3


def _month_window(start: datetime) -> tuple[str, str, str]:
    """Return (partition_name, inclusive_start, exclusive_end) for the month containing `start`."""
    end_year = start.year + (1 if start.month == 12 else 0)
    end_month = 1 if start.month == 12 else start.month + 1
    end = start.replace(year=end_year, month=end_month)
    return f"audit_log_{start.year}_{start.month:02d}", start.date().isoformat(), end.date().isoformat()


def _partition_months(count: int = PARTITION_LOOKAHEAD_MONTHS) -> list[tuple[str, str, str]]:
    """Return the current month plus the next `count - 1` months, oldest first."""
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    windows: list[tuple[str, str, str]] = []
    for _ in range(max(1, count)):
        name, begin, end = _month_window(start)
        windows.append((name, begin, end))
        start = datetime.fromisoformat(end).replace(tzinfo=timezone.utc)
    return windows


def _partition_bounds() -> tuple[str, str, str]:
    """Return current month partition and range."""
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return _month_window(start)


async def init_db() -> None:
    """Initialize async engine and session factory."""
    global _engine, _session_factory
    _engine = create_async_engine(
        _async_pg_url(),
        pool_size=settings.pg_pool_size,
        max_overflow=settings.db_pool_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        # pre_ping recycles a dead pooled connection on checkout, so the API auto-reconnects after a
        # Postgres restart (no manual pod restart); pool_recycle bounds stale-connection age.
        pool_pre_ping=True,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args=_build_connect_args(),
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    log.info("nrvq.db.connected", pool_size=settings.pg_pool_size, code="NRVQ-DB-9000")


async def create_tables() -> None:
    """Create schema and current-month audit partition."""
    from norviq.api.db.models import Base

    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    log.info("nrvq.startup.create_tables.begin", code="NRVQ-DB-DEBUG-2A")
    try:
        async with _engine.begin() as conn:
            log.info("nrvq.startup.create_tables.connection_acquired", code="NRVQ-DB-DEBUG-2B")
            await conn.run_sync(Base.metadata.create_all)
            log.info("nrvq.startup.create_tables.create_all_done", code="NRVQ-DB-DEBUG-2C")
            # create_all never ALTERs an existing table, so add new columns idempotently for
            # databases provisioned before the column existed (e.g. the running AKS namespace_settings).
            await conn.execute(
                text("ALTER TABLE namespace_settings ADD COLUMN IF NOT EXISTS sector VARCHAR(64)")
            )
            # Per-namespace apply governance mode (enforce | dry_run_only).
            await conn.execute(
                text("ALTER TABLE namespace_settings ADD COLUMN IF NOT EXISTS apply_mode VARCHAR(20)")
            )
            # Spoke fleet-bundle manifest (applied keys) for retract/reconcile.
            await conn.execute(
                text("ALTER TABLE fleet_bundle_state ADD COLUMN IF NOT EXISTS last_manifest TEXT")
            )
            # Force-password-change flag on the local login user store (create_all never ALTERs an
            # existing `users` table, so add it idempotently for DBs provisioned before the column existed).
            await conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change BOOLEAN NOT NULL DEFAULT true")
            )
            # redteam_runs.results is nullable (NULL = detail-pruned). create_all never ALTERs an
            # existing table, so drop the NOT NULL idempotently — else a retention prune (UPDATE results=NULL)
            # is rejected on a DB provisioned before D3. (No-op on a fresh DB where it's already nullable.)
            await conn.execute(
                text("ALTER TABLE redteam_runs ALTER COLUMN results DROP NOT NULL")
            )
            # policy_versions now stores the priority + enforcement_mode at each version so a rollback AFTER a
            # restart restores the exact posture. create_all never ALTERs an existing table — add idempotently
            # (rows predating this default to priority 100 / mode block, the historical rehydration default).
            await conn.execute(
                text("ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100")
            )
            await conn.execute(
                text("ALTER TABLE policy_versions ADD COLUMN IF NOT EXISTS enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'block'")
            )
            # Provision a ROLLING WINDOW of monthly audit partitions (current + look-ahead), not just
            # the current month — see PARTITION_LOOKAHEAD_MONTHS. Names/bounds are derived from the
            # clock here, never from user input.
            # Each CREATE runs in its own SAVEPOINT. Postgres aborts the ENTIRE transaction on any failed
            # statement, so a bare try/except here would poison every statement that follows (and the
            # final COMMIT); begin_nested() rolls back just the failing statement and leaves the outer
            # transaction usable.
            for part, start, end in _partition_months():
                try:
                    async with conn.begin_nested():
                        await conn.execute(
                            text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                                f"CREATE TABLE IF NOT EXISTS {part} PARTITION OF audit_log "
                                f"FOR VALUES FROM ('{start}') TO ('{end}')"
                            )
                        )
                except Exception as exc:
                    # The one way this legitimately fails: rows for `part` already landed in DEFAULT
                    # (look-ahead lapsed), and Postgres refuses to split them out — "updated partition
                    # constraint for default partition would be violated by some row". Startup must NOT
                    # brick over it: writes keep landing in DEFAULT, so nothing is lost. Loud, not fatal —
                    # the operator has to move those rows and re-create the partition.
                    log.error(
                        "nrvq.db.partition_create_failed", partition=part, start=start, end=end,
                        error=str(exc), code="NRVQ-DB-9003",
                    )
            # Hard backstop: even if look-ahead maintenance ever lapses, a write past the last
            # provisioned month lands in DEFAULT instead of raising. Best-effort — a failure here must
            # not break startup, and it must not mask the loud failure of the monthly creates above.
            try:
                async with conn.begin_nested():
                    await conn.execute(
                        text("CREATE TABLE IF NOT EXISTS audit_log_default PARTITION OF audit_log DEFAULT")
                    )
            except Exception as exc:  # pragma: no cover - backstop only
                log.warning("nrvq.db.default_partition_skipped", error=str(exc), code="NRVQ-DB-9002")
        log.info("nrvq.startup.create_tables.complete", code="NRVQ-DB-DEBUG-2D")
        log.info("nrvq.db.tables_created", code="NRVQ-DB-9001")
    except Exception as exc:
        log.error(
            "nrvq.startup.create_tables.failed",
            error=str(exc),
            error_type=type(exc).__name__,
            traceback=traceback.format_exc(),
            code="NRVQ-DB-DEBUG-2-ERR",
        )
        raise


async def ensure_schema_compatibility() -> None:
    """Backfill historically missing columns with idempotent DDL."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    statements = (
        "ALTER TABLE policies ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 100",
        "ALTER TABLE policies ADD COLUMN IF NOT EXISTS enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'block'",
        # HA last-applied convergence: `applied_at` tracked ONLY in PolicyLoader._applied_at
        # (process-local, never persisted/broadcast) would leave a replica pinned by an operator's session
        # showing the pre-apply (or null) timestamp after a peer applied. Persisting it here lets every
        # replica re-read the same authoritative value (via load_from_db/warm_cache/apply_remote_event),
        # consistent with how the rest of the loader (rego/version/enforcement_mode) already converges.
        "ALTER TABLE policies ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ",
        # attack_paths tenant scoping: namespace column + backfill from the linked asset_graph.
        "ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS namespace VARCHAR(255)",
        (
            "UPDATE attack_paths SET namespace = ("
            "SELECT namespace FROM asset_graph WHERE asset_graph.id = attack_paths.graph_id"
            ") WHERE namespace IS NULL"
        ),
        "CREATE INDEX IF NOT EXISTS ix_attack_paths_namespace ON attack_paths (namespace)",
        # Audit decision-source column (idempotent; existing rows default to '').
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS framework VARCHAR(32) NOT NULL DEFAULT ''",
        # Compliance-draft provenance (framework + control it remediates); NULL for Attack-Graph drafts.
        "ALTER TABLE intent_drafts ADD COLUMN IF NOT EXISTS source_framework VARCHAR(32)",
        "ALTER TABLE intent_drafts ADD COLUMN IF NOT EXISTS source_control_id VARCHAR(64)",
        "ALTER TABLE intent_drafts ADD COLUMN IF NOT EXISTS source_control_name VARCHAR(255)",
        # Draft retention TTL — GC deletes only expired NON-enforcing drafts (never a policy/version).
        "ALTER TABLE intent_drafts ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
        "CREATE INDEX IF NOT EXISTS ix_intent_drafts_expires_at ON intent_drafts (expires_at)",
        # The real affected class for a compliance-remediation draft, once `agent_class`
        # becomes the compound "<class>__remediation__" persistence key (NULL for other draft kinds).
        "ALTER TABLE intent_drafts ADD COLUMN IF NOT EXISTS affected_class VARCHAR(255)",
        # RETENTION: optional API-key expiry (NULL = never expires).
        "ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ",
        # SECURITY (trust fail-open fix): durable freeze/cap so a Redis flush can't lift a kill-switch.
        "ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS frozen BOOLEAN NOT NULL DEFAULT false",
        "ALTER TABLE agent_registry ADD COLUMN IF NOT EXISTS trust_cap DOUBLE PRECISION",
    )
    async with _engine.begin() as conn:
        for statement in statements:
            await conn.execute(text(statement))
        # RETENTION backfill: drafts created before the expires_at column existed have NULL expiry and the
        # GC's WHERE clause (expires_at IS NOT NULL) never touches them — stamp them with the normal TTL
        # from their created_at so they age out like every other draft. Idempotent (only fills NULLs).
        await conn.execute(
            text("UPDATE intent_drafts SET expires_at = created_at + make_interval(days => :d) "
                 "WHERE expires_at IS NULL"),
            {"d": int(settings.draft_ttl_days)},
        )
    log.info("nrvq.db.schema_compat_applied", statements=len(statements), code="NRVQ-DB-9003")


async def get_session() -> AsyncSession:
    """Yield async session and always close it after request."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    async with _session_factory() as session:
        yield session


async def close_db() -> None:
    """Dispose engine and clear global state."""
    global _engine, _session_factory
    if _engine is None:
        return
    await _engine.dispose()
    _engine = None
    _session_factory = None
    log.info("nrvq.db.closed", code="NRVQ-DB-9002")


async def upsert_policy(
    session: AsyncSession, *, name: str, namespace: str, agent_class: str, rego_source: str, enforcement_mode: str
) -> None:
    """Upsert active policy row by namespace and agent class."""
    from norviq.api.db.models import Policy

    stmt = insert(Policy).values(
        name=name,
        namespace=namespace,
        agent_class=agent_class,
        rego_source=rego_source,
        enforcement_mode=enforcement_mode,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_policy_ns_class",
        set_={"name": name, "rego_source": rego_source, "enforcement_mode": enforcement_mode},
    )
    await session.execute(stmt)


async def upsert_agent_registry(
    session: AsyncSession,
    *,
    spiffe_id: str,
    namespace: str,
    agent_class: str,
    trust_score: float,
    trust_category: str,
    violation_count: int = 0,
) -> None:
    """Write-through an agent's latest trust into the persistent registry (upsert by spiffe_id)."""
    from norviq.api.db.models import AgentRegistryEntry

    stmt = insert(AgentRegistryEntry).values(
        spiffe_id=spiffe_id,
        namespace=namespace,
        agent_class=agent_class,
        trust_score=trust_score,
        trust_category=trust_category,
        violation_count=violation_count,
        last_seen=datetime.now(timezone.utc),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["spiffe_id"],
        set_={
            "namespace": namespace,
            "agent_class": agent_class,
            "trust_score": trust_score,
            "trust_category": trust_category,
            "violation_count": violation_count,
            "last_seen": datetime.now(timezone.utc),
        },
    )
    await session.execute(stmt)


async def lock_policy_for_update(session: AsyncSession, *, namespace: str, agent_class: str) -> object | None:
    """Lock one policy row before mutation."""
    from norviq.api.db.models import Policy

    stmt = (
        select(Policy).where(Policy.namespace == namespace, Policy.agent_class == agent_class).with_for_update(of=Policy)
    )
    return await session.scalar(stmt)


async def bump_policy_version(session: AsyncSession, *, policy_id: object) -> int | None:
    """Increment policy version atomically and return new value."""
    from norviq.api.db.models import Policy

    stmt = update(Policy).where(Policy.id == policy_id).values(version=Policy.version + 1).returning(Policy.version)
    return await session.scalar(stmt)
