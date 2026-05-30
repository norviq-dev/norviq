# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async SQLAlchemy session lifecycle for Norviq API."""

from __future__ import annotations

from datetime import datetime, timezone

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
    return settings.pg_url.strip().strip("\"'").replace("postgresql://", "postgresql+asyncpg://")


def _partition_bounds() -> tuple[str, str, str]:
    """Return current month partition and range."""
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end_year = start.year + (1 if start.month == 12 else 0)
    end_month = 1 if start.month == 12 else start.month + 1
    end = start.replace(year=end_year, month=end_month)
    return f"audit_log_{start.year}_{start.month:02d}", start.date().isoformat(), end.date().isoformat()


async def init_db() -> None:
    """Initialize async engine and session factory."""
    global _engine, _session_factory
    _engine = create_async_engine(
        _async_pg_url(),
        pool_size=settings.pg_pool_size,
        max_overflow=5,
        pool_timeout=5,
        connect_args={"command_timeout": 5},
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    log.info("nrvq.db.connected", pool_size=settings.pg_pool_size, code="NRVQ-DB-9000")


async def create_tables() -> None:
    """Create schema and current-month audit partition."""
    from norviq.api.db.models import Base

    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        part, start, end = _partition_bounds()
        await conn.execute(
            text(
                f"CREATE TABLE IF NOT EXISTS {part} PARTITION OF audit_log "
                f"FOR VALUES FROM ('{start}') TO ('{end}')"
            )
        )
    log.info("nrvq.db.tables_created", code="NRVQ-DB-9001")


async def get_session() -> AsyncSession:
    """Return async session from initialized factory."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory()


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
