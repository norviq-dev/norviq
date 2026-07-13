# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet hub DB lifecycle — a SEPARATE async engine/session over the dedicated fleet store
(NRVQ_FLEET_PG_URL). Mirrors norviq/api/db/session.py but never touches the spoke engine."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from norviq.config import settings

log = structlog.get_logger()
_fleet_engine: AsyncEngine | None = None
_fleet_session_factory: async_sessionmaker[AsyncSession] | None = None


def _fleet_async_pg_url() -> str:
    """Return the SQLAlchemy asyncpg URL for the fleet store (ssl handled via connect_args)."""
    raw = settings.fleet_pg_url.strip().strip("\"'").replace("postgresql://", "postgresql+asyncpg://")
    split = urlsplit(raw)
    filtered = [(k, v) for k, v in parse_qsl(split.query, keep_blank_values=True) if k.lower() not in {"ssl", "sslmode"}]
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(filtered), split.fragment))


def _fleet_connect_args() -> dict:
    """Resolve asyncpg ssl from the fleet URL / db_ssl_mode (same logic as the spoke)."""
    pg_query = dict(parse_qsl(urlsplit(settings.fleet_pg_url).query, keep_blank_values=True))
    ssl_mode = str(pg_query.get("sslmode") or pg_query.get("ssl") or getattr(settings, "db_ssl_mode", "prefer")).lower()
    if ssl_mode in {"disable", "false", "0"}:
        ssl: object = False
    elif ssl_mode in {"require", "verify-ca", "verify-full"}:
        ssl = ssl_mode
    else:
        ssl = "prefer"
    return {"command_timeout": settings.db_command_timeout, "ssl": ssl}


async def fleet_init_db() -> None:
    """Initialize the fleet async engine + session factory."""
    global _fleet_engine, _fleet_session_factory
    _fleet_engine = create_async_engine(
        _fleet_async_pg_url(),
        pool_size=settings.pg_pool_size,
        max_overflow=settings.db_pool_max_overflow,
        pool_timeout=settings.db_pool_timeout,
        pool_pre_ping=True,
        pool_recycle=settings.db_pool_recycle_s,
        connect_args=_fleet_connect_args(),
    )
    _fleet_session_factory = async_sessionmaker(_fleet_engine, expire_on_commit=False)
    log.info("nrvq.fleet.db_connected", code="NRVQ-FLT-15011")


async def fleet_create_tables() -> None:
    """Create the fleet tables (FleetBase only — never the spoke schema)."""
    from norviq.fleet.models import FleetBase

    if _fleet_engine is None:
        raise RuntimeError("Fleet DB not initialized. Call fleet_init_db() first.")
    async with _fleet_engine.begin() as conn:
        await conn.run_sync(FleetBase.metadata.create_all)
        # F-69: additive column on the pre-existing `cluster` table — create_all only creates missing TABLES, not
        # columns. Idempotent (ADD COLUMN IF NOT EXISTS) so an already-registered fleet upgrades cleanly in place.
        await conn.execute(text("ALTER TABLE cluster ADD COLUMN IF NOT EXISTS console_url VARCHAR(512) DEFAULT ''"))


async def fleet_get_session() -> AsyncSession:
    """Yield a fleet async session (FastAPI dependency)."""
    if _fleet_session_factory is None:
        raise RuntimeError("Fleet DB not initialized. Call fleet_init_db() first.")
    async with _fleet_session_factory() as session:
        yield session


async def fleet_close_db() -> None:
    """Dispose the fleet engine."""
    global _fleet_engine, _fleet_session_factory
    if _fleet_engine is None:
        return
    await _fleet_engine.dispose()
    _fleet_engine = None
    _fleet_session_factory = None
