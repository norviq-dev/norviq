# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Concurrent replicas must be able to initialise the schema without one of them dying.

`Base.metadata.create_all` checks "does this table exist?" and then creates it, and those two steps are
not atomic. The chart runs `api.replicas: 2` by default (the HA default), so on a fresh install both
pods boot at once, both see `policies` absent, and both issue CREATE TABLE. One loses in the system
catalog and its STARTUP DIES:

    duplicate key value violates unique constraint "pg_type_typname_nsp_index"
    DETAIL:  Key (typname, typnamespace)=(policies, 2200) already exists.
    ERROR:    Application startup failed. Exiting.

Observed live on a fresh `helm install`, at `norviq/api/db/session.py::create_tables`.

It self-heals — the pod restarts and by then the table exists — which is exactly why it looked harmless
and survived. But it makes a fresh install NONDETERMINISTIC: with unluckier timing or more replicas the
crash backoff can outlast `helm install --wait --atomic`, which then rolls back a healthy install. A
transaction-scoped advisory lock makes check-then-create atomic across pods.

This test drives real concurrent engines against a real Postgres, because that is the only thing that
reproduces it — a single-connection test always passes. Measured here: WITHOUT the lock 3 of 4 replicas
crashed; WITH it, 4 of 4 booted.
"""

from __future__ import annotations

import asyncio
import os

import pytest

pytest.importorskip("asyncpg")

_DEFAULT_DSN = "postgresql://norviq:norviq_local_dev@127.0.0.1:5433/norviq"
_ADMIN_DSN = os.environ.get("NRVQ_TEST_PG_URL", _DEFAULT_DSN)
_RACE_DB = "norviq_schema_race_test"
_REPLICAS = 4


def _dsn_parts(dsn: str) -> dict:
    from urllib.parse import urlsplit

    u = urlsplit(dsn)
    return {"host": u.hostname, "port": u.port or 5432, "user": u.username,
            "password": u.password, "database": (u.path or "/norviq").lstrip("/")}


async def _postgres_reachable() -> bool:
    import asyncpg

    try:
        conn = await asyncio.wait_for(asyncpg.connect(**_dsn_parts(_ADMIN_DSN)), timeout=4)
    except Exception:
        return False
    await conn.close()
    return True


def _skip_without_postgres() -> None:
    if not asyncio.new_event_loop().run_until_complete(_postgres_reachable()):
        pytest.skip(f"no Postgres reachable at {_dsn_parts(_ADMIN_DSN)['host']}:{_dsn_parts(_ADMIN_DSN)['port']}")


async def _recreate_database() -> str:
    import asyncpg

    admin = await asyncpg.connect(**_dsn_parts(_ADMIN_DSN))
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{_RACE_DB}" WITH (FORCE)')
        await admin.execute(f'CREATE DATABASE "{_RACE_DB}"')
    finally:
        await admin.close()
    p = _dsn_parts(_ADMIN_DSN)
    return f"postgresql+asyncpg://{p['user']}:{p['password']}@{p['host']}:{p['port']}/{_RACE_DB}"


async def _boot_replicas(*, take_lock: bool) -> list[BaseException]:
    """Boot `_REPLICAS` independent engines concurrently; return whatever blew up."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from norviq.api.db.models import Base
    from norviq.api.db.session import _SCHEMA_INIT_LOCK

    url = await _recreate_database()
    # One engine per replica — separate pools, exactly like separate pods.
    engines = [create_async_engine(url) for _ in range(_REPLICAS)]

    async def boot(engine) -> None:
        async with engine.begin() as conn:
            if take_lock:
                await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _SCHEMA_INIT_LOCK})
            await conn.run_sync(Base.metadata.create_all)

    try:
        results = await asyncio.gather(*(boot(e) for e in engines), return_exceptions=True)
    finally:
        for e in engines:
            await e.dispose()
    return [r for r in results if isinstance(r, BaseException)]


def test_concurrent_replicas_all_initialise_the_schema() -> None:
    """The fix: every replica boots. This is the assertion that protects a fresh install."""
    _skip_without_postgres()
    failures = asyncio.run(_boot_replicas(take_lock=True))
    assert not failures, (
        f"{len(failures)}/{_REPLICAS} replicas failed schema init even WITH the advisory lock: "
        f"{type(failures[0]).__name__}: {str(failures[0])[:200]}"
    )


def test_the_race_is_real_without_the_lock() -> None:
    """Guards the PREMISE: if this ever stops failing, the test above proves nothing.

    Without it, someone could delete the advisory lock and the suite would stay green — the race is
    timing-dependent and a weaker test would pass by luck. If SQLAlchemy or Postgres ever makes
    create_all atomic on its own, this fails and the lock can be reconsidered deliberately.
    """
    _skip_without_postgres()
    failures = asyncio.run(_boot_replicas(take_lock=False))
    assert failures, (
        "concurrent create_all no longer races — check whether create_all became atomic before "
        "removing the advisory lock in norviq/api/db/session.py"
    )


def test_the_lock_keys_are_distinct_per_schema() -> None:
    """Hub and spoke own different schemas and must not block each other."""
    from norviq.api.db.session import _SCHEMA_INIT_LOCK
    from norviq.fleet.db import _FLEET_SCHEMA_INIT_LOCK

    assert _SCHEMA_INIT_LOCK != _FLEET_SCHEMA_INIT_LOCK
    # Postgres advisory locks are bigint.
    for key in (_SCHEMA_INIT_LOCK, _FLEET_SCHEMA_INIT_LOCK):
        assert -(2**63) <= key < 2**63, f"{key} is not a valid bigint advisory-lock key"
