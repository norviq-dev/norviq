# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Waiting for a peer to create the schema must not kill the pod.

`create_tables()` takes a transaction-scoped advisory lock so concurrent processes cannot race
`create_all`. That part is right. What was wrong is what happened to the WAITERS: the connection
carries the ordinary NRVQ_DB_COMMAND_TIMEOUT (10s by default), and the chart runs `api.workers: 4`
across `api.replicas: 2` — eight processes queueing on one lock. On the run that first creates a new
table the holder takes long enough that the waiters blow that budget, asyncpg raises TimeoutError, and
uvicorn reports "Application startup failed. Exiting."

The pod then CrashLoopBackOffs, and because every restart re-enters the same contention it does not
reliably recover: observed live on AKS as two of three api pods stuck at 7 restarts and climbing, on a
cluster whose database was perfectly healthy.

Queuing behind a peer is the NORMAL path for this lock, not a fault, so it is retried rather than
fatal. By the second attempt the tables exist and create_all no-ops.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from norviq.api.db import session as dbsession


async def test_lock_contention_is_retried_not_fatal(monkeypatch) -> None:
    calls = {"n": 0}

    async def flaky_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raise asyncio.TimeoutError("peer holds the schema lock")

    monkeypatch.setattr(dbsession, "_create_tables_once", flaky_once)
    monkeypatch.setattr(dbsession, "_SCHEMA_INIT_BACKOFF_S", 0.0)

    await dbsession.create_tables()
    assert calls["n"] == 2, "a contended first attempt must be retried, not surfaced as a startup failure"


async def test_a_persistently_held_lock_still_fails_loudly(monkeypatch) -> None:
    """Retrying must not become swallowing: if the lock is never released, startup must still fail so
    the operator sees it rather than running an API with no schema."""
    async def always_timeout():
        raise asyncio.TimeoutError("held forever")

    monkeypatch.setattr(dbsession, "_create_tables_once", always_timeout)
    monkeypatch.setattr(dbsession, "_SCHEMA_INIT_BACKOFF_S", 0.0)

    with pytest.raises((asyncio.TimeoutError, TimeoutError)):
        await dbsession.create_tables()


async def test_a_non_timeout_error_is_not_retried(monkeypatch) -> None:
    """Only lock contention is retried. A genuine schema error (bad DDL, permissions) must surface at
    once — retrying it four more times only delays the report."""
    calls = {"n": 0}

    async def boom():
        calls["n"] += 1
        raise RuntimeError("relation cannot be created")

    monkeypatch.setattr(dbsession, "_create_tables_once", boom)
    with pytest.raises(RuntimeError):
        await dbsession.create_tables()
    assert calls["n"] == 1


def test_the_patience_budget_exceeds_a_realistic_hold() -> None:
    """Eight processes serialising on one lock while the holder runs create_all needs more headroom
    than the 10s statement timeout that was killing them."""
    total = sum(dbsession._SCHEMA_INIT_BACKOFF_S * i for i in range(1, dbsession._SCHEMA_INIT_ATTEMPTS))
    assert total >= 20, f"only {total}s of patience — a slow first create_all will still crashloop"


def test_the_advisory_lock_itself_is_still_taken() -> None:
    """The retry must not be mistaken for a licence to drop the lock: without it, concurrent create_all
    calls race and one loses on pg_type_typname_nsp_index."""
    src = inspect.getsource(dbsession._create_tables_once)
    assert "pg_advisory_xact_lock" in src


def test_schema_init_uses_its_own_connection_budget() -> None:
    """The killer was a CLIENT-side timeout, so no server setting could have fixed it.

    `_build_connect_args` puts asyncpg's `command_timeout` (NRVQ_DB_COMMAND_TIMEOUT, 10s) on every
    connection, and `pg_advisory_xact_lock` BLOCKS — so a process queueing behind seven peers is killed
    by its own client long before Postgres would refuse it. Application-level retry alone could not fix
    that: every retry re-entered the same 10s ceiling, which is exactly what the live pod showed (20
    contention retries logged across 4 restarts, then exit).
    """
    src = inspect.getsource(dbsession._schema_engine)
    assert 'connect_args["command_timeout"] = _SCHEMA_INIT_COMMAND_TIMEOUT_S' in src
    assert dbsession._SCHEMA_INIT_COMMAND_TIMEOUT_S >= 60, (
        "too tight to outlast seven peers each running an idempotent create_all"
    )


def test_the_throwaway_engine_is_always_disposed() -> None:
    """One transaction per process, but leaking a connection per retry across eight processes would
    turn the fix for contention into a cause of it."""
    src = inspect.getsource(dbsession._create_tables_once)
    assert "finally:" in src and "await engine.dispose()" in src


def test_schema_compat_shares_the_lock_and_the_budget() -> None:
    """The timeout MOVED here the moment create_tables was fixed.

    ensure_schema_compatibility runs 16 idempotent ALTERs, each taking a table lock, and eight api
    processes run them at once on startup. On the main engine they queued against the ordinary 10s
    client command_timeout and the pod exited "Application startup failed" all over again — observed
    live, with create_tables.complete logged immediately before the traceback.

    Sharing the advisory lock is what removes the contention rather than merely surviving it: eight
    processes serialise on one cheap lock instead of thrashing table locks across sixteen ALTERs.
    """
    src = inspect.getsource(dbsession.ensure_schema_compatibility)
    assert "_schema_engine()" in src, "schema-compat is back on the 10s main-engine budget"
    assert "pg_advisory_xact_lock" in src, "schema-compat no longer serialises with its peers"
    assert "await engine.dispose()" in src, "the throwaway engine leaks a connection per process"


def test_the_draft_backfill_stays_inside_the_locked_transaction() -> None:
    """It reads a column the ALTERs above may have just added; outside the transaction it would race
    the statements that create what it touches."""
    src = inspect.getsource(dbsession.ensure_schema_compatibility)
    lock_at = src.index("pg_advisory_xact_lock")
    update_at = src.index("UPDATE intent_drafts")
    dispose_at = src.index("await engine.dispose()")
    assert lock_at < update_at < dispose_at
