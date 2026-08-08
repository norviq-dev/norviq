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
