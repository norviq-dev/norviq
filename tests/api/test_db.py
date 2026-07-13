# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for PostgreSQL models and sessions."""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from norviq.api.db.models import AgentRegistryEntry, AuditLogEntry, Policy
from norviq.api.db.session import (
    bump_policy_version,
    close_db,
    create_tables,
    ensure_schema_compatibility,
    get_session,
    init_db,
    lock_policy_for_update,
    upsert_policy,
)
from norviq.config import settings


@asynccontextmanager
async def _session():
    """Drive the get_session async-generator dependency for direct DB tests.

    get_session is an async generator — `await get_session()` raises TypeError (the P-15
    bug). See docs/engineering/bug-patterns.md (async session lifecycle).
    """
    gen = get_session()
    session = await gen.__anext__()
    try:
        yield session
    finally:
        await gen.aclose()


@pytest.fixture
async def db_ready() -> None:
    """Initialize database and ensure schema exists."""
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set for PostgreSQL integration tests")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()
    # Mirrors the real app startup (norviq/api/main.py lifespan), which always follows
    # create_tables() with ensure_schema_compatibility() — create_all() never ALTERs an
    # existing table, so a persistent local dev Postgres volume provisioned before a
    # column (e.g. audit_log.framework) existed needs the idempotent backfill too.
    await ensure_schema_compatibility()
    try:
        yield
    finally:
        # Clean up the ns-*/planner rows these tests insert so they don't pollute the shared
        # dev DB (test-hygiene, P-16). FK order: policy_versions before policies.
        async with _session() as session:
            await session.execute(
                text("DELETE FROM policy_versions WHERE policy_id IN (SELECT id FROM policies WHERE namespace LIKE 'ns-%')")
            )
            await session.execute(text("DELETE FROM policies WHERE namespace LIKE 'ns-%'"))
            await session.execute(text("DELETE FROM audit_log WHERE namespace LIKE 'ns-%'"))
            await session.execute(text("DELETE FROM agent_registry WHERE agent_class = 'planner'"))
            await session.commit()
        await close_db()
        settings.pg_url = old_url


async def test_create_insert_and_query_policy(db_ready: None) -> None:
    """Insert and query policy rows with async session."""
    async with _session() as session:
        policy = Policy(
            name=f"policy-{uuid.uuid4().hex}",
            namespace=f"ns-{uuid.uuid4().hex}",
            agent_class="planner",
            rego_source="package norviq",
        )
        session.add(policy)
        await session.commit()
        found = await session.scalar(select(Policy).where(Policy.id == policy.id))
        assert found is not None
        assert found.namespace == policy.namespace


async def test_insert_and_query_audit_entry(db_ready: None) -> None:
    """Insert and query audit records by namespace."""
    namespace = f"ns-{uuid.uuid4().hex}"
    async with _session() as session:
        entry = AuditLogEntry(
            event_id=uuid.uuid4(),
            tool_name="kubectl.get",
            decision="allow",
            agent_id=f"spiffe://agent-{uuid.uuid4().hex}",
            agent_class="copilot",
            namespace=namespace,
        )
        session.add(entry)
        await session.commit()
        found = await session.scalar(select(AuditLogEntry).where(AuditLogEntry.namespace == namespace))
        assert found is not None
        assert found.tool_name == "kubectl.get"


async def test_policy_constraint_rejects_duplicate_namespace_agent(db_ready: None) -> None:
    """Reject duplicate policies for namespace and agent class."""
    namespace = f"ns-{uuid.uuid4().hex}"
    payload = {"name": "p1", "namespace": namespace, "agent_class": "planner", "rego_source": "package p"}
    async with _session() as session:
        session.add(Policy(**payload))
        await session.commit()
        session.add(Policy(**payload))
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


async def test_agent_registry_spiffe_id_unique(db_ready: None) -> None:
    """Reject duplicate SPIFFE IDs in agent registry."""
    spiffe = f"spiffe://norviq/ns/default/sa/{uuid.uuid4().hex}"
    async with _session() as session:
        session.add(AgentRegistryEntry(spiffe_id=spiffe, namespace="default", agent_class="planner"))
        await session.commit()
        session.add(AgentRegistryEntry(spiffe_id=spiffe, namespace="default", agent_class="planner"))
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


async def test_upsert_lock_and_returning_version(db_ready: None) -> None:
    """Use conflict-safe and lock-safe policy write helpers."""
    namespace = f"ns-{uuid.uuid4().hex}"
    async with _session() as session:
        await upsert_policy(
            session,
            name="first",
            namespace=namespace,
            agent_class="planner",
            rego_source="package p1",
            enforcement_mode="block",
        )
        await session.commit()
    async with _session() as session:
        await upsert_policy(
            session,
            name="second",
            namespace=namespace,
            agent_class="planner",
            rego_source="package p2",
            enforcement_mode="audit",
        )
        row = await lock_policy_for_update(session, namespace=namespace, agent_class="planner")
        assert row is not None
        next_version = await bump_policy_version(session, policy_id=row.id)
        await session.commit()
        assert next_version == 2


async def test_close_db_releases_engine() -> None:
    """Dispose engine and prevent new sessions."""
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set for PostgreSQL integration tests")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await close_db()
    with pytest.raises(RuntimeError):
        await get_session().__anext__()
    settings.pg_url = old_url
