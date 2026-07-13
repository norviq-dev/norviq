# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for fire-and-forget AuditEmitter behavior."""

from __future__ import annotations

import os
import time
import uuid
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy import delete, select

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import close_db, create_tables, ensure_schema_compatibility, get_session, init_db
from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def _load_dotenv_if_present() -> None:
    """Load key/value pairs from local .env file."""
    env_file = Path(".env")
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#") or "=" not in item:
            continue
        key, value = item.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@asynccontextmanager
async def _session():
    """Drive the get_session async-generator dependency (`await get_session()` is the P-15 bug)."""
    gen = get_session()
    session = await gen.__anext__()
    try:
        yield session
    finally:
        await gen.aclose()


def _build_event(event_id: str, namespace: str) -> ToolCallEvent:
    """Create a test tool event."""
    return ToolCallEvent(
        event_id=event_id,
        tool_name="kubectl.get",
        tool_params={"kind": "Pod"},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{namespace}/sa/agent",
            namespace=namespace,
            agent_class="planner",
        ),
        session_id=f"sess-{uuid.uuid4().hex}",
    )


def _build_decision(event_id: str) -> PolicyDecision:
    """Create a test policy decision."""
    return PolicyDecision(
        decision="allow",
        policy_id="policy-default",
        rule_id="default_allow",
        reason="ok",
        trust_score=0.9,
        latency_ms=5.0,
        event_id=event_id,
    )


@pytest.fixture
async def postgres_ready() -> None:
    """Initialize PostgreSQL schema from env for integration tests."""
    _load_dotenv_if_present()
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set for PostgreSQL integration tests")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()
    # Mirrors the real app startup (norviq/api/main.py lifespan): create_tables() alone
    # never ALTERs an existing table, so a persistent local dev Postgres volume provisioned
    # before a column (e.g. audit_log.framework) existed needs this idempotent backfill too.
    await ensure_schema_compatibility()
    yield
    await close_db()
    settings.pg_url = old_url


async def test_emit_is_fire_and_forget(monkeypatch: pytest.MonkeyPatch) -> None:
    """emit() should return immediately while task runs in background."""
    emitter = AuditEmitter()
    started: list[str] = []

    async def _slow_emit(*_: object, **__: object) -> None:
        started.append("yes")
        await asyncio.sleep(0.05)

    monkeypatch.setattr(emitter, "_do_emit", _slow_emit)
    event_id = str(uuid.uuid4())
    t0 = time.perf_counter()
    emitter.emit(_build_event(event_id, "fire-and-forget"), _build_decision(event_id))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < 20
    await emitter.close()
    assert started == ["yes"]


async def test_emit_writes_to_postgresql(postgres_ready: None) -> None:
    """Emitter should persist AuditLogEntry rows."""
    emitter = AuditEmitter()
    namespace = f"audit-{uuid.uuid4().hex}"
    event_id = str(uuid.uuid4())
    emitter.emit(_build_event(event_id, namespace), _build_decision(event_id), payload={"scope": "read"})
    await emitter.close()
    async with _session() as session:
        found = await session.scalar(select(AuditLogEntry).where(AuditLogEntry.event_id == uuid.UUID(event_id)))
        assert found is not None
        assert found.namespace == namespace
        assert found.payload == {"scope": "read"}
        await session.execute(delete(AuditLogEntry).where(AuditLogEntry.event_id == uuid.UUID(event_id)))
        await session.commit()


async def test_emit_creates_otel_span(monkeypatch: pytest.MonkeyPatch) -> None:
    """Emitter should set all expected span attributes."""
    emitter = AuditEmitter()

    async def _noop(_: object) -> None:
        return None

    attrs: dict[str, object] = {}

    class _Span:
        def __enter__(self) -> "_Span":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def set_attribute(self, key: str, value: object) -> None:
            attrs[key] = value

    class _Tracer:
        def start_as_current_span(self, _: str) -> _Span:
            return _Span()

    monkeypatch.setattr(emitter, "_write_db", _noop)
    emitter._tracer = _Tracer()
    event_id = str(uuid.uuid4())
    emitter.emit(_build_event(event_id, "trace-ns"), _build_decision(event_id))
    await emitter.close()
    assert attrs["norviq.event_id"] == event_id
    assert attrs["norviq.tool_name"] == "kubectl.get"
    assert attrs["norviq.decision"] == "allow"
    assert attrs["norviq.rule_id"] == "default_allow"
    assert attrs["norviq.trust_score"] == 0.9
    assert attrs["norviq.latency_ms"] == 5.0
    assert attrs["norviq.session_id"].startswith("sess-")
    assert attrs["norviq.namespace"] == "trace-ns"


async def test_db_failure_does_not_crash_emit(monkeypatch: pytest.MonkeyPatch) -> None:
    """DB failures should be logged and suppressed."""
    emitter = AuditEmitter()

    async def _boom(_: object) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(emitter, "_write_db", _boom)
    event_id = str(uuid.uuid4())
    emitter.emit(_build_event(event_id, "db-fail"), _build_decision(event_id))
    await emitter.close()


async def test_span_failure_does_not_crash_emit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Span failures should be logged and suppressed."""
    emitter = AuditEmitter()

    async def _noop(_: object) -> None:
        return None

    class _BrokenTracer:
        def start_as_current_span(self, _: str) -> object:
            raise RuntimeError("otel down")

    monkeypatch.setattr(emitter, "_write_db", _noop)
    emitter._tracer = _BrokenTracer()
    event_id = str(uuid.uuid4())
    emitter.emit(_build_event(event_id, "span-fail"), _build_decision(event_id))
    await emitter.close()


async def test_close_drains_pending_tasks(monkeypatch: pytest.MonkeyPatch) -> None:
    """close() should await all pending emit tasks."""
    emitter = AuditEmitter()
    finished: list[str] = []

    async def _slow_do_emit(*_: object, **__: object) -> None:
        await asyncio.sleep(0.02)
        finished.append("done")

    monkeypatch.setattr(emitter, "_do_emit", _slow_do_emit)
    for _ in range(3):
        event_id = str(uuid.uuid4())
        emitter.emit(_build_event(event_id, "drain"), _build_decision(event_id))
    await emitter.close()
    assert len(finished) == 3
    assert not emitter._tasks
