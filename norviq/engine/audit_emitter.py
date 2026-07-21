# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Emit best-effort audit records to DB and OTel."""

from __future__ import annotations

import asyncio
from uuid import UUID

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.config import settings
from norviq.sdk.core.audit import AuditRecord
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()


class AuditEmitter:
    """Emits audit records to PostgreSQL and OTel in background tasks."""

    def __init__(self) -> None:
        """Create emitter state."""
        self._tasks: set[asyncio.Task[None]] = set()
        self._tracer: trace.Tracer | None = None
        # Bound how many audit DB writes can hold a pooled connection concurrently. emit()
        # still fires a task immediately for every call (fire-and-forget latency is preserved — the
        # caller never awaits this), but excess writers queue on the semaphore instead of each
        # grabbing a connection, so a flood of tool calls can't fan out enough concurrent INSERTs to
        # exhaust the DB pool (pg_pool_size + db_pool_max_overflow) and starve every other endpoint.
        self._db_write_gate = asyncio.Semaphore(settings.audit_emit_max_concurrency)

    async def init(self) -> None:
        """Initialize OTel tracer with OTLP exporter (skipped when OTel is disabled)."""
        if not settings.otel_enabled:
            # Don't build the OTLP exporter / batch processor when OTel is off — otherwise the
            # background batcher spams the (absent) collector even with otel.enabled=false.
            self._tracer = None
            log.info("nrvq.audit.init_skipped", reason="otel_disabled", code="NRVQ-AUD-6008")
            return
        try:
            provider = TracerProvider()
            exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer("norviq.audit")
            log.info("nrvq.audit.init", endpoint=settings.otel_endpoint, code="NRVQ-AUD-6000")
        except Exception as exc:
            self._tracer = None
            log.error("nrvq.audit.init_failed", error=str(exc), code="NRVQ-AUD-6001")

    def emit(self, event: ToolCallEvent, decision: PolicyDecision, payload: dict | None = None) -> None:
        """Schedule audit emit without blocking caller."""
        task = asyncio.create_task(self._do_emit(event, decision, payload))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _do_emit(self, event: ToolCallEvent, decision: PolicyDecision, payload: dict | None) -> None:
        """Run DB write and span export in background subtasks."""
        record = AuditRecord.from_event_and_decision(event, decision, payload=payload)
        db_task = asyncio.create_task(self._write_db(record))
        span_task = asyncio.create_task(self._emit_span(event, decision))
        await asyncio.gather(db_task, span_task, return_exceptions=True)
        log.debug("nrvq.audit.emitted", event_id=event.event_id, decision=decision.decision, code="NRVQ-AUD-6002")

    async def _acquire_session(self):
        """Acquire a session from the async-generator dependency or awaitable factory.

        get_session is a FastAPI async-generator dependency — `await get_session()` raises
        TypeError. See docs/engineering/bug-patterns.md (async session lifecycle / P-15/P-16).
        """
        provider = get_session()
        if hasattr(provider, "__anext__"):
            return await provider.__anext__(), provider
        return await provider, None

    async def _write_db(self, record: AuditRecord) -> None:
        """Persist an audit record into PostgreSQL.

        Gated by ``_db_write_gate`` so at most ``audit_emit_max_concurrency`` writers hold a
        pooled DB connection at once — a queued writer here does not block the caller of ``emit()``
        (that already returned), it only delays this specific background task.
        """
        async with self._db_write_gate:
            await self._write_db_locked(record)

    async def _write_db_locked(self, record: AuditRecord) -> None:
        """The actual write, run while holding a `_db_write_gate` permit."""
        session = None
        agen = None
        try:
            session, agen = await self._acquire_session()
            session.add(
                AuditLogEntry(
                    event_id=UUID(record.event_id),
                    tool_name=record.tool_name,
                    decision=record.decision,
                    agent_id=record.agent_id,
                    agent_class=record.agent_class,
                    namespace=record.namespace,
                    policy_id=record.policy_id,
                    rule_id=record.rule_id,
                    reason=record.reason,
                    session_id=record.session_id,
                    trust_score=record.trust_score,
                    latency_ms=record.latency_ms,
                    framework=record.framework,
                    payload=record.payload,
                )
            )
            await session.commit()
            log.debug("nrvq.audit.db_written", event_id=record.event_id, code="NRVQ-AUD-6003")
        except Exception as exc:
            log.error("nrvq.audit.db_failed", event_id=record.event_id, error=str(exc), code="NRVQ-AUD-6004")
            if session is not None:
                await session.rollback()
        finally:
            if agen is not None:
                await agen.aclose()
            elif session is not None:
                await session.close()

    async def _emit_span(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Emit OTel span attributes for a tool call."""
        if self._tracer is None:
            return
        try:
            with self._tracer.start_as_current_span("norviq.tool_call") as span:
                span.set_attribute("norviq.event_id", event.event_id)
                span.set_attribute("norviq.tool_name", event.tool_name)
                span.set_attribute("norviq.decision", decision.decision)
                span.set_attribute("norviq.rule_id", decision.rule_id)
                span.set_attribute("norviq.trust_score", decision.trust_score)
                span.set_attribute("norviq.latency_ms", decision.latency_ms)
                span.set_attribute("norviq.agent_id", event.agent_identity.spiffe_id)
                span.set_attribute("norviq.namespace", event.agent_identity.namespace)
                span.set_attribute("norviq.session_id", event.session_id)
            log.debug("nrvq.audit.span_emitted", event_id=event.event_id, code="NRVQ-AUD-6005")
        except Exception as exc:
            log.error("nrvq.audit.span_failed", event_id=event.event_id, error=str(exc), code="NRVQ-AUD-6006")

    async def close(self) -> None:
        """Drain pending emitter tasks for graceful shutdown."""
        if self._tasks:
            log.info("nrvq.audit.draining", pending=len(self._tasks), code="NRVQ-AUD-6007")
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
