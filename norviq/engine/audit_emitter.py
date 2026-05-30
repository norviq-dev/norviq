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

    async def init(self) -> None:
        """Initialize OTel tracer with OTLP exporter."""
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

    async def _write_db(self, record: AuditRecord) -> None:
        """Persist an audit record into PostgreSQL."""
        session = None
        try:
            session = await get_session()
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
            if session is not None:
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
