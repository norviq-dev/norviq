# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Span helpers for tool-call tracing."""

from __future__ import annotations

import structlog
from opentelemetry import trace
from opentelemetry.trace import Span

log = structlog.get_logger()
tracer = trace.get_tracer("norviq")


def create_tool_call_span(tool_name: str, namespace: str, agent_class: str) -> Span:
    """Create and return a tool call span."""
    try:
        return tracer.start_span(
            name="norviq.tool_call",
            attributes={
                "norviq.tool_name": tool_name,
                "norviq.namespace": namespace,
                "norviq.agent_class": agent_class,
            },
        )
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.span_failed", error=str(exc), code="NRVQ-TEL-12006")
        return trace.NonRecordingSpan(trace.INVALID_SPAN_CONTEXT)


def enrich_span(
    span: Span,
    decision: str,
    trust_score: float,
    rule_id: str,
    latency_ms: float,
    cache_hit: bool,
    trust_signals: dict | None = None,
) -> None:
    """Add evaluation attributes to an existing span."""
    span.set_attribute("norviq.decision", decision)
    span.set_attribute("norviq.trust_score", trust_score)
    span.set_attribute("norviq.rule_id", rule_id)
    span.set_attribute("norviq.latency_ms", latency_ms)
    span.set_attribute("norviq.cache_hit", cache_hit)
    if trust_signals is None:
        return
    for key, value in trust_signals.items():
        span.set_attribute(f"norviq.trust.signal.{key}", value)


def create_chain_span(parent_span: Span, agent_id: str, depth: int) -> Span:
    """Create a child span for agent delegation chains."""
    context = trace.set_span_in_context(parent_span)
    return tracer.start_span(
        name="norviq.agent_delegation",
        context=context,
        attributes={"norviq.agent_id": agent_id, "norviq.chain_depth": depth},
    )
