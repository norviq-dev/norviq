# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Telemetry span helper tests."""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from norviq.telemetry.spans import create_chain_span, create_tool_call_span, enrich_span


def test_create_tool_call_span_and_enrich() -> None:
    """Create a tool-call span and attach decision attributes."""
    trace.set_tracer_provider(TracerProvider())
    span = create_tool_call_span("search", "tenant-a", "support")
    enrich_span(span, "allow", 0.9, "default_allow", 8.2, True, {"violation_rate": 0.1})
    assert span.attributes["norviq.tool_name"] == "search"
    assert span.attributes["norviq.decision"] == "allow"
    assert span.attributes["norviq.rule_id"] == "default_allow"


def test_create_chain_span_has_parent() -> None:
    """Create child chain span using parent context."""
    trace.set_tracer_provider(TracerProvider())
    parent = create_tool_call_span("search", "tenant-a", "support")
    child = create_chain_span(parent, "agent-1", 2)
    assert child.parent is not None
    assert child.attributes["norviq.chain_depth"] == 2
