# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for AuditRecord schema."""

from __future__ import annotations

from datetime import timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from norviq.sdk.core.audit import AuditRecord
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def make_event() -> ToolCallEvent:
    """Build a valid ToolCallEvent for audit tests."""
    return ToolCallEvent(
        tool_name="search",
        tool_params={"query": "alpha"},
        session_id="sess-1",
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://cluster/ns/default/sa/agent-1",
            namespace="default",
            agent_class="planner",
        ),
    )


def make_decision() -> PolicyDecision:
    """Build a valid PolicyDecision for audit tests."""
    return PolicyDecision(
        decision="audit",
        policy_id="P-1",
        policy_version=3,
        rule_id="R-7",
        reason="sampled",
        trust_score=0.91,
        latency_ms=12.5,
    )


def test_audit_record_creates_with_required_fields() -> None:
    """AuditRecord should be created with required fields."""
    record = AuditRecord(
        event_id="evt-1", tool_name="search", decision="allow", agent_id="spiffe://a"
    )
    assert record.event_id == "evt-1"
    assert record.tool_name == "search"
    assert record.decision == "allow"
    assert record.agent_id == "spiffe://a"


def test_record_id_is_auto_generated_uuid() -> None:
    """record_id should default to a UUID v4 string."""
    record = AuditRecord(
        event_id="evt-1", tool_name="search", decision="allow", agent_id="spiffe://a"
    )
    parsed = UUID(record.record_id)
    assert parsed.version == 4


def test_from_event_and_decision_maps_all_fields() -> None:
    """Factory should map all event and decision fields."""
    event = make_event()
    decision = make_decision()
    record = AuditRecord.from_event_and_decision(event, decision)
    assert record.event_id == event.event_id
    assert record.tool_name == "search"
    assert record.decision == "audit"
    assert record.agent_id == event.agent_identity.spiffe_id
    assert record.agent_class == "planner"
    assert record.namespace == "default"
    assert record.policy_id == "P-1"
    assert record.policy_version == 3
    assert record.rule_id == "R-7"
    assert record.reason == "sampled"
    assert record.session_id == "sess-1"
    assert record.trust_score == 0.91
    assert record.latency_ms == 12.5


def test_payload_defaults_to_none() -> None:
    """Factory should default payload to None."""
    record = AuditRecord.from_event_and_decision(make_event(), make_decision())
    assert record.payload is None


def test_payload_is_set_when_provided() -> None:
    """Factory should preserve provided payload."""
    payload = {"query": "alpha"}
    record = AuditRecord.from_event_and_decision(make_event(), make_decision(), payload)
    assert record.payload == payload


def test_model_is_frozen_after_creation() -> None:
    """AuditRecord should reject mutation after creation."""
    record = AuditRecord.from_event_and_decision(make_event(), make_decision())
    with pytest.raises(ValidationError):
        record.reason = "mutated"


def test_model_dump_works() -> None:
    """model_dump should serialize expected fields."""
    record = AuditRecord.from_event_and_decision(make_event(), make_decision())
    dumped = record.model_dump()
    assert dumped["tool_name"] == "search"
    assert dumped["decision"] == "audit"
    assert dumped["payload"] is None
    assert record.timestamp_utc.tzinfo == timezone.utc
