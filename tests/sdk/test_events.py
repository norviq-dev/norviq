"""Tests for ToolCallEvent and AgentIdentity schemas."""

from __future__ import annotations

import json
from datetime import timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def make_identity() -> AgentIdentity:
    """Build a minimal AgentIdentity instance."""
    return AgentIdentity(
        spiffe_id="spiffe://cluster/ns/default/sa/agent-1",
        namespace="default",
    )


def make_event(tool_name: str = "search") -> ToolCallEvent:
    """Build a valid ToolCallEvent with required fields."""
    return ToolCallEvent(tool_name=tool_name, agent_identity=make_identity())


def test_tool_call_event_creates_with_required_fields_only() -> None:
    """ToolCallEvent should be created with required fields."""
    event = make_event()
    assert event.tool_name == "search"
    assert event.agent_identity.namespace == "default"
    assert event.tool_params == {}


def test_event_id_is_auto_generated_uuid() -> None:
    """event_id should default to a UUID v4 string."""
    event = make_event()
    parsed = UUID(event.event_id)
    assert parsed.version == 4


def test_timestamp_utc_is_auto_generated_and_timezone_aware() -> None:
    """timestamp_utc should default to an aware UTC datetime."""
    event = make_event()
    assert event.timestamp_utc.tzinfo is not None
    assert event.timestamp_utc.tzinfo == timezone.utc


@pytest.mark.parametrize("tool_name", ["", "   "])
def test_tool_name_validation_rejects_empty_values(tool_name: str) -> None:
    """tool_name should reject empty and whitespace-only values."""
    with pytest.raises(ValidationError):
        make_event(tool_name=tool_name)


def test_model_is_frozen_after_creation() -> None:
    """ToolCallEvent should be immutable after initialization."""
    event = make_event()
    with pytest.raises(ValidationError):
        event.tool_name = "mutated"


def test_model_dump_and_json_work() -> None:
    """model_dump and model_dump_json should serialize successfully."""
    event = make_event()
    dumped = event.model_dump()
    assert dumped["tool_name"] == "search"
    assert isinstance(dumped["agent_identity"], dict)
    dumped_json = event.model_dump_json()
    loaded = json.loads(dumped_json)
    assert loaded["tool_name"] == "search"
    assert loaded["agent_identity"]["namespace"] == "default"


def test_agent_identity_creates_with_required_fields_only() -> None:
    """AgentIdentity should be valid with only required fields."""
    identity = make_identity()
    assert identity.spiffe_id.startswith("spiffe://")
    assert identity.namespace == "default"
    assert identity.service_account == ""
