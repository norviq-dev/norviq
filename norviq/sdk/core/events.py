# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Event schemas for intercepted tool calls."""

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class AgentIdentity(BaseModel):
    """Agent workload identity from SPIFFE/SPIRE."""

    spiffe_id: str
    namespace: str
    service_account: str = ""
    agent_class: str = ""
    framework: str = ""
    pod_name: str = ""
    cluster_id: str = ""
    # The workload (Deployment) this agent runs as, so a WORKLOAD-tier policy (target deployment:<name>)
    # can match it. Optional — populated by the sidecar/SDK from the Deployment name; when empty, the
    # workload tier simply doesn't apply (we never guess a workload from the pod name).
    workload: str = ""


class ToolCallEvent(BaseModel):
    """Immutable record of a tool call intercepted by Norviq."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    tool_params: dict = Field(default_factory=dict)
    agent_identity: AgentIdentity
    session_id: str = ""
    timestamp_utc: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    framework: str = ""
    call_depth: int = 0
    raw_llm_output: str | None = None

    model_config = {"frozen": True}

    @field_validator("tool_name")
    @classmethod
    def tool_name_not_empty(cls, value: str) -> str:
        """Tool name must not be empty."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("tool_name cannot be empty")
        return stripped
