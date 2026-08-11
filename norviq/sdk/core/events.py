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
    # can match it. Populated by the injected sidecar from NRVQ_WORKLOAD, which the admission webhook
    # derives from the pod's OWNER reference (workloadFromPod, webhook/injector.go) or an explicit
    # norviq.io/workload label — never from the pod name, which would be a guess. When empty the workload
    # tier simply doesn't apply.
    #
    # This comment used to claim it was "populated by the sidecar/SDK" while NOTHING set it: every
    # production AgentIdentity construction left it "", so the whole workload tier was inert even though
    # policies targeting it saved, synced and reported Active.
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
    # Protocol context for calls that arrived over MCP. Optional and empty for every other path, so
    # the SDK and sidecar events are unchanged.
    #
    # This is the PEP's report of what IT observed about the tool's DEFINITION (which server served
    # it, whether the definition matches the one that was approved, what the Gate-A scanner found) —
    # facts that only exist on the MCP surface and that a policy may reasonably want to gate on
    # ("escalate any call to a tool whose definition drifted").
    #
    # TRUST LEVEL, stated plainly: this is exactly as trustworthy as `tool_name` and `tool_params`,
    # which also come from the PEP. It is NOT an identity claim and must never be used as one — a
    # compromised proxy that can forge `mcp.pin_status` can equally forge the tool name, or simply
    # not report the call. Identity stays bound to the caller's credential in the API layer
    # (`scoped_identity`/`attested_namespace`), and the AUTHORITATIVE pin state lives in the control
    # plane (`mcp_tool_pins`), never in this field.
    mcp: dict = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("tool_name")
    @classmethod
    def tool_name_not_empty(cls, value: str) -> str:
        """Tool name must not be empty."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("tool_name cannot be empty")
        return stripped
