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


#: Hard bounds on the PEP's refusal report, matching the API model's own `max_length`.
#:
#: THESE ARE A FAIL-OPEN GUARD, not tidiness. `pep_reason` is built from material the CALLER chose —
#: the MCP schema-violation reason interpolates undeclared argument NAMES verbatim — so without a
#: bound an attacker picks names long enough to exceed the API's cap, the report 422s, and
#: `PolicyEngineClient._post` counts that 4xx on the SAME circuit breaker the real evaluations use.
#: Three reports open it, `sdk_fallback_mode` defaults to "allow", and every subsequent call is
#: forwarded ungoverned. `_handle_http_error`'s own docstring names this shape: "A 4xx an attacker
#: can *provoke* is worse still: influence a tool param into a 422 and the same fallback allows the
#: call." Bounding here makes the 422 unreachable by construction rather than by convention, so no
#: producer of a report can reintroduce it.
PEP_RULE_ID_MAX = 255
PEP_REASON_MAX = 1024


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
    # THE PEP REFUSED THIS CALL ITSELF, BEFORE ANY POLICY RAN.
    #
    # A PEP has controls of its own that are not policy: the MCP firewall's Gate A withholds a tool
    # whose definition scanned as an injection, refuses one whose content hash drifted after approval,
    # rejects arguments the tool's own schema forbids, and drops a call trying to set outbound HTTP
    # headers. Each of those returns before the policy evaluation, so nothing ever reached the control
    # plane: measured live, three Gate-A denials produced exactly ZERO audit rows. The attack was
    # stopped and the console could not show it — no audit row, no attack-graph edge, no compliance
    # credit. By this product's own detection discipline a block with no audit row is indistinguishable
    # from nothing having happened.
    #
    # ONLY "" OR "block". This field can report a REFUSAL and nothing else. It is structurally
    # incapable of loosening a decision (see `apply_pep_denial`): there is no value it can carry that
    # turns a policy block into an allow, which is what keeps a PEP-reported field out of the trust
    # path. `pep_rule_id` names which PEP control refused, so the block is attributable in the audit
    # log rather than arriving anonymous.
    #
    # TRUST LEVEL: identical to `mcp` above and for the same reason — a compromised PEP that could
    # forge "I blocked this" could equally forge the tool name, or simply never call /evaluate at all.
    # Forging it buys an attacker nothing they do not already have; it can only ADD a block record for
    # a call the engine would otherwise never have heard about.
    pep_decision: str = ""
    pep_rule_id: str = Field(default="", max_length=PEP_RULE_ID_MAX)
    pep_reason: str = Field(default="", max_length=PEP_REASON_MAX)

    model_config = {"frozen": True}

    @field_validator("pep_decision")
    @classmethod
    def _pep_decision_may_only_refuse(cls, v: str) -> str:
        """Reject anything but a refusal, at the edge.

        Validating here rather than only at the point of use means the "cannot loosen" property is a
        property of the TYPE: no code path downstream can be handed a `pep_decision` of "allow" to
        mishandle, however it is later refactored.
        """
        if v not in ("", "block"):
            raise ValueError(
                "pep_decision may only be '' or 'block' — a PEP may report that it REFUSED a call, "
                "never that it permitted one, so this field can never loosen a policy decision"
            )
        return v

    @field_validator("tool_name")
    @classmethod
    def tool_name_not_empty(cls, value: str) -> str:
        """Tool name must not be empty."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("tool_name cannot be empty")
        return stripped
