# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluation route for policy decisions."""

from __future__ import annotations

from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from norviq.api.audit_hub import audit_record
from norviq.api.auth import attested_namespace, get_current_user, scoped_identity, scoped_namespace
from norviq.config import settings
from norviq.engine.capability import Verb, classify_tool
from norviq.engine.masking import mask_params
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent
from norviq.telemetry.metrics import record_path_phase

router = APIRouter()


class EvaluateRequest(BaseModel):
    """Payload for a tool evaluation call."""

    tool_name: str
    tool_params: dict = Field(default_factory=dict)
    agent_identity: dict
    session_id: str = ""
    trust_score: float = 0.0
    call_depth: int = 0
    framework: str = "redteam"
    # Optional MCP protocol context (server id, transport, pin status, Gate-A scan severity). Absent
    # for every non-MCP caller, so this is additive: an existing sidecar/SDK body is unchanged and
    # every existing policy still sees exactly the input document it saw before.
    mcp: dict = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    """Flattened evaluation result payload."""

    decision: str
    rule_id: str
    trust_score: float


@router.post("/evaluate")
async def evaluate_tool_call(
    payload: EvaluateRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> EvaluateResponse:
    """Evaluate one tool call against active policies."""
    # Handler-level attribution. The evaluator reports its own phases and the outermost ASGI timer
    # reports the total, but between them sat ~32ms that NOTHING measured: FastAPI routing and
    # dependency resolution, request/response model validation, and the post-decision audit work. The
    # phases below close that, and `route_total` vs the outer `total_asgi` is the framework's own cost
    # — the part no application-level timer can see.
    _t_handler = perf_counter()
    # Bind the evaluated namespace to the CALLER, not the client-supplied body. scoped_namespace()
    # already gives a service credential (sidecar/SDK/break-glass) the trusted hot path: an EMPTY namespace
    # claim on a service token is treated as authorized for any requested namespace, while a NON-empty
    # claim must match. A HUMAN token (admin/viewer) must be authorized for the namespace it asks to
    # evaluate — admin = any, non-admin → 403 on mismatch (matches every other tenant-scoped route).
    # Calling this unconditionally (instead of skipping it for role=service) closes a cross-tenant hole
    # where a sidecar token scoped to namespace A could evaluate as namespace B.
    effective_ns = scoped_namespace(user, (payload.agent_identity or {}).get("namespace"))
    # ...and resolve the SIBLING identity fields in the same dict from the credential too. `agent_class`
    # selects which Rego program is enforced, `spiffe_id` keys the trust score + the agent_frozen:
    # kill-switch, and `workload` pulls in the workload tier — so binding only `namespace` left an
    # intra-namespace escalation. Note this REWRITES the identity rather than just validating it: an
    # omitted/empty field is as powerful as a substituted one (dropping agent_class silently falls back
    # to the looser __baseline__), so the credential's value is written back over the body's.
    identity = scoped_identity(user, payload.agent_identity)
    # Finally, prefer the namespace ATTESTED by the caller's own SVID over both the body and an absent
    # claim. scoped_namespace above still lets a machine principal with an EMPTY namespace claim take the
    # body's namespace — necessary latitude for the hot path, but it means an unbound service token could
    # evaluate as any tenant. A Norviq SVID encodes its namespace (spiffe://norviq/ns/<ns>/sa/<sa>) and
    # spiffe_id is already credential-bound, so the workload names its own namespace and the body cannot
    # choose it. Returns "" when nothing is attestable, leaving the prior behaviour exactly as it was.
    attested_ns = attested_namespace(user, (payload.agent_identity or {}).get("namespace"))
    if attested_ns:
        effective_ns = attested_ns
    if effective_ns:
        identity["namespace"] = effective_ns
    # A malformed agent_identity (e.g. missing the required spiffe_id) is a client error — return
    # 422, not a raw 500 from the downstream model validation.
    try:
        event = ToolCallEvent.model_validate(
            {**payload.model_dump(exclude={"trust_score"}), "agent_identity": identity}
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"invalid agent_identity / tool call: {exc.errors()}") from exc
    record_path_phase("api", "route_identity", (perf_counter() - _t_handler) * 1000.0)
    _t = perf_counter()
    decision: PolicyDecision = await request.app.state.evaluator.evaluate(event)
    record_path_phase("api", "route_evaluate", (perf_counter() - _t) * 1000.0)
    _t = perf_counter()
    # Fire-and-forget audit emission (DB write + OTel span). emit() schedules its own
    # background task, holds the reference, and swallows write errors — so this never
    # blocks the response or fails the tool call (hot-path safe). The audit record carries
    # event.agent_identity.namespace, so audit data is tenant-scoped like everything else.
    emitter = getattr(request.app.state, "emitter", None)
    if emitter is not None:
        # Opt-in (default OFF): persist MASKED tool_params for event reconstruction (PCI 10.3) without
        # storing raw PAN/PII. Off by default so the audit payload is unchanged for everyone who hasn't opted in.
        audit_payload = None
        if settings.audit_capture_masked_params:
            audit_payload = {"masked_params": mask_params(event.tool_params)}
        # Verb OBSERVATION phase (tool-classification lifecycle): when the tool NAME is unclassifiable
        # but its PARAMS reveal the operation (a SQL body, a destination field), record that verb as
        # evidence on the audit row — /threats/tool-verbs aggregates it so an admin can PROMOTE the tool
        # to a defined verb. Pure in-memory token/dict classification — hot-path safe, no I/O.
        # MCP provenance on the audit row: which server served this tool, over which transport, and
        # what Gate A knew about its definition at the time. Without it an operator reading the audit
        # log sees `send_email  block` with no way to tell WHICH of four MCP integrations it came
        # from — the first question anyone asks when a chatbot has several. Stored under its own key
        # so it can never collide with masked_params or the verb-observation fields below.
        if event.mcp:
            audit_payload = {**(audit_payload or {}), "mcp": event.mcp}
        name_verb, _ = classify_tool(event.tool_name)
        if name_verb is Verb.UNKNOWN:
            param_verb, param_risk = classify_tool(event.tool_name, event.tool_params)
            if param_verb is not Verb.UNKNOWN:
                audit_payload = {
                    **(audit_payload or {}),
                    "op": param_verb.value,
                    "op_risk": param_risk.value if param_risk else None,
                    "op_src": "params",
                }
        emitter.emit(event, decision, payload=audit_payload)
    record_path_phase("api", "route_audit", (perf_counter() - _t) * 1000.0)
    _t = perf_counter()
    # Fan the decision out to live /ws/audit subscribers (in-process, non-blocking).
    hub = getattr(request.app.state, "audit_hub", None)
    if hub is not None:
        hub.publish(audit_record(event, decision))
    record_path_phase("api", "route_fanout", (perf_counter() - _t) * 1000.0)
    response = EvaluateResponse(
        decision=decision.decision, rule_id=decision.rule_id, trust_score=decision.trust_score
    )
    # Recorded LAST so it covers the whole handler. FastAPI still has to validate and serialise this
    # response afterwards, which is precisely why `total_asgi - route_total` is the number to read
    # rather than assuming the handler is the request.
    record_path_phase("api", "route_total", (perf_counter() - _t_handler) * 1000.0)
    return response
