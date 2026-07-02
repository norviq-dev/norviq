# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluation route for policy decisions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from norviq.api.audit_hub import audit_record
from norviq.api.auth import get_current_user, scoped_namespace
from norviq.config import settings
from norviq.engine.masking import mask_params
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

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
    # F-01: bind the evaluated namespace to the CALLER, not the client-supplied body. The agent's own
    # workload/service credential (sidecar/SDK/break-glass, role=service) evaluates within its scope and is
    # trusted here (the workload path); a HUMAN token (admin/viewer) must be authorized for the namespace it
    # asks to evaluate — admin = any, non-admin → 403 on mismatch (matches every other tenant-scoped route).
    if str(user.get("role", "")).lower() != "service":
        scoped_namespace(user, (payload.agent_identity or {}).get("namespace"))
    # OBS-1: a malformed agent_identity (e.g. missing the required spiffe_id) is a client error — return
    # 422, not a raw 500 from the downstream model validation.
    try:
        event = ToolCallEvent.model_validate(payload.model_dump(exclude={"trust_score"}))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"invalid agent_identity / tool call: {exc.errors()}") from exc
    decision: PolicyDecision = await request.app.state.evaluator.evaluate(event)
    # Fire-and-forget audit emission (DB write + OTel span). emit() schedules its own
    # background task, holds the reference, and swallows write errors — so this never
    # blocks the response or fails the tool call (hot-path safe). The audit record carries
    # event.agent_identity.namespace, so audit data is tenant-scoped like everything else.
    emitter = getattr(request.app.state, "emitter", None)
    if emitter is not None:
        # F-19 (opt-in, default OFF): persist MASKED tool_params for event reconstruction (PCI 10.3) without
        # storing raw PAN/PII. Off by default so the audit payload is unchanged for everyone who hasn't opted in.
        audit_payload = None
        if settings.audit_capture_masked_params:
            audit_payload = {"masked_params": mask_params(event.tool_params)}
        emitter.emit(event, decision, payload=audit_payload)
    # Fan the decision out to live /ws/audit subscribers (in-process, non-blocking).
    hub = getattr(request.app.state, "audit_hub", None)
    if hub is not None:
        hub.publish(audit_record(event, decision))
    return EvaluateResponse(decision=decision.decision, rule_id=decision.rule_id, trust_score=decision.trust_score)
