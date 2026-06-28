# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluation route for policy decisions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from norviq.api.audit_hub import audit_record
from norviq.api.auth import get_current_user
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
    _ = user
    event = ToolCallEvent.model_validate(payload.model_dump(exclude={"trust_score"}))
    decision: PolicyDecision = await request.app.state.evaluator.evaluate(event)
    # Fire-and-forget audit emission (DB write + OTel span). emit() schedules its own
    # background task, holds the reference, and swallows write errors — so this never
    # blocks the response or fails the tool call (hot-path safe). The audit record carries
    # event.agent_identity.namespace, so audit data is tenant-scoped like everything else.
    emitter = getattr(request.app.state, "emitter", None)
    if emitter is not None:
        emitter.emit(event, decision)
    # Fan the decision out to live /ws/audit subscribers (in-process, non-blocking).
    hub = getattr(request.app.state, "audit_hub", None)
    if hub is not None:
        hub.publish(audit_record(event, decision))
    return EvaluateResponse(decision=decision.decision, rule_id=decision.rule_id, trust_score=decision.trust_score)
