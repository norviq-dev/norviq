# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API routes for red-team simulation."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request

from norviq.api.auth import get_current_user
from norviq.redteam.attacks import ATTACKS, get_attack_by_id
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

log = structlog.get_logger()
router = APIRouter()
REPORTS: dict[str, dict] = {}


@router.post("/redteam/run")
async def run_attack(attack_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    """Run one red-team attack against the in-process evaluator."""
    _ = user
    attack = get_attack_by_id(attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")
    event = _build_event(attack.id, attack.tool_name, attack.tool_params, "redteam-test", "default", f"redteam-{attack.id}")
    decision = await request.app.state.evaluator.evaluate(event)
    passed = decision.decision == attack.expected_decision
    return {
        "attack_id": attack.id,
        "attack_name": attack.name,
        "expected": attack.expected_decision,
        "actual": decision.decision,
        "rule_id": decision.rule_id,
        "passed": passed,
        "trust_score": decision.trust_score,
        "latency_ms": decision.latency_ms,
    }


@router.post("/redteam/suite")
async def run_suite(
    request: Request,
    target_agent: str = "redteam-test",
    target_namespace: str = "default",
    user: dict = Depends(get_current_user),
) -> dict:
    """Run the full red-team suite against the in-process evaluator."""
    _ = user
    results = []
    for attack in ATTACKS:
        event = _build_event(attack.id, attack.tool_name, attack.tool_params, target_agent, target_namespace, target_agent)
        try:
            decision = await request.app.state.evaluator.evaluate(event)
            results.append(_result_row(attack, decision.decision, decision.rule_id, decision.latency_ms))
        except Exception as exc:
            results.append(_error_row(attack, str(exc)))
    passed = sum(1 for item in results if item.get("passed"))
    report = {"total": len(results), "passed": passed, "failed": len(results) - passed, "pass_rate": round(passed / len(results) * 100, 1) if results else 0, "results": results}
    run_id = str(uuid4())
    REPORTS[run_id] = {"run_id": run_id, **report}
    return REPORTS[run_id]


@router.get("/redteam/catalog")
async def get_catalog(user: dict = Depends(get_current_user)) -> list[dict]:
    """Return red-team attack catalog."""
    _ = user
    log.info("nrvq.redteam.catalog_loaded", total=len(ATTACKS), code="NRVQ-RED-13004")
    return [asdict(attack) for attack in ATTACKS]


@router.get("/redteam/report/{run_id}")
async def get_report(run_id: str, user: dict = Depends(get_current_user)) -> dict:
    """Fetch previously generated suite report."""
    _ = user
    if run_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    return REPORTS[run_id]


def _build_event(
    attack_id: str,
    tool_name: str,
    tool_params: dict[str, Any],
    target_agent: str,
    target_namespace: str,
    service_account: str,
) -> ToolCallEvent:
    """Build tool-call event for red-team evaluator tests."""
    return ToolCallEvent(
        tool_name=tool_name,
        tool_params=tool_params,
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{target_namespace}/sa/{service_account}",
            namespace=target_namespace,
            agent_class=target_agent,
        ),
        session_id=f"redteam-{attack_id}",
    )


def _result_row(attack: Any, actual: str, rule_id: str, latency_ms: float) -> dict[str, Any]:
    """Build one successful suite row."""
    return {
        "attack_id": attack.id,
        "attack_name": attack.name,
        "category": attack.category.value,
        "expected": attack.expected_decision,
        "actual": actual,
        "rule_id": rule_id,
        "passed": actual == attack.expected_decision,
        "latency_ms": latency_ms,
    }


def _error_row(attack: Any, error: str) -> dict[str, Any]:
    """Build one failed suite row."""
    return {
        "attack_id": attack.id,
        "attack_name": attack.name,
        "category": attack.category.value,
        "expected": attack.expected_decision,
        "actual": "error",
        "rule_id": "",
        "passed": False,
        "error": error,
    }
