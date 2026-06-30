# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API routes for red-team simulation."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import AgentRegistryEntry
from norviq.api.db.session import get_session
from norviq.redteam.attacks import ATTACKS, get_attack_by_id
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

log = structlog.get_logger()
router = APIRouter()
REPORTS: dict[str, dict] = {}

# F-44: when no real agent class is seeded yet, fall back to this synthetic identity so the suite still runs.
_FALLBACK_TARGET = "redteam-test"


async def _seeded_classes(session: AsyncSession, namespace: str) -> list[str]:
    """F-44: distinct real agent classes seeded in a namespace (reserved __scopes__ excluded)."""
    rows = await session.execute(
        select(AgentRegistryEntry.agent_class)
        .where(AgentRegistryEntry.namespace == namespace)
        .distinct()
    )
    return sorted(c for c in rows.scalars().all() if c and not c.startswith("__"))


@router.post("/redteam/run")
async def run_attack(
    attack_id: str,
    request: Request,
    target_agent: str = _FALLBACK_TARGET,
    target_namespace: str = "default",
    user: dict = Depends(get_current_user),
) -> dict:
    """Run one red-team attack against the in-process evaluator, as a chosen target identity (F-44)."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    attack = get_attack_by_id(attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")
    event = _build_event(attack, target_agent, target_namespace)
    decision = await request.app.state.evaluator.evaluate(event)
    row = _result_row(attack, target_agent, target_namespace, decision.decision, decision.rule_id, decision.latency_ms)
    return {**row, "trust_score": decision.trust_score}


@router.post("/redteam/suite")
async def run_suite(
    request: Request,
    target_agent: str | None = None,
    target_namespace: str = "default",
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Run the full red-team suite. F-44: target-aware — evaluates every attack against each seeded agent class
    in the namespace (or one explicit class), so the report reflects the deployed sector posture, not a synthetic
    identity. Each result row carries the agent_class/namespace it was evaluated against."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    if target_agent:
        targets = [target_agent]
    else:
        targets = await _seeded_classes(session, target_namespace) or [_FALLBACK_TARGET]
    results = []
    for agent_class in targets:
        for attack in ATTACKS:
            event = _build_event(attack, agent_class, target_namespace)
            try:
                decision = await request.app.state.evaluator.evaluate(event)
                results.append(_result_row(attack, agent_class, target_namespace, decision.decision, decision.rule_id, decision.latency_ms))
            except Exception as exc:
                results.append(_error_row(attack, agent_class, target_namespace, str(exc)))
    passed = sum(1 for item in results if item.get("passed"))
    run_id = str(uuid4())
    REPORTS[run_id] = {
        "run_id": run_id,
        "namespace": target_namespace,
        "targets": targets,
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "pass_rate": round(passed / len(results) * 100, 1) if results else 0,
        "results": results,
    }
    log.info("nrvq.redteam.suite_run", namespace=target_namespace, targets=targets,
             total=len(results), passed=passed, code="NRVQ-RED-13006")
    return REPORTS[run_id]


@router.get("/redteam/targets")
async def list_targets(
    namespace: str = "default",
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """F-44: the real agent classes seeded in a namespace, for the Policy-Tester/red-team target selector."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    return {"namespace": namespace, "targets": await _seeded_classes(session, namespace)}


@router.get("/redteam/catalog")
async def get_catalog(user: dict = Depends(get_current_user)) -> list[dict]:
    """Return red-team attack catalog."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    log.info("nrvq.redteam.catalog_loaded", total=len(ATTACKS), code="NRVQ-RED-13004")
    return [asdict(attack) for attack in ATTACKS]


@router.get("/redteam/report/{run_id}")
async def get_report(run_id: str, user: dict = Depends(get_current_user)) -> dict:
    """Fetch previously generated suite report."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    if run_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    return REPORTS[run_id]


def _build_event(attack: Any, target_agent: str, target_namespace: str) -> ToolCallEvent:
    """Build a tool-call event for one attack as a target identity. F-44: each class gets its own SVID so it picks
    up its own trust history; F-45: thread a chained-call `depth` param into the event's call_depth so chain-depth
    rules can fire (the engine reads input.call_depth, not the tool param)."""
    depth = attack.tool_params.get("depth")
    return ToolCallEvent(
        tool_name=attack.tool_name,
        tool_params=attack.tool_params,
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{target_namespace}/sa/{target_agent}",
            namespace=target_namespace,
            agent_class=target_agent,
        ),
        session_id=f"redteam-{attack.id}",
        call_depth=int(depth) if isinstance(depth, (int, str)) and str(depth).isdigit() else 0,
    )


def _result_row(attack: Any, agent_class: str, namespace: str, actual: str, rule_id: str, latency_ms: float) -> dict[str, Any]:
    """Build one successful suite row (F-44: carries the evaluated identity)."""
    return {
        "attack_id": attack.id,
        "attack_name": attack.name,
        "category": attack.category.value,
        "agent_class": agent_class,
        "namespace": namespace,
        "expected": attack.expected_decision,
        "actual": actual,
        "rule_id": rule_id,
        "passed": actual == attack.expected_decision,
        "latency_ms": latency_ms,
    }


def _error_row(attack: Any, agent_class: str, namespace: str, error: str) -> dict[str, Any]:
    """Build one failed suite row."""
    return {
        "attack_id": attack.id,
        "attack_name": attack.name,
        "category": attack.category.value,
        "agent_class": agent_class,
        "namespace": namespace,
        "expected": attack.expected_decision,
        "actual": "error",
        "rule_id": "",
        "passed": False,
        "error": error,
    }
