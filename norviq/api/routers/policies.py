# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy CRUD routes."""

from datetime import datetime, timedelta, timezone

import re
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_admin_or_service, scoped_namespace
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()


class PolicyCreate(BaseModel):
    """Policy create/update payload."""

    namespace: str
    agent_class: str
    rego_source: str
    enforcement_mode: str = "block"
    saved_by: str = ""
    priority: int = 100
    policy_name: str | None = None
    target: dict | None = None
    rules: list[str] | None = None


class RollbackRequest(BaseModel):
    """Rollback payload."""

    target_version: int


class ApplyRequest(BaseModel):
    """Policy apply payload."""

    target_type: str
    target_namespace: str
    target_name: str = ""
    target_kind: str = ""
    enforcement_mode: str = "block"


def _infer_target_type(ns: str, agent_class: str) -> str:
    """Classify a loader policy key into the UI's catalog tiers (class | namespace | workload)."""
    if ns == "__cluster__" or agent_class == "__baseline__" or agent_class.startswith("namespace:"):
        return "namespace"
    if ":" in agent_class:  # kind:name workload target, e.g. "deployment:checkout"
        return "workload"
    return "class"


@router.get("/policies")
async def list_policies(
    request: Request, namespace: str = Query("default"), user: dict = Depends(get_current_user)
) -> list[dict]:
    """List policies loaded in memory, scoped to one namespace."""
    namespace = scoped_namespace(user, namespace) or "default"
    rows = []
    loader = request.app.state.loader
    for key, entry in loader._policies.items():
        ns, agent_class = key.split(":", 1)
        if ns != namespace:
            continue
        rows.append(
            {
                "namespace": namespace,
                "agent_class": agent_class,
                "target_type": _infer_target_type(ns, agent_class),
                "current_version": len(loader.get_versions(namespace, agent_class)),
                "rego_length": len(str(entry["rego"])),
                "priority": int(entry.get("priority", 100)),
            }
        )
    log.info("nrvq.api.policies.listed", count=len(rows), code="NRVQ-API-7010")
    return rows


@router.get("/policies/{namespace}/{agent_class}")
async def get_policy(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Get one policy."""
    scoped_namespace(user, namespace)  # 403 if a non-admin reads another namespace's policy
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if rego is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"namespace": namespace, "agent_class": agent_class, "rego_source": rego, "version": len(loader.get_versions(namespace, agent_class))}


@router.post("/policies")
async def create_policy(body: PolicyCreate, request: Request, user: dict = Depends(get_current_user)) -> dict:
    """Create or update a policy (admin, or the webhook controller's service identity)."""
    require_admin_or_service(user)
    validate_policy_create(body)
    agent_class = resolve_policy_key(body)
    # F-37: `__pack__` is a managed scope OWNED by the packs router (materialized from NamespacePack rows). A direct
    # write here is silently wiped the next time any pack is toggled (and reads as 0 coverage) — reject it and point
    # at the real enable path. (`__guardrail__` is intentionally operator-loaded via this endpoint, F-14.)
    if agent_class == "__pack__":
        log.warning("nrvq.api.policy.reserved_scope", namespace=body.namespace, agent_class=agent_class,
                    code="NRVQ-API-7016")
        raise HTTPException(
            status_code=422,
            detail="'__pack__' is a managed scope — enable a sector pack via POST /api/v1/policy-packs/{id}/enable, "
                   "not the generic policy endpoint (a direct write is wiped when packs are re-materialized).",
        )
    version = await request.app.state.loader.create(
        body.namespace,
        agent_class,
        body.rego_source,
        saved_by=body.saved_by,
        priority=body.priority,
        enforcement_mode=body.enforcement_mode,
        policy_name=body.policy_name,
    )
    log.info(
        "nrvq.api.policy.created",
        namespace=body.namespace,
        agent_class=agent_class,
        version=version,
        priority=body.priority,
        policy_name=body.policy_name,
        actor=user.get("sub"),
        actor_role=user.get("role"),
        code="NRVQ-API-7011",
    )
    return {"namespace": body.namespace, "agent_class": agent_class, "version": version, "policy_name": body.policy_name, "priority": body.priority}


def validate_policy_create(body: PolicyCreate) -> None:
    """Validate policy payload for direct API writes."""
    if body.enforcement_mode not in {"block", "audit", "escalate"}:
        raise HTTPException(status_code=422, detail="invalid enforcement_mode")
    rego = body.rego_source or ""
    cleaned = _strip_rego_comments(rego)
    dequoted = _strip_string_literals(cleaned)
    if len(rego) > 65536:
        raise HTTPException(status_code=422, detail="rego_source exceeds max length")
    lines = [line for line in cleaned.splitlines() if line.strip()]
    if len(lines) > 500:
        raise HTTPException(status_code=422, detail="rego_source exceeds line limit")
    # Soft abuse heuristic (OPA uses linear-time RE2, so this is not a ReDoS guard). The shipped
    # comprehensive policy legitimately uses ~11 regex ops after the base64/PII/PCI detection rules,
    # so the cap must admit it with headroom.
    regex_ops = len(re.findall(r"\bregex\.[a-zA-Z0-9_]+\b", dequoted)) + len(re.findall(r"\bre_match\s*\(", dequoted))
    if regex_ops > 25:
        raise HTTPException(status_code=422, detail="too many regex operations")
    if not re.search(r'decision\s*=\s*"(block|escalate)"\s*\{', cleaned):
        raise HTTPException(status_code=422, detail="rego_source must include block or escalate decision")
    enforcement_bodies = re.findall(r'decision\s*=\s*"(?:block|escalate)"\s*\{([^}]*)\}', cleaned, flags=re.DOTALL)
    if enforcement_bodies and all(body.strip() == "false" for body in enforcement_bodies):
        raise HTTPException(status_code=422, detail="rego_source enforcement rule must be reachable")
    lowered = cleaned.lower()
    for required in ("decision", "rule_id", "reason"):
        if not re.search(rf"\b{required}\b", lowered):
            raise HTTPException(status_code=422, detail=f"rego_source must include {required}")


def _strip_rego_comments(rego: str) -> str:
    lines = []
    for line in rego.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _strip_string_literals(rego: str) -> str:
    # Remove quoted strings so keyword scans do not match inside literals.
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', rego)


def resolve_policy_key(body: PolicyCreate) -> str:
    """Resolve a stable loader key for namespace/workload policies."""
    if body.agent_class:
        return body.agent_class
    if body.policy_name:
        return body.policy_name
    target = body.target or {}
    target_kind = str(target.get("kind", "")).strip().lower()
    target_name = str(target.get("name", "")).strip()
    if target_kind and target_name:
        return f"{target_kind}:{target_name}"
    target_namespace = str(target.get("namespace", "")).strip()
    if target_namespace:
        return f"namespace:{target_namespace}"
    raise HTTPException(status_code=422, detail="agent_class or policy_name/target is required")


@router.delete("/policies/{namespace}/{agent_class}")
async def delete_policy(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Delete a policy from in-memory index (admin, or the webhook controller's service identity)."""
    require_admin_or_service(user)
    deleted = await request.app.state.loader.delete(namespace, agent_class)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")
    log.info("nrvq.api.policy.deleted", namespace=namespace, agent_class=agent_class,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7012")
    return {"deleted": True}


@router.get("/policies/{namespace}/{agent_class}/versions")
async def get_versions(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> list[dict]:
    """Return policy version history."""
    scoped_namespace(user, namespace)  # 403 if a non-admin reads another namespace's versions
    versions = request.app.state.loader.get_versions(namespace, agent_class)
    return [{"version": v.version, "saved_by": v.saved_by, "saved_at": v.saved_at.isoformat()} for v in versions]


@router.post("/policies/{namespace}/{agent_class}/rollback")
async def rollback_policy(
    namespace: str,
    agent_class: str,
    body: RollbackRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    """Rollback policy to a previous version."""
    require_admin(user)
    try:
        rego = await request.app.state.loader.rollback(namespace, agent_class, body.target_version)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    log.info("nrvq.api.policy.rolled_back", namespace=namespace, version=body.target_version,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7013")
    return {"rolled_back_to": body.target_version, "rego_length": len(rego)}


async def _validate_rego(evaluator, body: PolicyCreate) -> tuple[bool, list[str], dict | None]:
    """Compile + sample-evaluate the submitted rego via OPA; return (valid, errors, decision)."""
    errors: list[str] = []
    namespace = body.namespace or "default"
    agent_class = body.agent_class or "customer-support"
    sample_input = {
        "tool_name": "search_kb",
        "tool_params": {"query": "dry-run probe"},
        "agent": {
            "spiffe_id": f"spiffe://norviq/ns/{namespace}/sa/{agent_class}",
            "namespace": namespace,
            "agent_class": agent_class,
        },
        "trust_score": 0.8,
        "trust_category": "high",
        "session_id": "dry-run",
        "call_depth": 0,
    }
    decision: dict | None = None
    try:
        # Reuse the same OPA path real evaluation uses: this both compiles the rego and
        # confirms it yields a decision object (a syntax error makes opa exit non-zero → raises).
        # A distinct "dryrun:" key isolates the probe module so it never clobbers the live policy's
        # module in the shared OPA server (server mode).
        dry_key = f"dryrun:{namespace}:{agent_class}"
        decision = await evaluator._evaluate_opa(dry_key, namespace, agent_class, sample_input, body.rego_source)
        if decision.get("rule_id") == "evaluator_invalid_payload":
            errors.append("policy compiled but produced no valid decision object")
    except Exception as exc:
        errors.append(f"opa evaluation failed: {exc}")
    return (not errors), errors, decision


@router.post("/policies/dry-run")
async def dry_run_policy(
    body: PolicyCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Validate the submitted rego (compile + sample decision) and report recent block-rate."""
    _ = user  # authenticated; any role may dry-run (read-only simulation)
    valid, errors, sample_decision = await _validate_rego(request.app.state.evaluator, body)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    base = select(func.count(AuditLogEntry.id)).where(AuditLogEntry.timestamp_utc >= since)
    total = int((await session.scalar(base)) or 0)
    blocked = int((await session.scalar(base.where(AuditLogEntry.decision == "block"))) or 0)
    rate = (blocked / total * 100) if total > 0 else 0
    log.info("nrvq.api.policy.dry_run", valid=valid, total=total, blocked=blocked, code="NRVQ-API-7014")
    return {
        "valid": valid,
        "errors": errors,
        "sample_decision": sample_decision,
        "total_records_checked": total,
        "would_block": blocked,
        "would_allow": total - blocked,
        "block_rate_pct": round(rate, 2),
        "time_range": "last 24 hours",
        "recommendation": (
            "Invalid rego — fix errors before deploying"
            if not valid
            else "Safe to deploy"
            if rate < 5
            else "Review before deploying — high block rate"
        ),
    }


@router.post("/policies/{namespace}/{agent_class}/apply")
async def apply_policy(
    namespace: str,
    agent_class: str,
    body: ApplyRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> dict:
    """Apply a saved policy to a target scope."""
    require_admin(user)
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if not rego:
        raise HTTPException(status_code=404, detail="Policy not found. Save it first.")
    entry = loader.get_entry(namespace, agent_class) or {}
    loader._evaluator.load_policy(
        body.target_namespace,
        agent_class,
        rego,
        priority=int(entry.get("priority", 100)),
    )
    log.info(
        "nrvq.api.policy.applied",
        namespace=namespace,
        agent_class=agent_class,
        target_type=body.target_type,
        target_namespace=body.target_namespace,
        mode=body.enforcement_mode,
        actor=user.get("sub"),
        actor_role=user.get("role"),
        code="NRVQ-API-7015",
    )
    return {
        "applied": True,
        "policy": f"{namespace}/{agent_class}",
        "target_type": body.target_type,
        "target_namespace": body.target_namespace,
        "target_name": body.target_name,
        "enforcement_mode": body.enforcement_mode,
    }
