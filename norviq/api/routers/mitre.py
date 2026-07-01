# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""MITRE ATLAS coverage routes — technique → policy mapping cross-referenced with loaded rego."""

import json
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()

_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}


async def _activity_by_rule(session: AsyncSession, namespace: str, range_token: str) -> dict[str, dict[str, int]]:
    """F-39: per-rule_id observed-attempt + blocked counts from audit (best-effort; {} if the DB is unavailable)."""
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range_token, 24))
    stmt = (
        select(AuditLogEntry.rule_id, AuditLogEntry.decision, func.count(AuditLogEntry.id))
        .where(AuditLogEntry.timestamp_utc >= since, AuditLogEntry.namespace == namespace)
        .group_by(AuditLogEntry.rule_id, AuditLogEntry.decision)
    )
    by_rule: dict[str, dict[str, int]] = {}
    try:
        for rid, decision, count in (await session.execute(stmt)).all():
            entry = by_rule.setdefault(str(rid), {"observed": 0, "blocked": 0})
            entry["observed"] += int(count)
            if decision in ("block", "escalate"):
                entry["blocked"] += int(count)
    except Exception as exc:  # DB unavailable -> mapping still returns, activity just shows 0
        log.warning("nrvq.api.mitre.activity_unavailable", error=str(exc), code="NRVQ-API-7071")
    return by_rule

_CANDIDATE_PATHS = [
    Path(__file__).resolve().parents[3] / "policies" / "mitre_mapping.json",
    Path.cwd() / "policies" / "mitre_mapping.json",
]


@lru_cache(maxsize=1)
def _load_mapping() -> dict:
    """Load the ATLAS technique→policies mapping from disk (cached)."""
    for path in _CANDIDATE_PATHS:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    log.warning("nrvq.api.mitre.mapping_missing", code="NRVQ-API-7070-ERR")
    return {}


@router.get("/mitre/coverage")
async def mitre_coverage(
    request: Request,
    namespace: str = Query("default"),
    range: str = Query("24h"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Per-ATLAS-technique coverage: a technique is covered when one of its mapped policy rules appears in the rego
    loaded for this namespace (or the cluster baseline). F-39: each technique is also overlaid with observed-attempt
    + blocked counts from audit over `range`, so the page reflects real activity, not just the static mapping."""
    _ = user
    mapping = _load_mapping()
    loader = getattr(request.app.state, "loader", None)
    rego_blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if ns in (namespace, "__cluster__"):
                rego_blob += str(entry.get("rego", ""))

    by_rule = await _activity_by_rule(session, namespace, range)

    techniques = []
    for technique_id, info in mapping.items():
        policies = list(info.get("policies", []))
        covered_policies = [p for p in policies if p and p in rego_blob]
        observed = sum(by_rule.get(p, {}).get("observed", 0) for p in policies)
        blocked = sum(by_rule.get(p, {}).get("blocked", 0) for p in policies)
        techniques.append(
            {
                "technique_id": technique_id,
                "name": info.get("name", ""),
                "policies": policies,
                "covered_policies": covered_policies,
                "covered": len(covered_policies) > 0,
                "observed": observed,   # F-39
                "blocked": blocked,     # F-39
            }
        )
    techniques.sort(key=lambda t: t["technique_id"])
    covered = sum(1 for t in techniques if t["covered"])
    # Totals count DISTINCT audit activity (by rule_id) so a rule mapped to several techniques isn't double-counted
    # in the headline (per-technique counts above still attribute the activity to each technique it maps to).
    total_observed = sum(v["observed"] for v in by_rule.values())
    total_blocked = sum(v["blocked"] for v in by_rule.values())
    log.info("nrvq.api.mitre.coverage", namespace=namespace, covered=covered, total=len(techniques),
             observed=total_observed, blocked=total_blocked, code="NRVQ-API-7070")
    return {"namespace": namespace, "range": range, "covered": covered, "total": len(techniques),
            "observed": total_observed, "blocked": total_blocked, "techniques": techniques}
