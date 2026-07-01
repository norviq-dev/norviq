# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Coverage-by-category route (F046) — policy coverage across risk categories.

Replaces the console's fabricated category scores (magic coefficients on the block rate). A category's
`score` is **rules-present**: how many of its mapped rule_ids appear in the rego actually loaded for the
namespace (or the cluster baseline). F-44/F-45: "present" is NOT "effective" — a rule can be loaded yet never
fire — so this route ALSO overlays real audit efficacy (`observed`/`blocked` per category from traffic) and an
`effective` flag, and the response declares `basis: "rules_present"` so the number can't be read as a
protection guarantee. The category -> rule_id taxonomy lives in policies/category_mapping.json (a documented
artifact). True attack efficacy is proven by the red-team suite (/api/v1/redteam/suite), not this metric.
"""

import json
from functools import lru_cache
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.routers.mitre import _activity_by_rule

log = structlog.get_logger()
router = APIRouter()

_CANDIDATE_PATHS = [
    Path(__file__).resolve().parents[3] / "policies" / "category_mapping.json",
    Path.cwd() / "policies" / "category_mapping.json",
]


@lru_cache(maxsize=1)
def _load_mapping() -> dict[str, list[str]]:
    """Load the risk-category -> rule_id taxonomy from disk (cached); '_comment' keys are ignored."""
    for path in _CANDIDATE_PATHS:
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            return {k: v for k, v in raw.items() if isinstance(v, list)}
    log.warning("nrvq.api.coverage.mapping_missing", code="NRVQ-API-7081-ERR")
    return {}


@router.get("/coverage-by-category")
async def coverage_by_category(
    request: Request,
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Per risk category: `score` = how many mapped rules are PRESENT in this namespace's loaded rego (not a
    proof of efficacy); `observed`/`blocked` = real audit activity for those rules; `effective` = at least one
    rule in the category has actually blocked/escalated traffic. F-44/F-45: present != effective."""
    _ = user
    mapping = _load_mapping()
    loader = getattr(request.app.state, "loader", None)
    rego_blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if ns in (namespace, "__cluster__"):
                rego_blob += str(entry.get("rego", ""))

    activity = await _activity_by_rule(session, namespace, "30d")  # best-effort; {} if DB down
    categories = []
    total_covered = 0
    total_rules = 0
    for category, rules in mapping.items():
        covered = [r for r in rules if r and r in rego_blob]
        score = round(len(covered) / len(rules) * 100) if rules else 0
        observed = sum(activity.get(r, {}).get("observed", 0) for r in rules)
        blocked = sum(activity.get(r, {}).get("blocked", 0) for r in rules)
        categories.append({
            "category": category, "covered": len(covered), "total": len(rules), "score": score,
            "observed": observed, "blocked": blocked, "effective": blocked > 0,
        })
        total_covered += len(covered)
        total_rules += len(rules)

    coverage_pct = round(total_covered / total_rules * 100) if total_rules else 0
    log.info(
        "nrvq.api.coverage.served",
        namespace=namespace,
        coverage_pct=coverage_pct,
        categories=len(categories),
        code="NRVQ-API-7081",
    )
    # basis: the score is rules-present (loaded), not efficacy — efficacy is the audit overlay + the red-team suite.
    return {"namespace": namespace, "coverage_pct": coverage_pct, "basis": "rules_present", "categories": categories}
