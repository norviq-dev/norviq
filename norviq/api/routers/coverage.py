# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Coverage-by-category route (F046) — real policy coverage across risk categories.

Replaces the console's fabricated category scores (magic coefficients on the block rate). A category is
"covered" for a namespace when its mapped rule_ids appear in the rego actually loaded for that namespace
(or the cluster baseline) — the same cross-reference the MITRE coverage route uses. The category -> rule_id
taxonomy lives in policies/category_mapping.json (a documented artifact), so nothing is hardcoded here.
"""

import json
from functools import lru_cache
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, Query, Request

from norviq.api.auth import get_current_user

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
) -> dict:
    """Per risk category: how many of its rules are enforced in this namespace's loaded rego."""
    _ = user
    mapping = _load_mapping()
    loader = getattr(request.app.state, "loader", None)
    rego_blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if ns in (namespace, "__cluster__"):
                rego_blob += str(entry.get("rego", ""))

    categories = []
    total_covered = 0
    total_rules = 0
    for category, rules in mapping.items():
        covered = [r for r in rules if r and r in rego_blob]
        score = round(len(covered) / len(rules) * 100) if rules else 0
        categories.append({"category": category, "covered": len(covered), "total": len(rules), "score": score})
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
    return {"namespace": namespace, "coverage_pct": coverage_pct, "categories": categories}
