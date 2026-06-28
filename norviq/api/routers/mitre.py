# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""MITRE ATLAS coverage routes — technique → policy mapping cross-referenced with loaded rego."""

import json
from functools import lru_cache
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, Query, Request

from norviq.api.auth import get_current_user

log = structlog.get_logger()
router = APIRouter()

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
    user: dict = Depends(get_current_user),
) -> dict:
    """Return per-ATLAS-technique coverage: a technique is covered when one of its mapped policy
    rules appears in the rego loaded for this namespace (or the cluster baseline)."""
    _ = user
    mapping = _load_mapping()
    loader = getattr(request.app.state, "loader", None)
    rego_blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if ns in (namespace, "__cluster__"):
                rego_blob += str(entry.get("rego", ""))

    techniques = []
    for technique_id, info in mapping.items():
        policies = list(info.get("policies", []))
        covered_policies = [p for p in policies if p and p in rego_blob]
        techniques.append(
            {
                "technique_id": technique_id,
                "name": info.get("name", ""),
                "policies": policies,
                "covered_policies": covered_policies,
                "covered": len(covered_policies) > 0,
            }
        )
    techniques.sort(key=lambda t: t["technique_id"])
    covered = sum(1 for t in techniques if t["covered"])
    log.info("nrvq.api.mitre.coverage", namespace=namespace, covered=covered, total=len(techniques), code="NRVQ-API-7070")
    return {"namespace": namespace, "covered": covered, "total": len(techniques), "techniques": techniques}
