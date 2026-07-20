# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Red-team catalog mapping + efficacy roll-up — pure, DB-free, unit-testable.

Every attack maps to a MITRE ATLAS technique (``mitre_technique``) and, where applicable, an OWASP LLM
control (derived from the attack ``category`` enum name, e.g. ``OWASP_LLM01`` -> ``LLM01:2025``). Technique /
control display names are resolved from the SAME shipped mapping files the Compliance feature reads
(``policies/mitre_mapping.json`` + ``policies/owasp_llm_mapping.json``), so the two views never drift.

Given the result rows from a suite run, compute a caught-vs-got-through efficacy roll-up — overall and per
ATLAS technique + per OWASP control. Only "block-expected" attacks count toward the proven-blocking ratio (an
attack whose expected decision is ``allow`` is a runtime/intent control case, reported separately, never counted
as a miss). Synthetic / probe target identities are EXCLUDED so the number reflects real deployed posture.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from norviq.api.synthetic import is_synthetic_identity

_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "policies"


@lru_cache(maxsize=1)
def _mitre_names() -> dict[str, str]:
    """AML.T00xx -> display name (from the shipped ATLAS mapping)."""
    try:
        data = json.loads((_POLICIES_DIR / "mitre_mapping.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {tid: str(v.get("name", tid)) for tid, v in data.items() if isinstance(v, dict)}


@lru_cache(maxsize=1)
def _owasp_names() -> dict[str, str]:
    """LLM0x:2025 -> display name (from the shipped OWASP LLM mapping)."""
    try:
        data = json.loads((_POLICIES_DIR / "owasp_llm_mapping.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {cid: str(v.get("name", cid)) for cid, v in data.items() if isinstance(v, dict)}


def owasp_control_for_category(category_name: str) -> str | None:
    """Map an AttackCategory ENUM NAME (e.g. ``OWASP_LLM01``) to its OWASP control id (``LLM01:2025``).

    Non-OWASP categories (SQL_INJECTION, CROSS_TENANT, …) return None — they still carry an ATLAS technique.
    """
    if not category_name.startswith("OWASP_LLM"):
        return None
    suffix = category_name.removeprefix("OWASP_")  # LLM01
    return f"{suffix}:2025"


def attack_mapping(attack: Any) -> dict[str, Any]:
    """The ATLAS + OWASP mapping for one attack definition (display-name resolved)."""
    tid = attack.mitre_technique
    category_name = attack.category.name  # enum NAME, e.g. OWASP_LLM01
    owasp_id = owasp_control_for_category(category_name)
    return {
        "atlas": {"technique_id": tid, "technique_name": _mitre_names().get(tid, tid)},
        "owasp": (
            {"control_id": owasp_id, "control_name": _owasp_names().get(owasp_id, owasp_id)}
            if owasp_id
            else None
        ),
    }


def catalog_entry(attack: Any) -> dict[str, Any]:
    """One enriched catalog row (attack fields + resolved ATLAS/OWASP mapping)."""
    m = attack_mapping(attack)
    return {
        "attack_id": attack.id,
        "name": attack.name,
        "category": attack.category.value,
        "description": attack.description,
        "severity": attack.severity,
        "tool_name": attack.tool_name,
        "expected_decision": attack.expected_decision,
        "expected_rule": attack.expected_rule,
        "tags": list(attack.tags),
        "atlas_technique": m["atlas"]["technique_id"],
        "atlas_technique_name": m["atlas"]["technique_name"],
        "owasp_control": m["owasp"]["control_id"] if m["owasp"] else None,
        "owasp_control_name": m["owasp"]["control_name"] if m["owasp"] else None,
    }


def _blank_bucket() -> dict[str, int]:
    return {"total": 0, "caught": 0, "got_through": 0}


def _finalize(bucket: dict[str, Any]) -> dict[str, Any]:
    total, caught = bucket["total"], bucket["caught"]
    bucket["proven_blocking_pct"] = round(caught / total * 100, 1) if total else 0.0
    return bucket


def compute_efficacy(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Caught-vs-got-through roll-up over the suite's result rows.

    - Synthetic / probe target identities are excluded (``is_synthetic_identity``).
    - Only rows whose EXPECTED decision is ``block`` count toward the proven-blocking ratio. A ``caught`` row is
      one that actually blocked (``passed``); a ``got_through`` row expected a block but did not get one.
    - Rows whose expected decision is not ``block`` (runtime/intent-only control cases) are tallied under
      ``non_enforcement`` and never counted as a miss.
    """
    considered = [r for r in results if not is_synthetic_identity(r.get("agent_class"))]
    overall = _blank_bucket()
    by_technique: dict[str, dict[str, Any]] = {}
    by_owasp: dict[str, dict[str, Any]] = {}
    non_enforcement = 0
    sector_not_enabled = 0  # sector-pack attacks whose pack isn't enabled — out of scope, NOT a miss
    excluded_synthetic = len(results) - len(considered)

    for r in considered:
        if r.get("expected") != "block":
            non_enforcement += 1
            continue
        # A sector attack whose enforcing rule isn't loaded (pack not enabled) is out of scope for THIS
        # deployment — it must not deflate proven-blocking, exactly like an un-enabled coverage category.
        if r.get("applicable") is False:
            sector_not_enabled += 1
            continue
        caught = bool(r.get("passed"))
        overall["total"] += 1
        overall["caught" if caught else "got_through"] += 1

        tid = r.get("atlas_technique") or "unknown"
        tb = by_technique.setdefault(tid, {**_blank_bucket(), "technique_id": tid,
                                            "technique_name": r.get("atlas_technique_name") or tid})
        tb["total"] += 1
        tb["caught" if caught else "got_through"] += 1

        cid = r.get("owasp_control")
        if cid:
            ob = by_owasp.setdefault(cid, {**_blank_bucket(), "control_id": cid,
                                           "control_name": r.get("owasp_control_name") or cid})
            ob["total"] += 1
            ob["caught" if caught else "got_through"] += 1

    return {
        "overall": _finalize(overall),
        "by_technique": [_finalize(v) for v in sorted(by_technique.values(), key=lambda x: x["technique_id"])],
        "by_owasp": [_finalize(v) for v in sorted(by_owasp.values(), key=lambda x: x["control_id"])],
        "non_enforcement": non_enforcement,
        "sector_not_enabled": sector_not_enabled,
        "excluded_synthetic": excluded_synthetic,
    }
