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

from norviq.api.routers.system_health import non_policy_rule_for  # a fault or a throttle is not a detection
from norviq.api.synthetic import is_synthetic_identity
from norviq.redteam.vectors import VECTORS_BY_ID, EVALUATE_REACHABLE, coverage_denominators

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
        "mcp_vector": getattr(attack, "mcp_vector", "") or None,
        "mcp_vector_title": (
            VECTORS_BY_ID[attack.mcp_vector].title
            if getattr(attack, "mcp_vector", "") in VECTORS_BY_ID
            else None
        ),
    }


# Decisions that actually STOP the call. `escalate` belongs here: the firewall holds the call for human
# approval, the SDK interceptor raises NorviqEscalateError, and the sidecar proxy drops anything that is
# not `is_allowed()`. The attack did not reach the tool, which is what "caught" claims.
_ENFORCED_DECISIONS = frozenset({"block", "escalate"})


def _blank_bucket() -> dict[str, int]:
    return {"total": 0, "caught": 0, "would_block": 0, "got_through": 0}


def _row_outcome(r: dict[str, Any]) -> str:
    """caught | would_block | got_through, for a row that expected a block.

    The scorer read `passed` — which is `actual == expected` — so ONLY a hard block counted. Every
    baseline control now ships on `monitor`, and a monitored control is implemented by emitting an
    `audits[]` head, so a control that DETECTED the attack and recorded it scored identically to one
    that never fired. Measured on the shipped default: a run where two of four attacks were detected
    and audited reported proven_blocking_pct 25.0 with both audits in `got_through`.

    Three outcomes rather than two, because collapsing them either way is a lie an operator would act
    on. Counting an audit as caught would claim a defence while the call proceeded — the same mistake
    as BUG-018, arriving from the other side. Counting it as got-through says nothing detected it,
    when something did and the operator can promote that control to Enforce in one click.

    `proven_blocking_pct` deliberately stays caught/total: what it claims is PROVEN blocking, and a
    monitored detection has not proven it.

    An engine fault is never a detection. A fail-closed `block` carrying `evaluator_timeout` is the
    engine failing, not a control working, and scoring it as caught inflates the headline number with
    an outage — so faults are tested BEFORE the enforced check and left in the red bucket.

    A THROTTLE is never a detection either, for the same reason and with a nastier failure mode. The
    engine's rate limiter fires only on a decision that already resolved to `allow`, so a
    `block / rate_limit_exceeded` row is a call the policy stack examined and permitted, refused
    afterwards on volume alone. Scoring it as caught made `proven_blocking_pct` a function of how hard
    the suite was driven rather than of policy quality — and, worse, made it rise as coverage got
    WORSE, since only an allow is eligible to be throttled. The check is `non_policy_rule_for`, which
    covers faults and the throttle together.
    """
    rule_id = str(r.get("rule_id") or "")
    if non_policy_rule_for(rule_id) is not None:
        return "got_through"
    actual = str(r.get("actual") or "")
    if actual in _ENFORCED_DECISIONS:
        return "caught"
    # `audit` with a rule behind it means a control fired and the call was let through on purpose.
    # `default_allow` is the absence of a match, which is a genuine miss.
    if actual == "audit" and rule_id and rule_id != "default_allow":
        return "would_block"
    return "got_through"


def _finalize(bucket: dict[str, Any]) -> dict[str, Any]:
    total, caught = bucket["total"], bucket["caught"]
    bucket["proven_blocking_pct"] = round(caught / total * 100, 1) if total else 0.0
    # What the controls SAW, enforced or not. Reported beside the proven number rather than folded
    # into it: on the shipped all-monitor default these differ by design, and an operator reading a
    # 0% proven score needs to know whether that is "nothing detected it" or "everything detected it
    # and nothing is promoted yet" — two opposite situations with two opposite next actions.
    detected = caught + bucket["would_block"]
    bucket["detected_pct"] = round(detected / total * 100, 1) if total else 0.0
    return bucket


def _vector_coverage(exercised: set[str]) -> dict[str, Any]:
    """What this run measured of the MCP/tool surface, and — the point — what it did not.

    Without this block a scorecard reading 100% across two vectors is indistinguishable from full MCP
    coverage, while thirty catalogued vectors went untouched. That is the "the console says covered,
    and it is not" failure the whole product exists to prevent, so the denominator travels with the
    numerator rather than being available on request.

    The denominators come from the CATALOG, not from the rows, and they are STORED on the run. Only the
    newest run per namespace keeps its result rows (`redteam_detail_keep_runs`), so a block re-derived
    from rows would silently vanish from every older run while the rest of the efficacy summary
    survived. `exercised` counts DISTINCT vectors seen, not rows: five attacks across two vectors is
    two, because the question is surface coverage, not attack volume.

    PROXY-only vectors are not failures and must never read as such. Most are enforced, several
    provably (Gate A stripping, the content-hash pin) — they are simply decided before the policy
    engine, which is the one thing this suite can score.
    """
    d = coverage_denominators()
    return {
        **d,
        "exercised": len(exercised),
        "unexercised_reachable": sorted(EVALUATE_REACHABLE - exercised),
    }


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
    by_vector: dict[str, dict[str, Any]] = {}
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
        outcome = _row_outcome(r)
        overall["total"] += 1
        overall[outcome] += 1

        tid = r.get("atlas_technique") or "unknown"
        tb = by_technique.setdefault(tid, {**_blank_bucket(), "technique_id": tid,
                                            "technique_name": r.get("atlas_technique_name") or tid})
        tb["total"] += 1
        tb[outcome] += 1

        cid = r.get("owasp_control")
        if cid:
            ob = by_owasp.setdefault(cid, {**_blank_bucket(), "control_id": cid,
                                           "control_name": r.get("owasp_control_name") or cid})
            ob["total"] += 1
            ob[outcome] += 1

        # SKIPPED when absent, following `by_owasp` and NOT `by_technique`. `by_technique` defaults to
        # "unknown" because every attack is supposed to carry a technique, so that bucket is an alarm
        # for a broken mapping. An MCP vector is legitimately absent for every attack that predates the
        # dimension — bucketing those as "unknown" would assert they exercise an unidentified MCP
        # vector, which is false, and would render one row of ~29xN attacks that dominates the table
        # and means nothing.
        vid = r.get("mcp_vector")
        if vid:
            vb = by_vector.setdefault(vid, {**_blank_bucket(), "vector_id": vid,
                                            "vector_title": r.get("mcp_vector_title") or vid})
            vb["total"] += 1
            vb[outcome] += 1

    return {
        "overall": _finalize(overall),
        "by_technique": [_finalize(v) for v in sorted(by_technique.values(), key=lambda x: x["technique_id"])],
        "by_owasp": [_finalize(v) for v in sorted(by_owasp.values(), key=lambda x: x["control_id"])],
        "by_vector": [_finalize(v) for v in sorted(by_vector.values(), key=lambda x: x["vector_id"])],
        "vector_coverage": _vector_coverage(set(by_vector)),
        "non_enforcement": non_enforcement,
        "sector_not_enabled": sector_not_enabled,
        "excluded_synthetic": excluded_synthetic,
    }
