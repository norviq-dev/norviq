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
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace
from norviq.api.db.models import AuditLogEntry
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


_RESERVED_CLASS_RE = re.compile(r"^__.*__$")
_ALLOW_NAMES_RE = re.compile(r'allow_names\s*:=\s*\{([^}]*)\}')
_QUOTED_RE = re.compile(r'"([^"]+)"')
# The refinement toggles are detectable by the helper rules the generator only emits when the toggle is on.
_REFINEMENT_MARKERS = {"readonly": "is_read ", "egress": "is_egress ", "scope": "in_scope ", "rate": "rate_within "}
_LEARNED_RE = re.compile(r'#\s*Learned verbs[^:]*:\s*(.+)')


def _parse_agent_policy(agent_class: str, rego: str, priority: int, mode: str) -> dict:
    """Summarise what an APPLIED agent-class policy enforces, so the Overview can show it (not just the
    risk-category taxonomy). Parses the deterministic markers our generators emit; a hand-authored policy
    degrades gracefully to kind='custom' with no allowlist detail."""
    pkg = ""
    m = re.search(r"package\s+([\w.]+)", rego or "")
    if m:
        pkg = m.group(1)
    if pkg.startswith("norviq.intent."):
        kind = "intent"
    elif pkg.startswith("norviq.remediation.capability."):
        kind = "capability"
    else:
        kind = "custom"
    allow_tools: list[str] = []
    am = _ALLOW_NAMES_RE.search(rego or "")
    if am:
        allow_tools = sorted(set(_QUOTED_RE.findall(am.group(1))))
    refinements = [key for key, marker in _REFINEMENT_MARKERS.items() if marker in (rego or "")]
    learned: list[str] = []
    lm = _LEARNED_RE.search(rego or "")
    if lm:
        learned = [seg.strip() for seg in lm.group(1).split(",") if "=" in seg]
    return {
        "cls": agent_class, "kind": kind, "allow_tools": allow_tools, "refinements": refinements,
        "learned_verbs": learned, "priority": priority, "enforcement_mode": mode,
    }


async def _agent_class_policies(
    session: AsyncSession, namespace: str | None, ns_mode: str
) -> tuple[list[dict], bool]:
    """Per-agent-class positive-security / custom policies APPLIED in this namespace, with what each
    enforces + real 30d audit efficacy (blocked / would-blocked / observed) for the class. This is the
    dimension the risk-category chart can't show: an intent policy governs the WHOLE class (default-deny),
    keyed on the class, not on a risk taxonomy's rule_ids.

    Returns ``(policies, degraded)``. ``degraded`` is True when a DB read failed so the caller can surface
    an honest "section unavailable" signal — a swallowed fault must NOT be indistinguishable from a
    genuinely empty namespace (a statement timeout / serialization failure would otherwise read as
    "no agent-class policies applied")."""
    where = "agent_class !~ '^__.*__$'"
    params: dict = {}
    if namespace is not None:
        where += " AND namespace = :ns"
        params["ns"] = namespace
    try:
        rows = (await session.execute(
            text(f"SELECT DISTINCT ON (namespace, agent_class) namespace, agent_class, rego_source, priority, "
                 f"enforcement_mode FROM policies WHERE {where} ORDER BY namespace, agent_class, version DESC"),
            params,
        )).mappings().all()
    except Exception as exc:  # best-effort: a DB hiccup must not 500 the dashboard — but it must be OBSERVABLE,
        # not silently read as "no agent-class policies applied" (NRVQ-API-7081-ERR).
        log.warning("nrvq.api.coverage.agent_class_query_failed", error=str(exc),
                    namespace=namespace, code="NRVQ-API-7081-ERR")
        return [], True
    if not rows:
        return [], False

    # 30d audit efficacy per class: real block / monitor would-block / total governed calls.
    since = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = select(AuditLogEntry.agent_class, AuditLogEntry.decision, AuditLogEntry.rule_id,
                  func.count(AuditLogEntry.id)).where(AuditLogEntry.timestamp_utc >= since)
    if namespace is not None:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    stmt = stmt.group_by(AuditLogEntry.agent_class, AuditLogEntry.decision, AuditLogEntry.rule_id)
    eff: dict[str, dict[str, int]] = {}
    degraded = False
    try:
        for cls, decision, rule_id, n in (await session.execute(stmt)).all():
            d = eff.setdefault(str(cls), {"observed": 0, "blocked": 0, "would_block": 0})
            d["observed"] += int(n)
            if str(decision) == "block":
                d["blocked"] += int(n)
            # Monitor-mode would-block: decision softened to audit with a would-block rule marker.
            elif str(decision) == "audit" and str(rule_id or "").startswith("monitor_would_block:"):
                d["would_block"] += int(n)
    except Exception as exc:  # best-effort; efficacy overlay is optional — but a fault still leaves the
        # efficacy numbers wrong/zeroed, so flag the section degraded rather than showing them as real.
        log.warning("nrvq.api.coverage.agent_class_efficacy_failed", error=str(exc),
                    namespace=namespace, code="NRVQ-API-7081-ERR")
        eff = {}
        degraded = True

    out = []
    for r in rows:
        summary = _parse_agent_policy(str(r["agent_class"]), str(r["rego_source"] or ""),
                                      int(r["priority"] or 100), str(r["enforcement_mode"] or "block"))
        e = eff.get(str(r["agent_class"]), {})
        summary["observed"] = e.get("observed", 0)
        summary["blocked"] = e.get("blocked", 0)
        summary["would_block"] = e.get("would_block", 0)
        # A policy set to block but in a Monitor namespace is LOADED, not enforcing — say so honestly.
        summary["enforcing"] = summary["enforcement_mode"] == "block" and ns_mode != "audit"
        # "effective" = has actually stopped (or would-stop, in monitor) traffic — the proven-blocking signal.
        summary["effective"] = e.get("blocked", 0) > 0 or e.get("would_block", 0) > 0
        out.append(summary)
    out.sort(key=lambda s: (not s["effective"], s["cls"]))
    return out, degraded


async def _namespace_mode(session: AsyncSession, namespace: str | None) -> str:
    """The namespace's enforcement posture ('block' | 'audit'). 'audit' = Monitor mode (logs, no enforce).
    A multi/all-namespace view has no single mode → 'block' (don't imply monitor across the fleet)."""
    if namespace is None:
        return "block"
    try:
        row = (await session.execute(
            text("SELECT enforcement_mode FROM namespace_settings WHERE namespace = :ns LIMIT 1"),
            {"ns": namespace},
        )).scalar()
    except Exception:
        return "block"
    return str(row) if row in ("block", "audit") else "block"


@router.get("/coverage-by-category")
async def coverage_by_category(
    request: Request,
    namespace: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Per risk category: `score` = how many mapped rules are PRESENT in this namespace's loaded rego (not a
    proof of efficacy); `observed`/`blocked` = real audit activity for those rules; `effective` = at least one
    rule in the category has actually blocked/escalated traffic. F-44/F-45: present != effective."""
    namespace = read_namespace(user, namespace)  # None => all namespaces
    mapping = _load_mapping()
    loader = getattr(request.app.state, "loader", None)
    rego_blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if namespace is None or ns in (namespace, "__cluster__"):
                rego_blob += str(entry.get("rego", ""))

    activity, _synthetic_excluded = await _activity_by_rule(session, namespace, "30d")  # best-effort; {} if DB down
    categories = []
    # IN-SCOPE coverage: a category is IN SCOPE only when at least one of its rules is actually loaded for
    # this namespace (baseline horizontal rules, or a sector pack the operator ENABLED). Sector packs the
    # operator never enabled are NOT gaps — they are "available to add", not a 0% failure. The headline
    # coverage_pct is computed over IN-SCOPE categories only, so it reflects the enforced posture and is not
    # diluted by every sector the product ships (which made a fully-covered baseline read as a scary 28%).
    in_scope_covered = 0
    in_scope_total = 0
    available = 0
    for category, rules in mapping.items():
        covered = [r for r in rules if r and r in rego_blob]
        n_cov = len(covered)
        in_scope = n_cov > 0
        score = round(n_cov / len(rules) * 100) if rules else 0
        observed = sum(activity.get(r, {}).get("observed", 0) for r in rules)
        blocked = sum(activity.get(r, {}).get("blocked", 0) for r in rules)
        categories.append({
            "category": category, "covered": n_cov, "total": len(rules), "score": score,
            "observed": observed, "blocked": blocked, "effective": blocked > 0,
            "in_scope": in_scope,
        })
        if in_scope:
            in_scope_covered += n_cov
            in_scope_total += len(rules)
        else:
            available += 1

    coverage_pct = round(in_scope_covered / in_scope_total * 100) if in_scope_total else 0

    # AGENT-CLASS dimension: the risk-category taxonomy above is horizontal (rule_ids per sector); it can't
    # represent a per-class positive-security policy (report-gen's default-deny allowlist). Surface those
    # separately so an APPLIED agent-class policy is visible on the Overview, with what it enforces.
    ns_mode = await _namespace_mode(session, namespace)
    agent_policies, agent_policies_degraded = await _agent_class_policies(session, namespace, ns_mode)

    log.info(
        "nrvq.api.coverage.served",
        namespace=namespace,
        coverage_pct=coverage_pct,
        in_scope=len(categories) - available,
        available=available,
        agent_policies=len(agent_policies),
        agent_policies_degraded=agent_policies_degraded,
        code="NRVQ-API-7081",
    )
    # basis: the score is rules-present (loaded), not efficacy — efficacy is the audit overlay + the red-team suite.
    # `available` = sector categories NOT enabled for this namespace (surfaced as "add a pack", never as a gap).
    # `agent_class_policies_degraded`: a DB read for the agent-class section failed — the empty/partial list is
    # an infra hiccup, NOT a genuinely empty namespace, so the UI can say so instead of "no policies applied".
    return {
        "namespace": namespace, "coverage_pct": coverage_pct, "basis": "rules_present",
        "available": available, "categories": categories,
        "namespace_mode": ns_mode, "agent_class_policies": agent_policies,
        "agent_class_policies_degraded": agent_policies_degraded,
    }
