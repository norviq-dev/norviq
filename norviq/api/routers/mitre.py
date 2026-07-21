# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Compliance (MITRE ATLAS) coverage routes — technique→policy mapping cross-referenced with the loaded rego and
real audit activity. Every value is DERIVED (no mock): coverage from the loaded rego, observed/blocked + affected
agent-classes from the audit DB, the trend from a persisted snapshot series, the evidence pack from the same
computation. Scope splits techniques into runtime-enforceable (counted) vs out-of-scope (shown, not counted)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import AsyncIterator, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, require_target_cluster
from norviq.api.db.models import AuditLogEntry, IntentDraft, MitreCoverageSnapshot
from norviq.api.db.session import get_session
from norviq.api.retention import draft_expiry, enforce_draft_cap
from norviq.api.synthetic import is_synthetic_identity  # the ONE shared classifier (do not fork)
from norviq.api.threat_intent import generate_remediation_rego, remediation_generatable_rules

log = structlog.get_logger()
router = APIRouter()

_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
# Live, backend-computed frameworks → their technique→policy mapping file. Both are computed from the SAME real
# loaded rego + audit machinery (no mock). ATLAS stays the default so the existing /mitre routes are unchanged.
_FRAMEWORKS = {"atlas": "mitre_mapping.json", "owasp": "owasp_llm_mapping.json"}
_MAX_AFFECTED = 8  # cap affected-class chips per technique


def _valid_framework(framework: str) -> str:
    if framework not in _FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework '{framework}'. Live: {sorted(_FRAMEWORKS)}")
    return framework


# --------------------------------------------------------------------------------------------------
# mapping + audit activity
# --------------------------------------------------------------------------------------------------

@lru_cache(maxsize=len(_FRAMEWORKS))
def _load_mapping(framework: str = "atlas") -> dict:
    """Load a framework's technique→policies mapping from disk (cached). ATLAS names verified against
    atlas.mitre.org; OWASP names are the official 2025 list. Both share the same coverage machinery."""
    filename = _FRAMEWORKS.get(framework, "mitre_mapping.json")
    for base in (Path(__file__).resolve().parents[3] / "policies", Path.cwd() / "policies"):
        path = base / filename
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    log.warning("nrvq.api.mitre.mapping_missing", framework=framework, code="NRVQ-API-7070-ERR")
    return {}


async def _activity_by_rule(
    session: AsyncSession, namespace: str | None, range_token: str
) -> tuple[dict[str, dict[str, int]], int]:
    """Per-rule_id observed-attempt + blocked counts from audit, EXCLUDING synthetic/simulated events, plus
    the count of events excluded (best-effort; ({}, 0) if the DB is unavailable).

    COMP-EVIDENCE (product decision): an audit-evidence pack is an attestation to an auditor — it must count
    REAL traffic only. Synthetic/probe/eval identities (the synthetic-identity classifier) and red-team framework events
    (efficacy tooling, not live enforcement) are excluded from the observed/blocked headline so the pack
    can't be read as real enforcement evidence. Red-team efficacy still lives in its own clearly-labelled
    'proven-blocking' surface (RedTeam page), never merged into these counts. The excluded count is
    surfaced so the pack states the exclusion explicitly."""
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range_token, 24))
    # Group by agent_class + framework too, so the Python-side classifier can drop synthetic identities
    # (it is not expressible in SQL) and red-team events before aggregating.
    stmt = (
        select(
            AuditLogEntry.rule_id,
            AuditLogEntry.decision,
            AuditLogEntry.agent_class,
            AuditLogEntry.framework,
            func.count(AuditLogEntry.id),
        )
        .where(AuditLogEntry.timestamp_utc >= since)
        .group_by(AuditLogEntry.rule_id, AuditLogEntry.decision, AuditLogEntry.agent_class, AuditLogEntry.framework)
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    by_rule: dict[str, dict[str, int]] = {}
    excluded = 0
    try:
        for rid, decision, cls, framework, count in (await session.execute(stmt)).all():
            n = int(count)
            if str(framework or "") == "redteam" or is_synthetic_identity(str(cls or "")):
                excluded += n
                continue
            entry = by_rule.setdefault(str(rid), {"observed": 0, "blocked": 0})
            entry["observed"] += n
            if decision in ("block", "escalate"):
                entry["blocked"] += n
    except Exception as exc:  # noqa: BLE001 — activity is derived; a DB error just shows 0
        log.warning("nrvq.api.mitre.activity_unavailable", error=str(exc), code="NRVQ-API-7071")
    return by_rule, excluded


async def _blocked_by_rule_class(session: AsyncSession, namespace: str | None, range_token: str) -> dict[str, dict[str, int]]:
    """{rule_id: {agent_class: blocked_count}} over `range` — the REAL rule×audit join behind the
    per-technique affected-agent-class chips.

    Excludes the SAME population as the headline `_activity_by_rule`: synthetic/probe/eval classes AND
    red-team framework events. Grouping by `framework` (like the sibling helper) is what lets the
    Python-side filter drop red-team rows — without it the affected-class chips counted red-team probes
    the honest technique headline excluded, so the chip (e.g. 24) contradicted its own headline (9) and
    over-attributed enforcement to a class. REAL traffic only, consistently."""
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range_token, 24))
    stmt = (
        select(
            AuditLogEntry.rule_id,
            AuditLogEntry.agent_class,
            AuditLogEntry.framework,
            func.count(AuditLogEntry.id),
        )
        .where(AuditLogEntry.timestamp_utc >= since, AuditLogEntry.decision.in_(("block", "escalate")))
        .group_by(AuditLogEntry.rule_id, AuditLogEntry.agent_class, AuditLogEntry.framework)
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    out: dict[str, dict[str, int]] = {}
    try:
        for rid, cls, framework, count in (await session.execute(stmt)).all():
            cls = str(cls or "")
            # never list a probe/test class or a red-team efficacy run as an "affected" class
            if not cls or str(framework or "") == "redteam" or is_synthetic_identity(cls):
                continue
            out.setdefault(str(rid), {})[cls] = out.setdefault(str(rid), {}).get(cls, 0) + int(count)
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.mitre.affected_unavailable", error=str(exc), code="NRVQ-API-7072")
    return out


# --------------------------------------------------------------------------------------------------
# core coverage computation (shared by /coverage, /export, snapshots)
# --------------------------------------------------------------------------------------------------

def _rego_blob(request: Request, namespace: str | None) -> str:
    loader = getattr(request.app.state, "loader", None)
    blob = ""
    if loader is not None:
        for key, entry in loader._policies.items():
            ns = key.split(":", 1)[0]
            if namespace is None or ns in (namespace, "__cluster__"):
                blob += str(entry.get("rego", ""))
    return blob


async def _compute_coverage(request: Request, session: AsyncSession, namespace: str | None, range_token: str, framework: str = "atlas") -> dict:
    """Build the full coverage payload for a framework from its mapping + the loaded rego + audit. NO mock."""
    mapping = _load_mapping(framework)
    rego_blob = _rego_blob(request, namespace)
    by_rule, synthetic_excluded = await _activity_by_rule(session, namespace, range_token)
    by_rule_class = await _blocked_by_rule_class(session, namespace, range_token)

    techniques = []
    for technique_id, info in mapping.items():
        scope = info.get("scope", "enforceable")
        policies = list(info.get("policies", []))
        covered_policies = [p for p in policies if p and p in rego_blob]
        enforceable = scope == "enforceable"
        covered = bool(covered_policies)
        if not enforceable:
            status = "out_of_scope"
        elif covered:
            status = "enforced"
        else:
            status = "gap"
        # Is this control auto-generatable, or does it need a bespoke (non-tool-call) control?
        # A gap with no runtime-expressible rule (bespoke, or empty `policies`) ESCALATES on generate — the UI
        # must know up front so it doesn't offer a "Generate" checkbox that only ever dead-ends.
        generatable = (
            status == "gap" and not _control_is_bespoke(info) and bool(remediation_generatable_rules(policies))
        )
        observed = sum(by_rule.get(p, {}).get("observed", 0) for p in policies)
        blocked = sum(by_rule.get(p, {}).get("blocked", 0) for p in policies)
        # PER-RULE blocked counts (rule_id → blocked), so an evidence row attributes blocks to the
        # RIGHT rule instead of repeating the technique-wide `blocked` total on every covered-rule row. Keyed
        # over the technique's mapped policies (a mapped-but-inactive rule reads 0).
        blocked_by_rule = {p: by_rule.get(p, {}).get("blocked", 0) for p in policies}
        # Affected agent-classes: aggregate blocked-by-class across this technique's covered rules (synthetic
        # already excluded in _blocked_by_rule_class), sort worst-first, cap.
        agg: dict[str, int] = {}
        for rule in covered_policies:
            for cls, cnt in by_rule_class.get(rule, {}).items():
                agg[cls] = agg.get(cls, 0) + cnt
        affected = [{"class": c, "blocked": n} for c, n in sorted(agg.items(), key=lambda kv: -kv[1])][:_MAX_AFFECTED]
        techniques.append({
            "technique_id": technique_id,
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "scope": scope,
            "status": status,
            "generatable": generatable,
            "priority": info.get("priority"),
            "also": info.get("also"),
            "policies": policies,
            "covered_policies": covered_policies,
            "covered": covered,
            "observed": observed,
            "blocked": blocked,
            "blocked_by_rule": blocked_by_rule,
            "affected_classes": affected,
        })
    techniques.sort(key=lambda t: t["technique_id"])

    enforceable_total = sum(1 for t in techniques if t["scope"] == "enforceable")
    enforced = sum(1 for t in techniques if t["status"] == "enforced")
    gap = sum(1 for t in techniques if t["status"] == "gap")
    oos = sum(1 for t in techniques if t["scope"] == "out_of_scope")
    coverage_pct = round(enforced / enforceable_total * 100) if enforceable_total else 0
    # The headline observed/blocked/agent-classes are attributable to THIS framework — sum over the
    # framework's DISTINCT mapped rule_ids (a rule mapped to several techniques counts once), NOT the global
    # audit total. ATLAS and OWASP therefore show different, correct numbers.
    framework_rules = {p for info in mapping.values() for p in info.get("policies", []) if p}
    total_observed = sum(by_rule.get(r, {}).get("observed", 0) for r in framework_rules)
    total_blocked = sum(by_rule.get(r, {}).get("blocked", 0) for r in framework_rules)
    agent_classes = len({c for r in framework_rules for c in by_rule_class.get(r, {})})
    return {
        "namespace": namespace, "range": range_token, "framework": framework,
        "enforceable_total": enforceable_total, "enforced": enforced, "gap": gap, "oos": oos,
        "coverage_pct": coverage_pct,
        # back-compat headline fields (old page)
        "covered": enforced, "total": enforceable_total,
        "observed": total_observed, "blocked": total_blocked, "agent_classes": agent_classes,
        # COMP-EVIDENCE (product decision): the count of synthetic/simulated + red-team events excluded from
        # observed/blocked, so the console + evidence pack can state the exclusion explicitly.
        "synthetic_excluded": synthetic_excluded,
        "techniques": techniques,
    }


def _ns_key(namespace: str | None) -> str:
    return namespace or "__all__"


async def _coverage_cached(
    request: Request, session: AsyncSession, namespace: str | None, range_token: str, framework: str = "atlas"
) -> dict:
    """Request-scoped memoization of _compute_coverage. The coverage aggregation runs two audit
    GROUP BY scans (_activity_by_rule + _blocked_by_rule_class) that are LOOP-INVARIANT within one request —
    (namespace, range, framework) don't change across a batch's techniques. Batch generate must therefore
    compute coverage ONCE, not 2*N times. The cache lives on request.state so it never leaks across requests
    (a fresh request recomputes)."""
    cache = getattr(request.state, "_coverage_cache", None)
    if cache is None:
        cache = {}
        request.state._coverage_cache = cache
    key = (_ns_key(namespace), range_token, framework)
    hit = cache.get(key)
    if hit is None:
        hit = await _compute_coverage(request, session, namespace, range_token, framework)
        cache[key] = hit
    return hit


def _snapshot_lock_key(namespace: str, framework: str, hour_start: datetime) -> int:
    """A stable signed-64-bit key for pg_advisory_xact_lock so concurrent same-hour snapshot writers
    serialize on the SAME lock (the second reads the first's committed row and short-circuits). sha256 keeps it
    seed-independent across replicas; usedforsecurity=False — this is a lock key, not a credential."""
    raw = "|".join((namespace, framework, hour_start.isoformat()))
    return int.from_bytes(hashlib.sha256(raw.encode(), usedforsecurity=False).digest()[:8], "big", signed=True)


def _stable_draft_id(framework: str, technique_id: str, namespace: str, target: str) -> str:
    """The dedup id for a compliance-remediation draft, as a SEED-INDEPENDENT pure function of its
    (framework, control, namespace, class) content. sha256 (not Python's PYTHONHASHSEED-salted builtin hash())
    so the same inputs mint the same id on every replica — a deeplink minted on one replica resolves after a
    regenerate lands on another. usedforsecurity=False: this is a display/dedup id token, not a credential."""
    digest = hashlib.sha256("|".join((framework, technique_id, namespace, target)).encode(),
                            usedforsecurity=False).hexdigest()
    return f"dmitre{digest[:11]}"


async def _record_snapshot(session: AsyncSession, namespace: str | None, cov: dict, framework: str) -> None:
    """Upsert at most ONE coverage snapshot per (namespace, framework, hour) so the trend accumulates a
    real series with no scheduler. Best-effort — never fails the coverage read."""
    try:
        hour_start = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        # Serialize concurrent same-hour writers before the read-then-insert. A transaction-scoped
        # advisory lock keyed on (namespace, framework, hour) makes the throttle single-writer even under READ
        # COMMITTED and across replicas — the second writer blocks until the first commits, then reads the row
        # and returns without inserting. (The partial UNIQUE index on mitre_coverage_snapshots is the
        # structural backstop on a fresh DB.)
        await session.execute(
            select(func.pg_advisory_xact_lock(_snapshot_lock_key(_ns_key(namespace), framework, hour_start)))
        )
        existing = await session.scalar(
            select(func.count(MitreCoverageSnapshot.id)).where(
                MitreCoverageSnapshot.namespace == _ns_key(namespace),
                MitreCoverageSnapshot.framework == framework,
                MitreCoverageSnapshot.kind == "snapshot",
                MitreCoverageSnapshot.timestamp_utc >= hour_start,
            )
        )
        if existing:
            return
        session.add(MitreCoverageSnapshot(
            namespace=_ns_key(namespace), framework=framework, kind="snapshot",
            enforced=cov["enforced"], enforceable_total=cov["enforceable_total"],
            coverage_pct=cov["coverage_pct"], blocked=cov["blocked"],
        ))
        await session.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.mitre.snapshot_failed", error=str(exc), code="NRVQ-API-7073")


async def _top_active_classes(session: AsyncSession, namespace: str | None, range_token: str) -> list[str]:
    """The real, non-synthetic agent classes with the most audit activity in ns/range — the classes a gap
    control (no block-by-rule data of its own) would plausibly need remediation for. Worst/most-active first."""
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range_token, 24))
    stmt = (
        select(AuditLogEntry.agent_class, func.count(AuditLogEntry.id))
        .where(AuditLogEntry.timestamp_utc >= since)
        .group_by(AuditLogEntry.agent_class)
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    ranked: list[tuple[str, int]] = []
    try:
        for cls, count in (await session.execute(stmt)).all():
            cls = str(cls or "")
            if cls and not is_synthetic_identity(cls):
                ranked.append((cls, int(count)))
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.mitre.active_classes_unavailable", error=str(exc), code="NRVQ-API-7078")
    return [c for c, _ in sorted(ranked, key=lambda kv: -kv[1])]


# A control is REMEDIABLE when at least one of its mapped rule_ids (the `policies` list in the
# framework mapping) has a runtime remediation template (remediation_generatable_rules). A control with no
# such rule — an empty `policies`, or a mapping explicitly flagged `remediation: bespoke` — is ESCALATED,
# never faked with a generic per-class deny-all.
def _control_is_bespoke(info: dict) -> bool:
    return str(info.get("remediation") or "").strip().lower() == "bespoke"


async def _last_exported(session: AsyncSession, namespace: str | None, framework: str) -> str | None:
    try:
        row = await session.scalar(
            select(MitreCoverageSnapshot.timestamp_utc).where(
                MitreCoverageSnapshot.namespace == _ns_key(namespace),
                MitreCoverageSnapshot.framework == framework,
                MitreCoverageSnapshot.kind == "export",
            ).order_by(MitreCoverageSnapshot.timestamp_utc.desc()).limit(1)
        )
        return row.isoformat() if row else None
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------------------------------
# endpoints
# --------------------------------------------------------------------------------------------------

@router.get("/mitre/coverage")
async def mitre_coverage(
    request: Request,
    namespace: str | None = Query(default=None),
    range: str = Query("24h"),
    framework: str = Query("atlas"),  # atlas | owasp — both live, same real coverage machinery
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Per-technique coverage for a live framework (atlas|owasp) with scope (enforceable/out-of-scope), status
    (enforced/gap/out_of_scope), real observed/blocked + affected agent-classes, and the enforced/enforceable
    headline. Records a throttled snapshot for the trend + reports the last export time. Every value is derived."""
    framework = _valid_framework(framework)
    namespace = read_namespace(user, namespace)
    cov = await _compute_coverage(request, session, namespace, range, framework)
    await _record_snapshot(session, namespace, cov, framework)
    cov["last_exported"] = await _last_exported(session, namespace, framework)
    log.info("nrvq.api.mitre.coverage", namespace=namespace, framework=framework, enforced=cov["enforced"],
             enforceable=cov["enforceable_total"], pct=cov["coverage_pct"], code="NRVQ-API-7070")
    return cov


@router.get("/mitre/coverage/trend")
async def mitre_trend(
    namespace: str | None = Query(default=None),
    range: str = Query("30d"),
    framework: str = Query("atlas"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """The REAL coverage-trend series for a framework from the persisted snapshot table (accumulates over
    time; empty until the first snapshot). No fabricated points."""
    framework = _valid_framework(framework)
    namespace = read_namespace(user, namespace)
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS.get(range, 720))
    points: list[dict] = []
    try:
        rows = (await session.execute(
            select(MitreCoverageSnapshot).where(
                MitreCoverageSnapshot.namespace == _ns_key(namespace),
                MitreCoverageSnapshot.framework == framework,
                MitreCoverageSnapshot.kind == "snapshot",
                MitreCoverageSnapshot.timestamp_utc >= since,
            ).order_by(MitreCoverageSnapshot.timestamp_utc.asc())
        )).scalars().all()
        points = [{"timestamp": r.timestamp_utc.isoformat(), "enforced": r.enforced,
                   "coverage_pct": r.coverage_pct, "blocked": r.blocked} for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.mitre.trend_unavailable", error=str(exc), code="NRVQ-API-7074")
    return {"namespace": namespace, "range": range, "framework": framework, "points": points}


@router.get("/mitre/coverage/export")
async def mitre_export(
    request: Request,
    namespace: str | None = Query(default=None),
    range: str = Query("24h"),
    framework: str = Query("atlas"),
    format: Literal["json", "pdf"] = Query("json"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    """Stream a REAL in-cluster evidence pack for a framework (per-technique id/name/scope/status, mapped +
    covered policies, per-rule blocked counts, generated-at). No egress. Records the export time."""
    framework = _valid_framework(framework)
    namespace = read_namespace(user, namespace)
    cov = await _compute_coverage(request, session, namespace, range, framework)
    generated_at = datetime.now(timezone.utc).isoformat()
    # record the export event (best-effort) so the UI's "last exported" is real
    try:
        session.add(MitreCoverageSnapshot(
            namespace=_ns_key(namespace), framework=framework, kind="export",
            enforced=cov["enforced"], enforceable_total=cov["enforceable_total"],
            coverage_pct=cov["coverage_pct"], blocked=cov["blocked"],
        ))
        await session.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.mitre.export_record_failed", error=str(exc), code="NRVQ-API-7075")

    pack = {
        "framework": "MITRE ATLAS" if framework == "atlas" else "OWASP LLM Top 10 (2025)",
        "framework_id": framework, "namespace": namespace, "range": range,
        "generated_at": generated_at, "generated_by": str(user.get("sub") or ""),
        "coverage_pct": cov["coverage_pct"], "enforced": cov["enforced"],
        "enforceable_total": cov["enforceable_total"], "gap": cov["gap"], "out_of_scope": cov["oos"],
        "blocked_over_range": cov["blocked"],
        # COMP-EVIDENCE (product decision): carry the synthetic/simulated + red-team exclusion count into the
        # pack so the JSON export and the PDF can state "real traffic only" honestly.
        "synthetic_excluded": cov["synthetic_excluded"],
        "controls": [
            {
                "technique_id": t["technique_id"], "name": t["name"], "scope": t["scope"], "status": t["status"],
                "mapped_policies": t["policies"], "enforcing_policies": t["covered_policies"],
                "blocked": t["blocked"], "observed": t["observed"],
                # PER-RULE blocked counts (the docstring above promises this) so the exported evidence
                # pack attributes blocks to each enforcing rule instead of repeating the technique-wide total.
                "blocked_by_rule": t["blocked_by_rule"],
                "affected_classes": t["affected_classes"],
            }
            for t in cov["techniques"]
        ],
    }
    log.info("nrvq.api.mitre.export", namespace=namespace, format=format, controls=len(pack["controls"]),
             code="NRVQ-API-7076")

    if format == "pdf":
        body = _evidence_pdf(pack)

        async def _pdf_gen() -> AsyncIterator[bytes]:
            yield body

        return StreamingResponse(_pdf_gen(), media_type="application/pdf",
                                 headers={"Content-Disposition": f"attachment; filename=norviq-{framework}-evidence.pdf"})

    async def _json_gen() -> AsyncIterator[str]:
        yield json.dumps(pack, indent=2)

    return StreamingResponse(_json_gen(), media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=norviq-{framework}-evidence.json"})


class GenerateRequest(BaseModel):
    technique_id: str
    namespace: str = "default"
    agent_class: str | None = None  # optional — the backend derives the real affected/active class when absent
    range: str = "24h"
    framework: str = "atlas"


async def _resolve_target_class(
    request: Request, session: AsyncSession, namespace: str | None, range_token: str, framework: str,
    technique_id: str, requested: str | None,
) -> str | None:
    """Pick a REAL agent class to scope the draft to. Preference: an explicit, non-synthetic caller class →
    the control's own top affected class (blocked-by-rule) → the namespace's top active non-synthetic class.
    Returns None when there is genuinely no real class to remediate (→ caller emits 'nothing to remediate')."""
    requested = (requested or "").strip()
    if requested and requested.lower() != "default" and not is_synthetic_identity(requested):
        return requested
    cov = await _coverage_cached(request, session, namespace, range_token, framework)  # memoized per request
    tech = next((t for t in cov["techniques"] if t["technique_id"] == technique_id), None)
    if tech:
        for chip in tech.get("affected_classes", []):
            cls = chip.get("class", "")
            if cls and not is_synthetic_identity(cls):
                return cls
    for cls in await _top_active_classes(session, namespace, range_token):
        return cls  # already ranked, non-synthetic
    return None


async def _affected_real_classes(
    request: Request, session: AsyncSession, namespace: str | None, range_token: str, framework: str,
    technique_id: str,
) -> list[str]:
    """Every REAL (non-synthetic) agent class the control affects in range — the fan-out set for the batch
    "all affected classes" mode. Falls back to the namespace's top active class when the technique has no
    recorded affected class yet, so "all" still remediates something real rather than nothing."""
    cov = await _coverage_cached(request, session, namespace, range_token, framework)  # memoized per request
    tech = next((t for t in cov["techniques"] if t["technique_id"] == technique_id), None)
    out: list[str] = []
    for chip in (tech or {}).get("affected_classes", []) if tech else []:
        cls = chip.get("class", "")
        if cls and not is_synthetic_identity(cls) and cls not in out:
            out.append(cls)
    if not out:
        for cls in await _top_active_classes(session, namespace, range_token):
            out.append(cls)
            break
    return out


async def _generate_remediation_draft(
    request: Request, session: AsyncSession, user: dict, framework: str, technique_id: str,
    namespace: str, agent_class: str | None, range_token: str,
) -> dict:
    """Validate + build a CONTROL-SPECIFIC tighten-only DRY-RUN remediation draft for one
    (framework, control, class). Shared by the single-generate + batch endpoints. Returns a status dict
    (draft / escalate / no_affected_classes); never raises for the escalate/no-class cases so a batch item's
    outcome is reported rather than aborting the whole batch. Callers do the admin + target-cluster gating."""
    mapping = _load_mapping(framework)
    info = mapping.get(technique_id)
    if not info:
        raise HTTPException(status_code=404, detail=f"Unknown technique {technique_id}")
    if info.get("scope") != "enforceable":
        raise HTTPException(status_code=422, detail="Only runtime-enforceable techniques can be generated for.")
    if agent_class and is_synthetic_identity(agent_class):
        raise HTTPException(status_code=422, detail="Refusing to generate a policy for a synthetic/test class.")

    control_name = str(info.get("name") or technique_id)
    rule_ids = list(info.get("policies") or [])
    usable = remediation_generatable_rules(rule_ids)
    # A bespoke control OR one with no runtime-expressible mapped rule is ESCALATED — never faked
    # with a vacuous per-class deny-all.
    if _control_is_bespoke(info) or not usable:
        log.info("nrvq.api.mitre.generate_escalate", technique=technique_id, framework=framework,
                 code="NRVQ-API-7079")
        return {"status": "escalate", "draft_id": None, "technique_id": technique_id,
                "control_name": control_name, "framework": framework,
                "message": f"{technique_id} {control_name} can't be auto-generated as a runtime policy — this "
                           f"risk doesn't show up in agent tool-call traffic, so there is no signal a policy "
                           f"rule could match at enforcement time. Address it with a bespoke control in "
                           f"configuration or process (outside runtime enforcement)."}

    # Scope to a REAL class; never invent a 'default' deny-all when there's nothing to remediate.
    target = await _resolve_target_class(request, session, namespace, range_token, framework,
                                         technique_id, agent_class)
    if not target:
        log.info("nrvq.api.mitre.generate_no_classes", technique=technique_id, ns=namespace,
                 framework=framework, code="NRVQ-API-7080")
        return {"status": "no_affected_classes", "draft_id": None, "technique_id": technique_id,
                "control_name": control_name, "framework": framework, "ns": namespace,
                "message": "No affected agent classes in range — nothing to remediate yet."}

    # CONTROL-SPECIFIC rego assembled from the technique's mapped rule_ids (package
    # norviq.remediation.<fw>.<control>) — two different controls differ. Tighten-only, dry-run.
    rego = generate_remediation_rego(framework, technique_id, control_name, target, rule_ids)
    # DATA-LOSS GUARD: a compliance control is inherently ADDITIVE — "tighten-only draft that
    # denies this one control" — never a replacement for the class's existing comprehensive policy. Reviewing
    # + applying a draft POSTs its (namespace, agent_class) straight into `loader.create()`'s full-replace
    # UPSERT (`ON CONFLICT ... DO UPDATE SET rego_source = EXCLUDED.rego_source`); persisting the draft at the
    # REAL class's own key would let "Review & Apply" silently DESTROY that class's enforcing policy. So the
    # draft's PERSISTENCE target is the dedicated per-class overlay key `"<target>__remediation__"` (double-
    # underscore suffix — NOT a colon; policies.py `_infer_target_type` treats any `:` in agent_class as a
    # workload key and would misclassify it). `evaluator._collect_candidates` resolves this key as an
    # additive, tighten-only OVERLAY (mirrors `__pack__`/`__guardrail__`), so applying it can only ADD a block
    # for `target` — the base `(namespace, target)` policy is left byte-identical. The real affected class is
    # retained separately (`affected_class`) for UI display/traceability.
    overlay_class = f"{target}__remediation__"
    # Dedup key = (framework, control_id, class) → same control twice updates ONE draft; two different
    # controls for the same class stay as TWO distinct drafts (different control_id). Also clears any
    # draft that was keyed directly on `target` (the legacy, destructive key) so it can never later be
    # "reviewed & applied" and destroy the base policy.
    # The id MUST be a pure function of its content so a deeplink minted on replica A still resolves
    # after a regenerate lands on replica B. Python's builtin hash() of a str/tuple is PYTHONHASHSEED-salted
    # per process (no PYTHONHASHSEED pinning here + api.replicas>=2), so `abs(hash(...))` would produce a
    # different id per replica and the deeplink would 404. sha256 is seed-independent across processes/replicas.
    draft_id = _stable_draft_id(framework, technique_id, namespace, target)
    created_at = datetime.now(timezone.utc)
    await session.execute(
        text("DELETE FROM intent_drafts WHERE namespace = :ns AND agent_class IN (:cls, :legacy_cls) "
             "AND source_framework = :fw AND source_control_id = :cid"),
        {"ns": namespace, "cls": overlay_class, "legacy_cls": target, "fw": framework, "cid": technique_id},
    )
    session.add(IntentDraft(
        id=draft_id, namespace=namespace, agent_class=overlay_class, affected_class=target, rego_source=rego,
        allow_tools=[], toggles=usable, priority=1,  # toggles now carries the mapped rule_ids (traceability)
        covered_count=0, total=0, would_block=0, would_allow=0,
        created_by=str(user.get("sub") or ""), created_at=created_at,
        source_framework=framework, source_control_id=technique_id, source_control_name=control_name,
        expires_at=draft_expiry(target, created_at),  # TTL (24h test / 14d real)
    ))
    await session.commit()
    await enforce_draft_cap(session, namespace)  # per-namespace cap
    log.info("nrvq.api.mitre.generate", technique=technique_id, ns=namespace, cls=target,
             overlay_cls=overlay_class, framework=framework, rules=usable, draft_id=draft_id,
             actor=user.get("sub"), code="NRVQ-API-7077")
    return {"status": "draft", "draft_id": draft_id, "ns": namespace, "cls": target,
            "technique_id": technique_id, "control_name": control_name, "framework": framework,
            "mapped_rules": usable, "refinement": ", ".join(usable),
            "deeplink": f"/policies/catalog?intent_draft={draft_id}", "enforcement": "draft"}


@router.post("/mitre/coverage/generate")
async def mitre_generate(
    body: GenerateRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """GAP → generate a REAL tighten-only DRY-RUN remediation draft, CONTROL-SPECIFIC (its
    mapped block rule(s), package norviq.remediation.<fw>.<control>), SCOPED to the control's affected (or the
    namespace's most-active) real agent class and TAGGED with its framework + control. A control with no
    runtime-expressible rule (empty mapping policies / remediation=bespoke) → status=escalate; no real class →
    status=no_affected_classes (creates nothing). NEVER auto-enforces — gated apply via Policies (admin +
    target-cluster)."""
    require_admin(user)
    framework = _valid_framework(body.framework)
    return await _generate_remediation_draft(request, session, user, framework, body.technique_id,
                                             body.namespace, body.agent_class, body.range)


class GenerateBatchRequest(BaseModel):
    technique_ids: list[str]
    namespace: str = "default"
    # class_mode: "affected" = the control's top affected class (default) · "all" = every real affected class ·
    # any other value = that specific (non-synthetic) class. Multi-select fans out over technique_ids.
    class_mode: str = "affected"
    range: str = "24h"
    framework: str = "atlas"


@router.post("/mitre/coverage/generate-batch")
async def mitre_generate_batch(
    body: GenerateBatchRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Multi-select: generate one CONTROL-SPECIFIC remediation draft per (technique × class). The
    class fan-out is driven by class_mode ("affected" | "all" | a specific class). Same admin + target-cluster
    gating + synthetic-class refusal as the single generate; each (technique × class) reuses the dedup key so
    re-running UPDATES rather than duplicates. Returns a per-item result list + a rollup summary; a bad technique
    id / out-of-scope / synthetic class is reported per item, never aborting the whole batch."""
    require_admin(user)
    framework = _valid_framework(body.framework)
    mode = (body.class_mode or "affected").strip()
    results: list[dict] = []
    for tid in body.technique_ids:
        # Resolve the class set for THIS technique per the mode.
        if mode.lower() == "all":
            classes: list[str | None] = list(
                await _affected_real_classes(request, session, body.namespace, body.range, framework, tid)
            ) or [None]
        elif mode.lower() == "affected":
            classes = [None]  # let the core resolve the top affected class
        else:
            classes = [mode]  # a specific class
        for cls in classes:
            try:
                results.append(await _generate_remediation_draft(
                    request, session, user, framework, tid, body.namespace, cls, body.range))
            except HTTPException as exc:
                results.append({"status": "error", "technique_id": tid, "cls": cls,
                                "framework": framework, "http_status": exc.status_code, "message": exc.detail})
    drafts = [r for r in results if r.get("status") == "draft"]
    log.info("nrvq.api.mitre.generate_batch", framework=framework, techniques=len(body.technique_ids),
             mode=mode, drafts=len(drafts), items=len(results), actor=user.get("sub"), code="NRVQ-API-7081")
    return {"framework": framework, "namespace": body.namespace, "class_mode": mode,
            "requested": len(body.technique_ids), "drafts_created": len(drafts), "results": results}


# --------------------------------------------------------------------------------------------------
# Framework-neutral compliance routes — the correct surface name for a multi-framework feature. These
# DELEGATE to the /mitre/* handlers above with the framework taken from the path (no functional change; the
# /mitre/* routes stay as ATLAS-default back-compat aliases). Same auth + gating (the delegates re-check).
# --------------------------------------------------------------------------------------------------

@router.get("/compliance/{framework}/coverage")
async def compliance_coverage(
    framework: str,
    request: Request,
    namespace: str | None = Query(default=None),
    range: str = Query("24h"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Framework-neutral coverage (atlas|owasp from the path). Same data as /mitre/coverage?framework=…"""
    return await mitre_coverage(request, namespace, range, framework, user, session)


@router.get("/compliance/{framework}/trend")
async def compliance_trend(
    framework: str,
    namespace: str | None = Query(default=None),
    range: str = Query("30d"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await mitre_trend(namespace, range, framework, user, session)


@router.get("/compliance/{framework}/export")
async def compliance_export(
    framework: str,
    request: Request,
    namespace: str | None = Query(default=None),
    range: str = Query("24h"),
    format: Literal["json", "pdf"] = Query("json"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    return await mitre_export(request, namespace, range, framework, format, user, session)


@router.post("/compliance/{framework}/generate")
async def compliance_generate(
    framework: str,
    body: GenerateRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Framework-neutral GAP→generate; the path framework wins over any framework in the body."""
    body = body.model_copy(update={"framework": _valid_framework(framework)})
    return await mitre_generate(body, request, user, session, _target)


@router.post("/compliance/{framework}/generate-batch")
async def compliance_generate_batch(
    framework: str,
    body: GenerateBatchRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Framework-neutral multi-select generate; the path framework wins over any framework in the body."""
    body = body.model_copy(update={"framework": _valid_framework(framework)})
    return await mitre_generate_batch(body, request, user, session, _target)


# --------------------------------------------------------------------------------------------------
# minimal, dependency-free PDF (single page) for the evidence pack
# --------------------------------------------------------------------------------------------------

def _evidence_pdf(pack: dict) -> bytes:
    """Render a minimal, VALID single-page PDF summary of the evidence pack — no external dependency, no egress.
    (The JSON export carries the full machine-readable pack; the PDF is the human-readable summary.)"""
    excluded = int(pack.get("synthetic_excluded") or 0)
    lines = [
        f"Norviq — {pack['framework']} Evidence Pack",
        f"Namespace: {pack['namespace'] or 'all'}   Range: {pack['range']}",
        f"Generated: {pack['generated_at']}",
        f"Coverage: {pack['coverage_pct']}%  (enforced {pack['enforced']} / {pack['enforceable_total']} enforceable)",
        f"Gaps: {pack['gap']}   Out-of-scope: {pack['out_of_scope']}   Blocked over range: {pack['blocked_over_range']}",
    ]
    # COMP-EVIDENCE: real-traffic-only promise — synthetic/simulated + red-team events are excluded from the
    # counts above; state how many, matching the console line.
    if excluded > 0:
        lines.append(f"Real traffic only · {excluded} synthetic/simulated event{'' if excluded == 1 else 's'} excluded")
    lines.append("")
    for c in pack["controls"]:
        lines.append(f"{c['technique_id']}  {c['name']}  [{c['status']}]  blocked={c['blocked']}")
        if c["enforcing_policies"]:
            lines.append(f"    rules: {', '.join(c['enforcing_policies'])}")

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    text_ops = "BT /F1 9 Tf 40 800 Td 11 TL\n"
    for ln in lines:
        text_ops += f"({esc(ln[:110])}) Tj T*\n"
    text_ops += "ET"
    stream = text_ops.encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return out
