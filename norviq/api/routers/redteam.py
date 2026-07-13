# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API routes for red-team simulation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import AgentRegistryEntry, RedTeamRun
from norviq.api.db.session import get_session
from norviq.api.redteam_efficacy import attack_mapping, catalog_entry, compute_efficacy
from norviq.api.synthetic import is_synthetic_identity
from norviq.config import settings
from norviq.redteam.attacks import ATTACKS, AttackCategory, get_attack_by_id
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

log = structlog.get_logger()
router = APIRouter()
# In-process cache of the last runs (fast path); the durable record lives in the redteam_runs table (B2).
REPORTS: dict[str, dict] = {}

# F-44: when no real agent class is seeded yet, fall back to this synthetic identity so the suite still runs.
_FALLBACK_TARGET = "redteam-test"

# D1: per-namespace in-flight guard. A suite run is long; two concurrent runs for the same namespace waste the
# engine and race the retention prune. This maps namespace -> the in-flight run_id so a second concurrent POST
# is rejected (409) with the id of the run already going. In-process is sufficient: the guard's job is to stop
# a double-submit (UI double-click or a rapid scripted repeat) against a single API process.
_INFLIGHT_SUITES: dict[str, str] = {}

# LOW/MED-4: process-wide cap on concurrently EXECUTING suites, on top of the per-namespace guard above. The
# per-namespace guard alone lets an admin fan out one suite per namespace simultaneously — each suite is
# len(targets) x len(ATTACKS) evaluate() calls plus a DB persist, so an unbounded fan-out across namespaces is
# still an engine/DB load spike. Module-level (not per-request) so it is shared by every request in this
# process; a 409 (like the per-namespace guard) is more honest than silently queuing an admin-triggered scan.
_SUITE_GLOBAL_GATE = asyncio.Semaphore(settings.redteam_suite_global_concurrency)


async def _seeded_classes(session: AsyncSession, namespace: str) -> list[str]:
    """D2 (run-writer fix): distinct REAL agent classes seeded in a namespace.

    Reserved ``__scopes__`` are excluded, and — new — synthetic/probe identities (allowlist-probe-*, scorer,
    policy-tester, wave\\de2e, …) are excluded via ``is_synthetic_identity``. Without this the suite evaluated
    AND STORED every synthetic class in the namespace (e.g. ~84 allowlist-probe-* → ~2,436 rows that the
    efficacy roll-up already discards), bloating each run's stored matrix. Scoping the writer to real classes
    keeps a run's results meaningful and bounded (the view still paginates on top of this)."""
    rows = await session.execute(
        select(AgentRegistryEntry.agent_class)
        .where(AgentRegistryEntry.namespace == namespace)
        .distinct()
    )
    return sorted(
        c for c in rows.scalars().all()
        if c and not c.startswith("__") and not is_synthetic_identity(c)
    )


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
    # D1: reject a concurrent run for the same namespace (double-click / scripted double-submit) — return the
    # in-flight run_id so the caller can watch it instead of starting a second identical run. Registered here,
    # before any await into the run, so the check-and-set is atomic under asyncio (no interleaving in between).
    if target_namespace in _INFLIGHT_SUITES:
        inflight = _INFLIGHT_SUITES[target_namespace]
        log.info("nrvq.redteam.suite_concurrent_rejected", namespace=target_namespace, inflight_run_id=inflight,
                 code="NRVQ-RED-13008")
        raise HTTPException(
            status_code=409,
            detail={"error": "a red-team suite is already running for this namespace", "run_id": inflight},
        )
    run_id = str(uuid4())
    _INFLIGHT_SUITES[target_namespace] = run_id
    try:
        # LOW/MED-4: bound how many suites (across ALL namespaces) actually execute at once — the
        # _INFLIGHT_SUITES check above only stops a double-submit for THIS namespace. Acquired AFTER the
        # per-namespace guard so a rejected double-submit never occupies a global slot; released before
        # `finally` pops the namespace so a queued suite behind this one can start as soon as the engine
        # work is done (the namespace guard is only cleared once the whole persist is done, on purpose).
        async with _SUITE_GLOBAL_GATE:
            if target_agent:
                targets = [target_agent]
            else:
                targets = await _seeded_classes(session, target_namespace) or [_FALLBACK_TARGET]
            # A sector-pack attack is only APPLICABLE when its enforcing rule is actually loaded for this
            # namespace (i.e. the operator enabled that pack). Same "rule present" test the coverage metric uses,
            # so a baseline-only namespace isn't scored against controls it never opted into.
            ns_rego = _loaded_rego(request, target_namespace)
            results = []
            for agent_class in targets:
                for attack in ATTACKS:
                    event = _build_event(attack, agent_class, target_namespace)
                    applicable = _attack_applicable(attack, ns_rego)
                    try:
                        decision = await request.app.state.evaluator.evaluate(event)
                        results.append(_result_row(attack, agent_class, target_namespace, decision.decision, decision.rule_id, decision.latency_ms, applicable))
                    except Exception as exc:
                        results.append(_error_row(attack, agent_class, target_namespace, str(exc)))
            passed = sum(1 for item in results if item.get("passed"))
            efficacy = compute_efficacy(results)  # B3: caught-vs-got-through roll-up (synthetic excluded)
            report = {
                "run_id": run_id,
                "namespace": target_namespace,
                "targets": targets,
                "total": len(results),
                "passed": passed,
                "failed": len(results) - passed,
                "pass_rate": round(passed / len(results) * 100, 1) if results else 0,
                "results": results,
                "efficacy": efficacy,
            }
            REPORTS[run_id] = report
            # B2: persist the run durably + prune to the retention window (read-only evidence; never enforces).
            created_at = await _persist_run(session, report, str(user.get("sub") or ""))
            if created_at is not None:
                report["created_at"] = created_at
    finally:
        # always release the namespace, even if the run raised, so a failed run never wedges the guard.
        _INFLIGHT_SUITES.pop(target_namespace, None)
    log.info("nrvq.redteam.suite_run", namespace=target_namespace, targets=targets,
             total=len(results), passed=passed, proven_blocking_pct=efficacy["overall"]["proven_blocking_pct"],
             code="NRVQ-RED-13006")
    return report


def plan_retention(
    runs: list[tuple[str, datetime]],
    *,
    now: datetime,
    detail_runs: int,
    detail_ttl: timedelta,
    summary_runs: int,
    summary_ttl: timedelta,
) -> tuple[set[str], set[str]]:
    """D3 (pure, DB-free): decide the two-tier retention for ONE namespace's runs.

    ``runs`` is ``(run_id, created_at)`` for the namespace. Returns ``(delete_ids, detail_prune_ids)``:
      • delete_ids       — rows to remove entirely (beyond the summary count OR older than the summary TTL).
      • detail_prune_ids — rows whose per-attack ``results`` are nulled (kept as SUMMARY only) because they are
        beyond the detail count OR older than the detail TTL (and not already being deleted).
    A run is KEPT at a tier only while it is within BOTH that tier's count window AND its age window ("up to K
    runs / D days"), so a burst of runs in one day is bounded by COUNT and a long idle gap is bounded by AGE.
    SAFETY: the single newest run is NEVER placed in either set — its detail + summary are always retained, so
    ``/redteam/results/latest`` can always return full detail.
    """
    ordered = sorted(runs, key=lambda r: r[1], reverse=True)  # newest first
    if not ordered:
        return set(), set()
    latest_id = ordered[0][0]
    keep_detail = {r[0] for r in ordered[:detail_runs]}
    keep_summary = {r[0] for r in ordered[:summary_runs]}
    delete: set[str] = set()
    detail_prune: set[str] = set()
    for rid, ts in ordered:
        if rid == latest_id:
            continue  # SAFETY: never touch the latest run
        age = now - ts
        if rid not in keep_summary or age > summary_ttl:
            delete.add(rid)  # gone entirely — beyond the summary count OR older than the summary TTL
        elif rid not in keep_detail or age > detail_ttl:
            detail_prune.add(rid)  # summary kept, detail nulled — beyond the detail count OR older than its TTL
    return delete, detail_prune


async def _persist_run(session: AsyncSession, report: dict[str, Any], created_by: str) -> str | None:
    """B2/D3: write one RedTeamRun row, then apply two-tier retention for its namespace (delete old rows beyond
    the summary window; detail-prune mid-age rows to summary-only). Best-effort — a DB hiccup must not fail the
    run itself (the report is still returned + cached in REPORTS)."""
    ns = report["namespace"]
    try:
        row = RedTeamRun(
            id=report["run_id"], namespace=ns, targets=report["targets"],
            total=report["total"], passed=report["passed"], failed=report["failed"],
            pass_rate=report["pass_rate"], results=report["results"], efficacy=report["efficacy"],
            created_by=created_by,
        )
        session.add(row)
        await session.commit()
        # D3: two-tier retention, scoped to THIS namespace. Anchor "now" on the just-written row's timestamp.
        now = row.created_at or datetime.now(timezone.utc)
        ns_runs = (await session.execute(
            select(RedTeamRun.id, RedTeamRun.created_at).where(RedTeamRun.namespace == ns)
        )).all()
        delete_ids, detail_ids = plan_retention(
            [(r[0], r[1]) for r in ns_runs],
            now=now,
            detail_runs=settings.redteam_detail_keep_runs,
            detail_ttl=timedelta(days=settings.redteam_detail_keep_days),
            summary_runs=settings.redteam_summary_keep_runs,
            summary_ttl=timedelta(days=settings.redteam_summary_keep_days),
        )
        if delete_ids:
            await session.execute(RedTeamRun.__table__.delete().where(RedTeamRun.id.in_(delete_ids)))
        if detail_ids:
            await session.execute(
                RedTeamRun.__table__.update().where(RedTeamRun.id.in_(detail_ids)).values(results=None)
            )
        if delete_ids or detail_ids:
            await session.commit()
            log.info("nrvq.redteam.retention", namespace=ns, deleted=len(delete_ids),
                     detail_pruned=len(detail_ids), code="NRVQ-RED-13009")
        return row.created_at.isoformat() if row.created_at else None
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("nrvq.redteam.persist_failed", run_id=report.get("run_id"), error=str(exc),
                    code="NRVQ-RED-13007")
        try:
            await session.rollback()
        except Exception:  # nosec B110 - best-effort rollback; the run result is still returned to the caller
            log.debug("nrvq.redteam.rollback_failed", run_id=report.get("run_id"))
        return None


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
    """B1: the red-team attack catalog, each entry mapped to its MITRE ATLAS technique + OWASP LLM control
    (display names resolved from the shipped compliance mappings)."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    log.info("nrvq.redteam.catalog_loaded", total=len(ATTACKS), code="NRVQ-RED-13004")
    return [catalog_entry(attack) for attack in ATTACKS]


@router.get("/redteam/results/latest")
async def latest_result(
    namespace: str | None = None,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """B2/B3: the most recent DURABLE run (full results + efficacy roll-up). Honest empty state when none exist:
    ``{"has_run": false}`` — the Red Team view + the Compliance/Overview efficacy overlay (F2) read this.

    STALE-4: scope to a namespace when given (a concrete ns other than the "all" aggregate) so the efficacy
    a page shows belongs to the namespace it displays — not whatever cluster-wide run happened to be newest.
    """
    require_admin(user)
    q = select(RedTeamRun).order_by(RedTeamRun.created_at.desc())
    if namespace and namespace != "all":
        q = q.where(RedTeamRun.namespace == namespace)
    row = (await session.execute(q.limit(1))).scalars().first()
    if row is None:
        return {"has_run": False}
    return {"has_run": True, **_run_to_dict(row)}


@router.get("/redteam/results")
async def list_results(
    limit: int = 0,
    offset: int = 0,
    namespace: str | None = None,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """B2/F1/D3: recent run history — SUMMARIES ONLY (no per-attack detail), newest first, bounded + paginated.
    Never returns every run's detail (that is what blew up the DB); the page size is capped by config.

    STALE-4: optional namespace filter so the history table matches the selected scope.
    """
    require_admin(user)
    cap = settings.redteam_summary_keep_runs
    page = settings.redteam_history_page_size if limit <= 0 else limit
    page = max(1, min(page, cap))
    offset = max(0, offset)
    scoped = namespace and namespace != "all"
    count_q = select(func.count()).select_from(RedTeamRun)
    rows_q = select(RedTeamRun).order_by(RedTeamRun.created_at.desc())
    if scoped:
        count_q = count_q.where(RedTeamRun.namespace == namespace)
        rows_q = rows_q.where(RedTeamRun.namespace == namespace)
    total = (await session.execute(count_q)).scalar() or 0
    rows = (await session.execute(rows_q.offset(offset).limit(page))).scalars().all()
    return {"runs": [_run_summary(r) for r in rows], "total": int(total), "offset": offset, "limit": page}


@router.get("/redteam/results/{run_id}")
async def get_result(
    run_id: str,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """B2: fetch one durable run by id (falls back to the in-process cache for a run from this process)."""
    require_admin(user)
    row = (await session.execute(
        select(RedTeamRun).where(RedTeamRun.id == run_id)
    )).scalars().first()
    if row is not None:
        return _run_to_dict(row)
    if run_id in REPORTS:
        return REPORTS[run_id]
    raise HTTPException(status_code=404, detail="Run not found")


@router.get("/redteam/report/{run_id}")
async def get_report(run_id: str, user: dict = Depends(get_current_user)) -> dict:
    """Fetch a previously generated suite report from the in-process cache (kept for back-compat; durable reads
    should use /redteam/results/{run_id})."""
    require_admin(user)  # F-43: red-team is admin-only (was any authenticated role)
    if run_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    return REPORTS[run_id]


def _run_summary(row: RedTeamRun) -> dict[str, Any]:
    """Lightweight run summary for the history list (no full result rows)."""
    eff = row.efficacy or {}
    overall = eff.get("overall", {}) if isinstance(eff, dict) else {}
    return {
        "run_id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "namespace": row.namespace,
        "targets": row.targets,
        "total": row.total,
        "passed": row.passed,
        "failed": row.failed,
        "pass_rate": row.pass_rate,
        "proven_blocking_pct": overall.get("proven_blocking_pct", 0.0),
        "caught": overall.get("caught", 0),
        "got_through": overall.get("got_through", 0),
    }


def _run_to_dict(row: RedTeamRun) -> dict[str, Any]:
    """Serialize a persisted RedTeamRun row to the same shape the suite endpoint returns. D3: if the run's
    per-attack detail has been retention-pruned (``results IS NULL``), return an empty results list plus
    ``detail_pruned=true`` so the caller knows the summary (efficacy) is authoritative but the rows are gone."""
    pruned = row.results is None
    return {
        "run_id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "namespace": row.namespace,
        "targets": row.targets,
        "total": row.total,
        "passed": row.passed,
        "failed": row.failed,
        "pass_rate": row.pass_rate,
        "results": row.results or [],
        "detail_pruned": pruned,
        "efficacy": row.efficacy,
    }


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


def _mapping_fields(attack: Any) -> dict[str, Any]:
    """B1/B3: the ATLAS/OWASP mapping fields carried on every result row so the efficacy roll-up can group by
    technique + control without re-deriving them."""
    m = attack_mapping(attack)
    return {
        "atlas_technique": m["atlas"]["technique_id"],
        "atlas_technique_name": m["atlas"]["technique_name"],
        "owasp_control": m["owasp"]["control_id"] if m["owasp"] else None,
        "owasp_control_name": m["owasp"]["control_name"] if m["owasp"] else None,
    }


def _loaded_rego(request: Request, namespace: str) -> str:
    """The concatenated rego actually loaded for a namespace (+ the cluster baseline) — used to tell whether
    a sector pack is enabled (its rules present). Mirrors the coverage route's loader read."""
    loader = getattr(request.app.state, "loader", None)
    if loader is None:
        return ""
    blob = ""
    for key, entry in loader._policies.items():
        ns = key.split(":", 1)[0]
        if ns in (namespace, "__cluster__"):
            blob += str(entry.get("rego", ""))
    return blob


def _attack_applicable(attack: Any, ns_rego: str) -> bool:
    """A non-sector attack always applies. A SECTOR_POLICY attack applies only when its enforcing rule is
    loaded for the namespace (the pack is enabled) — otherwise it's out of scope, not a real miss."""
    if attack.category != AttackCategory.SECTOR_POLICY:
        return True
    return bool(attack.expected_rule and attack.expected_rule in ns_rego)


def _result_row(attack: Any, agent_class: str, namespace: str, actual: str, rule_id: str, latency_ms: float, applicable: bool = True) -> dict[str, Any]:
    """Build one successful suite row (F-44: carries the evaluated identity; B1: carries the ATLAS/OWASP map).

    ``applicable``=False marks a SECTOR_POLICY attack whose enforcing rule is not loaded for this namespace
    (the sector pack was never enabled). Such a row is NOT a real "got through" — the operator never opted
    into that control — so compute_efficacy excludes it from the proven-blocking denominator and the UI
    labels it "pack not enabled" instead of a red miss."""
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
        "applicable": applicable,
        "latency_ms": latency_ms,
        **_mapping_fields(attack),
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
        **_mapping_fields(attack),
    }
