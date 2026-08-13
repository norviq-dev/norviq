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
from norviq.redteam.vectors import vector_title
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

log = structlog.get_logger()
router = APIRouter()
# In-process cache of the last runs (fast path); the durable record lives in the redteam_runs table.
REPORTS: dict[str, dict] = {}

# When no real agent class is seeded yet, fall back to this synthetic identity so the suite still runs.
_FALLBACK_TARGET = "redteam-test"

# Per-namespace in-flight guard. A suite run is long; two concurrent runs for the same namespace waste the
# engine and race the retention prune. Maps namespace -> the in-flight run_id so a second concurrent POST is
# rejected (409) with the id of the run already going.
#
# THIS DICT ALONE IS NOT THE GUARD, and the comment that used to sit here said it was. It claimed
# "in-process is sufficient ... against a single API process" — but the chart ships `api.replicas: 2`
# (helm/norviq/values.yaml), so the two halves of a double-submit are load-balanced to DIFFERENT pods,
# each consults its own dict, and both start a run. Measured against the deployed 2-replica service:
# four of six paired POSTs returned `200 200`, i.e. the guard did not fire at all most of the time.
#
# The authoritative guard is now a Redis lock (Redis is already a hard dependency, and `SET NX EX` is
# atomic across pods). The dict is kept as an in-process fast path and as the fallback when Redis is
# unreachable — degrading to the old single-process behaviour is better than degrading to none.
_INFLIGHT_SUITES: dict[str, str] = {}

# Long enough to outlive a real suite (len(targets) x len(ATTACKS) evaluations plus the persist), short
# enough that a pod dying mid-run does not wedge the namespace for long. The `finally` releases it on
# every normal path; this bound only covers the crash.
_SUITE_LOCK_TTL_S = 900

# Process-wide cap on concurrently EXECUTING suites, on top of the per-namespace guard above. The
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


def _reject_unknown_query_params(request: Request, accepted: set[str]) -> None:
    """422 on any query parameter this route does not declare.

    FastAPI ignores undeclared query params, which is the right default for most routes and exactly
    wrong for a measurement one: `?namespace=chatbot-lab` was dropped, the suite ran against the
    `default` scope, and the report came back with a pass_rate for a namespace nobody asked about.
    The operator has no way to tell that from a real result.

    The error names the accepted parameters, because the whole failure mode is that the caller used a
    plausible-but-wrong name and had no signal.
    """
    unknown = sorted(set(request.query_params.keys()) - accepted)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=(
                f"unknown query parameter(s): {', '.join(unknown)}. "
                f"This endpoint accepts: {', '.join(sorted(accepted))}. "
                "Refused rather than ignored — an ignored scope parameter means the report you get "
                "back measures a different scope than the one you asked for."
            ),
        )


@router.post("/redteam/run")
async def run_attack(
    attack_id: str,
    request: Request,
    target_agent: str = _FALLBACK_TARGET,
    target_namespace: str = "default",
    user: dict = Depends(get_current_user),
) -> dict:
    """Run one red-team attack against the in-process evaluator, as a chosen target identity."""
    require_admin(user)  # red-team is admin-only
    attack = get_attack_by_id(attack_id)
    if attack is None:
        raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")
    event = _build_event(attack, target_agent, target_namespace)
    decision = await request.app.state.evaluator.evaluate(event)
    _emit_redteam_audit(request, event, decision)
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
    """Run the full red-team suite. Target-aware — evaluates every attack against each seeded agent class
    in the namespace (or one explicit class), so the report reflects the deployed sector posture, not a synthetic
    identity. Each result row carries the agent_class/namespace it was evaluated against."""
    require_admin(user)  # red-team is admin-only
    # MEASUREMENT INTEGRITY (F-014). `namespace=` and `agent_class=` are the names an operator reaches
    # for, and FastAPI silently ignores query params it does not declare — so the suite ran against
    # `default`, which on most installs has no baseline, and reported pass_rate 5.9% for a namespace
    # that was actually at 82.4%. A scan that measures the wrong scope and says nothing is worse than
    # one that refuses: the operator acts on the number.
    _reject_unknown_query_params(request, {"target_agent", "target_namespace"})
    # Reject a concurrent run for the same namespace (double-click / scripted double-submit) — return the
    # in-flight run_id so the caller can watch it instead of starting a second identical run. Registered here,
    # before any await into the run, so the check-and-set is atomic under asyncio (no interleaving in between).
    run_id = str(uuid4())
    cache = getattr(request.app.state, "cache", None)

    # In-process first: free, and it catches a double-click that lands on this same pod.
    inflight = _INFLIGHT_SUITES.get(target_namespace)
    if inflight is None and cache is not None:
        # ...then the cross-replica lock, which is the one that actually holds under the chart's
        # default 2-replica topology. Failure to reach Redis must not block an admin-triggered scan,
        # so an error here degrades to the in-process guard rather than refusing.
        try:
            inflight = await cache.acquire_lock(f"redteam:suite:{target_namespace}", run_id, _SUITE_LOCK_TTL_S)
        except Exception as exc:  # noqa: BLE001 - a guard outage must not deny the operation it guards
            log.warning("nrvq.redteam.suite_lock_unavailable", namespace=target_namespace,
                        error=str(exc)[:200], code="NRVQ-RED-13009")
            inflight = None
    if inflight:
        log.info("nrvq.redteam.suite_concurrent_rejected", namespace=target_namespace, inflight_run_id=inflight,
                 code="NRVQ-RED-13008")
        raise HTTPException(
            status_code=409,
            detail={"error": "a red-team suite is already running for this namespace", "run_id": inflight},
        )
    _INFLIGHT_SUITES[target_namespace] = run_id
    try:
        # Bound how many suites (across ALL namespaces) actually execute at once — the
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
                        _emit_redteam_audit(request, event, decision)
                        results.append(_result_row(attack, agent_class, target_namespace, decision.decision, decision.rule_id, decision.latency_ms, applicable))
                    except Exception as exc:
                        results.append(_error_row(attack, agent_class, target_namespace, str(exc)))
            passed = sum(1 for item in results if item.get("passed"))
            efficacy = compute_efficacy(results)  # caught-vs-got-through roll-up (synthetic excluded)
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
                # WHAT WAS ACTUALLY MEASURED (F-014). A pass_rate is meaningless without it, and the
                # reported failure was exactly this: 5.9% for a namespace with no policies loaded read
                # as "our controls are broken" when it meant "this scope is empty". The number and the
                # scope it describes now travel together, so a report cannot be quoted without it.
                #
                # `scope_empty` is the honest distinction between "we tested your posture and it is
                # bad" and "there was nothing here to test". `targets_are_fallback` says the same
                # thing about the agent side: no real class was seeded, so the synthetic
                # `redteam-test` identity was scored instead of anything the operator deployed.
                "scope": {
                    "namespace": target_namespace,
                    "agent_classes": targets,
                    "targets_are_fallback": targets == [_FALLBACK_TARGET],
                    "policy_rules_loaded": bool(ns_rego),
                    "scope_empty": not ns_rego,
                },
            }
            if not ns_rego:
                log.warning(
                    "nrvq.redteam.suite_scope_empty",
                    namespace=target_namespace,
                    pass_rate=report["pass_rate"],
                    code="NRVQ-RED-13011",
                )
            REPORTS[run_id] = report
            # Persist the run durably + prune to the retention window (read-only evidence; never enforces).
            created_at = await _persist_run(session, report, str(user.get("sub") or ""))
            if created_at is not None:
                report["created_at"] = created_at
    finally:
        # always release the namespace, even if the run raised, so a failed run never wedges the guard.
        _INFLIGHT_SUITES.pop(target_namespace, None)
        if cache is not None:
            try:
                await cache.release_lock(f"redteam:suite:{target_namespace}", run_id)
            except Exception as exc:  # noqa: BLE001 - the TTL is the backstop; never mask the real result
                log.warning("nrvq.redteam.suite_lock_release_failed", namespace=target_namespace,
                            error=str(exc)[:200], code="NRVQ-RED-13010")
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
    """Write one RedTeamRun row, then apply two-tier retention for its namespace (delete old rows beyond
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
        # Two-tier retention, scoped to THIS namespace. Anchor "now" on the just-written row's timestamp.
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
    """The real agent classes seeded in a namespace, for the Policy-Tester/red-team target selector."""
    require_admin(user)  # red-team is admin-only
    return {"namespace": namespace, "targets": await _seeded_classes(session, namespace)}


@router.get("/redteam/catalog")
async def get_catalog(user: dict = Depends(get_current_user)) -> list[dict]:
    """The red-team attack catalog, each entry mapped to its MITRE ATLAS technique + OWASP LLM control
    (display names resolved from the shipped compliance mappings)."""
    require_admin(user)  # red-team is admin-only
    log.info("nrvq.redteam.catalog_loaded", total=len(ATTACKS), code="NRVQ-RED-13004")
    return [catalog_entry(attack) for attack in ATTACKS]


@router.get("/redteam/results/latest")
async def latest_result(
    namespace: str | None = None,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """The most recent DURABLE run (full results + efficacy roll-up). Honest empty state when none exist:
    ``{"has_run": false}`` — the Red Team view + the Compliance/Overview efficacy overlay read this.

    Scope to a namespace when given (a concrete ns other than the "all" aggregate) so the efficacy
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
    """Recent run history — SUMMARIES ONLY (no per-attack detail), newest first, bounded + paginated.
    Never returns every run's detail (that is what blew up the DB); the page size is capped by config.

    Optional namespace filter so the history table matches the selected scope.
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
    """Fetch one durable run by id (falls back to the in-process cache for a run from this process)."""
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
    require_admin(user)  # red-team is admin-only
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
    """Serialize a persisted RedTeamRun row to the same shape the suite endpoint returns. If the run's
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


def _emit_redteam_audit(request: Request, event: ToolCallEvent, decision: Any) -> None:
    """Write the attack's decision to the audit log, tagged framework="redteam".

    The engine's own _emit_audit only LOGS ("minimal non-blocking emission until dedicated pipeline
    integration") — the DB row is written by the /api/v1/evaluate ROUTE via the emitter. Red team calls
    evaluator.evaluate() directly, so its decisions never reached the audit log at all, while the
    Overview told operators red-team rows were "excluded from counts but visible in the Audit Log" and
    each result linked to Audit as its evidence. That link resolved to unrelated production traffic
    that happened to share a rule_id.

    Safe to write: framework="redteam" is already excluded from real-traffic counts by the same
    is_synthetic/framework filters the Overview uses, so this adds evidence without moving any metric.
    Best-effort — a red-team run must never fail because audit is unavailable.
    """
    emitter = getattr(request.app.state, "emitter", None)
    if emitter is None:
        return
    try:
        emitter.emit(event, decision)
    except Exception as exc:  # noqa: BLE001 - evidence is best-effort; the run's own result store is authoritative
        log.warning("nrvq.api.redteam.audit_emit_failed", error=str(exc), code="NRVQ-API-7092")


def _build_event(attack: Any, target_agent: str, target_namespace: str) -> ToolCallEvent:
    """Build a tool-call event for one attack as a target identity. Each class gets its own SVID so it picks
    up its own trust history; thread a chained-call `depth` param into the event's call_depth so chain-depth
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
        # Tag the decision source so the audit row is EXCLUDED from real-traffic counts by the same
        # framework filter the Overview uses. Without this the row lands untagged and synthetic
        # attack volume would inflate the operator's live metrics.
        framework="redteam",
        session_id=f"redteam-{attack.id}",
        call_depth=int(depth) if isinstance(depth, (int, str)) and str(depth).isdigit() else 0,
        # Gate-A context, published to rego as `input.mcp`. Empty for every non-MCP attack, which is
        # the same document a plain SDK call presents, so nothing about the existing 29 changes.
        # COPY it: `ATTACKS` is a module constant built once at import, and handing the same dict to
        # every event in every run makes any future mutation an untraceable cross-run bug.
        mcp=dict(getattr(attack, "mcp_context", None) or {}),
    )


def _mapping_fields(attack: Any) -> dict[str, Any]:
    """The ATLAS/OWASP mapping fields carried on every result row so the efficacy roll-up can group by
    technique + control without re-deriving them."""
    m = attack_mapping(attack)
    return {
        "atlas_technique": m["atlas"]["technique_id"],
        "atlas_technique_name": m["atlas"]["technique_name"],
        "owasp_control": m["owasp"]["control_id"] if m["owasp"] else None,
        "owasp_control_name": m["owasp"]["control_name"] if m["owasp"] else None,
        # None, not "", for an attack with no MCP vector — `compute_efficacy` skips falsy vectors, and
        # None reads as "this attack exercises no MCP vector" rather than as an empty vector id.
        "mcp_vector": getattr(attack, "mcp_vector", "") or None,
        "mcp_vector_title": vector_title(attack.mcp_vector) if getattr(attack, "mcp_vector", "") else None,
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


# Categories whose enforcing rule is CONDITIONAL on an operator having loaded something — a sector
# pack, or the opt-in MCP integration guardrail. Verified: no shipped baseline reads `input.mcp` at all
# (strict/moderate/permissive/comprehensive, zero references), so an MCP attack in a namespace without
# the guardrail can never be blocked and would score got_through forever, with no operator action that
# fixes it. That is not a miss, it is a control that was never installed — and reporting it as a miss
# would paint every default namespace red on the day this ships.
_CONDITIONAL_CATEGORIES = frozenset(
    {AttackCategory.SECTOR_POLICY, AttackCategory.MCP_IDENTITY}
)


def _attack_applicable(attack: Any, ns_rego: str) -> bool:
    """An unconditional attack always applies. A conditional one (sector pack, MCP guardrail) applies only
    when its enforcing rule is loaded for the namespace — otherwise it's out of scope, not a real miss.

    POLICY_COMPOSITION is deliberately NOT conditional: its expected rules are baseline blocks that ship
    everywhere, so the question it asks — did this class's own policy override the baseline? — is always
    a fair one to ask."""
    if attack.category not in _CONDITIONAL_CATEGORIES:
        return True
    return bool(attack.expected_rule and attack.expected_rule in ns_rego)


def _result_row(attack: Any, agent_class: str, namespace: str, actual: str, rule_id: str, latency_ms: float, applicable: bool = True) -> dict[str, Any]:
    """Build one successful suite row (carries the evaluated identity + the ATLAS/OWASP map).

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
