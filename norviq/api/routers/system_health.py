# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Ongoing-issue surface for the console banner.

A governance product failing is not self-announcing: when the engine is unreachable the sidecars
quietly fail closed, every agent's tool calls stop working, and the operator's first signal is a user
complaining that the bot "got dumber". Worse in the other direction — with a fail-open posture the
tool calls are forwarded UNGOVERNED and nothing visibly changes at all.

This route answers one question: *is something wrong right now?* It reports only what it can prove
from data this deployment already owns — the decisions the data plane actually recorded — so it never
claims an outage it cannot substantiate. Each issue carries the evidence and the remediation.

That cuts BOTH ways, and the second half used to be missing. "No infrastructure verdicts in the
window" is not proof of health: the loudest outages are the ones that stop anything from being
written at all. So the route also has to be able to answer *I do not know*:

* Two of the rule_ids below (``thin_proxy_fail_open`` / ``thin_proxy_fail_closed``) are minted by the
  THIN-PROXY sidecar, which by design has no local emitter — ``SidecarProxy.start`` sets
  ``self._emitter = None`` in proxy mode because "the central /evaluate persisted the record", and the
  central /evaluate is exactly what is unreachable when those verdicts fire. ``engine_rejected_request``
  is the same shape from the SDK/MCP gateway side. They are kept here because they are the right keys
  the day a producer can deliver them (a sidecar-side counter POSTed on reconnect), but nothing writes
  them to ``audit_log`` today, and this module must not pretend otherwise.
* ``evaluator_error`` and ``policy_load_pending`` DO reach ``audit_log``: the engine mints them
  (evaluator.py) and they travel back out through the API's own emitter, so the API is by definition
  up when they are recorded. They are the substantiable half of "Norviq itself is the problem".
* And when the window holds NO REAL recorded decisions, the data plane is either idle or severed —
  indistinguishable from here. That is reported as ``status: "unknown"``, never as ``"ok"``. "Real"
  is doing work in that sentence: the Policy Tester and the red-team runner both write ``audit_log``
  rows through this API's OWN emitter with no data plane in the loop, so counting them would let the
  console manufacture its own all-clear. The liveness count applies the shared
  ``audit_row_is_non_real`` filter; the incident query above deliberately does not.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.synthetic import audit_row_is_non_real  # the ONE shared real-traffic filter (do not fork)
from norviq.engine.evaluator import WOULD_BLOCK_RULE_PREFIXES

log = structlog.get_logger()
router = APIRouter()

# How far back "ongoing" reaches. Long enough to survive a gap between polls, short enough that a
# resolved incident clears on its own rather than sticking until someone dismisses it.
_WINDOW_MINUTES = 15

# rule_ids the data plane writes when the decision did NOT come from policy. These are the ground
# truth for "Norviq itself is the problem" — every one is an infrastructure verdict, not a rule.
_INFRA_RULE_IDS = {
    # The engine was unreachable and the posture is fail-closed: real tool calls are being refused.
    "thin_proxy_fail_closed": (
        "critical",
        "Agents are being blocked by an engine outage",
        "The policy engine is unreachable, so governed tool calls are failing closed. Agents can still "
        "converse, but every tool call is refused until the engine recovers.",
        "Check norviq-api and norviq-engine pods, and the sidecars' NRVQ_API_URL connectivity.",
    ),
    # The engine was unreachable and the posture is fail-open: calls are running UNGOVERNED.
    "thin_proxy_fail_open": (
        "critical",
        "Tool calls are running UNGOVERNED",
        "The policy engine is unreachable and the configured fallback posture is 'allow', so tool "
        "calls are being forwarded without evaluation. No policy is being enforced on them.",
        "Restore the engine. To fail closed instead, set webhook.injection.fallbackMode=block.",
    ),
    # The engine ANSWERED and refused the caller — a credential/request fault, never an outage.
    "engine_rejected_request": (
        "critical",
        "Agents are being rejected by the engine",
        "The engine is reachable but refused these calls — typically an expired or wrong sidecar "
        "token, so the caller cannot be identified. Calls are blocked (this never fails open).",
        "Check the sidecar's NRVQ_API_TOKEN and the API secret it was minted from; restart affected pods.",
    ),
    # --- the substantiable half: written by the ENGINE, carried out through the API's own emitter, so
    # --- the record exists precisely because the API was up to write it.
    # OPA evaluation failed persistently. The engine answered the sidecar, then could not decide, and
    # fail-closed blocked the call. Never a policy verdict — no rule denied it.
    #
    # It does NOT stay hard in monitor mode, and this comment used to say it did, naming a symbol
    # (`_POSTURE_EXEMPT_RULES`) that no longer exists. Monitor mode softens it deliberately — the whole
    # point of allow-by-default is that an engine fault must not drop customer traffic — which is
    # exactly why `_INFRA_RULE_VARIANTS` below folds the softened `monitor_would_block:` spelling back
    # to the bare id: the banner has to survive the softening, or this view goes dark in precisely the
    # namespaces most likely to be running monitor.
    "evaluator_error": (
        "critical",
        "Tool calls are being blocked by an engine fault",
        "The policy engine is reachable but its evaluations are failing, so calls are being refused "
        "fail-closed. These are engine errors, not policy decisions — no rule denied them.",
        "Check the OPA container/sidecar and norviq-engine logs (NRVQ-ENG-2057) for the failing query.",
    ),
    # The engine could not decide IN TIME. Same shape as `evaluator_error` and it was missing: a
    # fail-closed refusal of real traffic caused entirely by engine latency, with no rule behind it.
    # Excluding it meant the one outage an operator is most likely to actually have — the engine
    # slowing down under load rather than falling over — was the one the banner could not show.
    "evaluator_timeout": (
        "critical",
        "Tool calls are timing out in the engine",
        "The policy engine is reachable but not answering within the evaluation budget, so calls are "
        "being refused fail-closed. These are timeouts, not policy decisions — no rule denied them.",
        "Check norviq-engine and OPA latency and CPU, and the sdk_timeout_ms budget for this deployment.",
    ),
    # The generic fail-closed path: evaluation raised something unhandled. Rarer than the two above and
    # for that reason MORE interesting — it is the one that means nobody has seen this failure before.
    "evaluator_fallback": (
        "critical",
        "Tool calls are being refused by an unhandled engine fault",
        "Evaluation failed in a way the engine did not classify, so calls are being refused "
        "fail-closed. No rule denied them.",
        "Check norviq-engine logs for the unhandled exception (NRVQ-ENG-2003) around this window.",
    ),
    # DELIBERATELY ABSENT: `invalid_spiffe_identity`. It names a CALLER fault — a malformed or forged
    # identity — and a single spoof attempt raising "Norviq is down" is exactly the misdirection this
    # module's docstring warns about. The fleet-wide version of that failure (every sidecar suddenly
    # unable to authenticate) already has a key here in `engine_rejected_request`.
    # The policy subsystem had not finished warming when the call arrived. Transient at rollout; if it
    # persists, policy never loaded and everything governed is being refused.
    "policy_load_pending": (
        "critical",
        "Policy has not loaded — calls are being refused",
        "The policy subsystem was not ready when these calls arrived, so they were blocked fail-closed "
        "rather than evaluated against a policy that had not loaded yet.",
        "Expected briefly during a rollout. If it persists, check the policy loader and the DB/Redis it warms from.",
    ),
}


# An infra verdict recorded in a MONITOR-mode namespace is stored prefixed
# (`monitor_would_block:evaluator_error`), because monitor mode now softens operational blocks rather
# than dropping the customer's traffic. This route matched rule_ids exactly, so that softening would
# have taken the outage banner dark in precisely the namespaces most likely to be running monitor
# mode — trading "we no longer drop traffic during an engine fault" for "you can no longer see the
# engine fault", which is the worse of the two.
#
# The evidence is unchanged; only the key is decorated. So match every stored form and fold it back to
# the bare id. A softened verdict is still an outage — the operator needs it in the banner either way.
_INFRA_RULE_VARIANTS: dict[str, str] = {
    variant: rule_id
    for rule_id in _INFRA_RULE_IDS
    for variant in (rule_id, *(f"{prefix}{rule_id}" for prefix in WOULD_BLOCK_RULE_PREFIXES))
}

# Public: the rule ids the ENGINE mints for its own failures, as distinct from any policy decision.
#
# Exported because other surfaces must be able to exclude them. Monitor mode softens an operational
# block exactly like a real one, so these arrive elsewhere wearing the same `monitor_would_block:`
# prefix as a genuine control — and a compliance view that counts them tells the operator "38 calls
# would have been blocked" when the truth is "the evaluator errored 38 times". One list, here, next to
# the copy that explains each one.
INFRA_RULE_IDS: frozenset[str] = frozenset(_INFRA_RULE_IDS)


def infra_rule_for(rule_id: str) -> str | None:
    """The bare infrastructure rule a stored rule_id names, or None.

    One resolver, because the "is this an engine fault" question is now asked from three places and
    each fork got the softening wrong in its own way: this route matched exactly and went dark under
    monitor, /audit/stats matched exactly and undercounted engine errors, and /policy-compliance
    reported them as policy non-compliance. The stored spelling depends on whether the verdict was
    softened, which is a detail none of the callers should have to know.
    """
    return _INFRA_RULE_VARIANTS.get(rule_id)


def _issue(rule_id: str, count: int, last_seen: datetime, namespaces: list[str]) -> dict:
    severity, title, detail, remediation = _INFRA_RULE_IDS[rule_id]
    return {
        "id": rule_id,
        "severity": severity,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "affected_calls": count,
        "namespaces": namespaces,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "window_minutes": _WINDOW_MINUTES,
    }


@router.get("/system-health")
async def system_health(
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Report infrastructure-caused enforcement problems observed in the last window.

    Scoped like every other read: a non-admin sees only their own namespace, so a tenant is never
    shown another tenant's incident. An admin without a namespace claim sees the whole deployment.
    """
    since = datetime.now(timezone.utc) - timedelta(minutes=_WINDOW_MINUTES)
    role = str(user.get("role", "")).lower()
    claim_ns = str(user.get("namespace", "") or "")

    stmt = (
        select(
            AuditLogEntry.rule_id,
            func.count().label("n"),
            func.max(AuditLogEntry.timestamp_utc).label("last_seen"),
            func.array_agg(func.distinct(AuditLogEntry.namespace)).label("namespaces"),
        )
        .where(AuditLogEntry.timestamp_utc >= since)
        .where(AuditLogEntry.rule_id.in_(_INFRA_RULE_VARIANTS.keys()))
        .group_by(AuditLogEntry.rule_id)
    )
    if role != "admin" and claim_ns:
        stmt = stmt.where(AuditLogEntry.namespace == claim_ns)

    rows = (await session.execute(stmt)).all()
    # One underlying rule can now arrive as up to three grouped rows (bare + the two would-block
    # forms), so fold them together before rendering or the banner would show the same outage
    # several times with a split count.
    folded: dict[str, dict] = {}
    for row in rows:
        rule_id = _INFRA_RULE_VARIANTS.get(row.rule_id)
        if rule_id is None:
            continue
        agg = folded.setdefault(rule_id, {"n": 0, "last_seen": None, "namespaces": set()})
        agg["n"] += int(row.n)
        if row.last_seen and (agg["last_seen"] is None or row.last_seen > agg["last_seen"]):
            agg["last_seen"] = row.last_seen
        agg["namespaces"].update(ns for ns in (row.namespaces or []) if ns)
    issues = [
        _issue(rule_id, agg["n"], agg["last_seen"], sorted(agg["namespaces"]))
        for rule_id, agg in folded.items()
    ]
    # Most-recent first so the banner leads with what is happening now.
    issues.sort(key=lambda i: (i["last_seen"] or ""), reverse=True)

    if issues:
        log.warning(
            "nrvq.api.system_health.degraded",
            issues=[i["id"] for i in issues],
            code="NRVQ-API-7090",
        )
        return {
            "status": "degraded",
            "issues": issues,
            "window_minutes": _WINDOW_MINUTES,
            "decisions_in_window": None,  # not needed: an incident is already substantiated
        }

    # No infrastructure verdict fired. That is only an ALL-CLEAR if the data plane was talking to us at
    # all — every record this route reads arrives through the central /evaluate, so a data plane that
    # has been severed from the API writes nothing and looks identical to a healthy quiet one. Count
    # what the window actually holds, in the caller's scope, and say which of the two we are in.
    recorded = await _decisions_in_window(session, since, None if role == "admin" or not claim_ns else claim_ns)
    if recorded is None:
        # The liveness read itself failed. "We could not look" is never "we looked and it is clean".
        log.warning("nrvq.api.system_health.liveness_unavailable", code="NRVQ-API-7091")
        return {
            "status": "unknown",
            "issues": [],
            "window_minutes": _WINDOW_MINUTES,
            "decisions_in_window": None,
            "evidence": "No infrastructure verdict was recorded, and the liveness read failed — health is unknown.",
        }
    if recorded == 0:
        return {
            "status": "unknown",
            "issues": [],
            "window_minutes": _WINDOW_MINUTES,
            "decisions_in_window": 0,
            "evidence": (
                f"No real governed tool call was recorded in the last {_WINDOW_MINUTES} min (Policy-Tester "
                "and red-team rows do not count — the console writes those itself). The data plane is either "
                "idle or unable to reach this API, and the two are indistinguishable from here, so this is "
                "not an all-clear."
            ),
        }
    return {
        "status": "ok",
        "issues": [],
        "window_minutes": _WINDOW_MINUTES,
        "decisions_in_window": recorded,
        "evidence": (
            f"{recorded} real governed tool call{'' if recorded == 1 else 's'} reached this API in the last "
            f"{_WINDOW_MINUTES} min and none carried an infrastructure verdict."
        ),
    }


async def _decisions_in_window(session: AsyncSession, since: datetime, claim_ns: str | None) -> int | None:
    """How many REAL governed calls the data plane recorded in the window, in the caller's scope.

    This is the route's POSITIVE liveness evidence — the thing that separates "we looked and it is
    clean" from "nothing wrote to us, and we cannot tell why". Returns ``None`` when the read itself
    failed, which is a third state and must never be collapsed into 0.

    REAL TRAFFIC ONLY, and this filter is the whole load-bearing part. Two populations reach
    ``audit_log`` WITHOUT any data plane involved, both written by this API's own in-process emitter:
    the Policy Tester (the console POSTs ``/evaluate`` under an ephemeral ``policy-tester-<rand>``
    class, routers/evaluate.py) and a red-team run (routers/redteam.py `_emit_redteam_audit`, tagged
    ``framework="redteam"``). Counting either as proof that the data plane reached us means an
    operator whose sidecars are severed gets a green all-clear the moment they open the Policy Tester
    to find out why nothing works — the console substantiating its own health banner. So the count
    uses `audit_row_is_non_real`, the ONE shared classifier every other real-traffic surface uses
    (audit stats, /tools, /mitre, dry-run replay), which also makes this number reconcile with the
    Overview's governed-call KPI instead of being a third definition of "a call happened".

    Deliberately asymmetric with the incident query above, which is NOT filtered: an infrastructure
    verdict recorded during a red-team run is still a genuine engine fault worth a banner. Evidence of
    a FAULT is counted generously; evidence of HEALTH is counted strictly."""
    stmt = (
        select(func.count())
        .select_from(AuditLogEntry)
        .where(AuditLogEntry.timestamp_utc >= since)
        .where(~audit_row_is_non_real(AuditLogEntry))
    )
    if claim_ns:
        stmt = stmt.where(AuditLogEntry.namespace == claim_ns)
    try:
        return int(await session.scalar(stmt) or 0)
    except Exception as exc:  # noqa: BLE001 — a failed probe is reported as unknown, never as healthy
        log.warning("nrvq.api.system_health.liveness_failed", error=str(exc), code="NRVQ-API-7092")
        return None
