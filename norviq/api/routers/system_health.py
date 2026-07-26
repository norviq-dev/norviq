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
}


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
        .where(AuditLogEntry.rule_id.in_(_INFRA_RULE_IDS.keys()))
        .group_by(AuditLogEntry.rule_id)
    )
    if role != "admin" and claim_ns:
        stmt = stmt.where(AuditLogEntry.namespace == claim_ns)

    rows = (await session.execute(stmt)).all()
    issues = [
        _issue(row.rule_id, int(row.n), row.last_seen, sorted(ns for ns in (row.namespaces or []) if ns))
        for row in rows
        if row.rule_id in _INFRA_RULE_IDS
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
        "status": "degraded" if issues else "ok",
        "issues": issues,
        "window_minutes": _WINDOW_MINUTES,
    }
