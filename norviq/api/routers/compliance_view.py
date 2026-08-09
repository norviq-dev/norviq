# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy compliance — what is non-compliant right now, and with which control.

GET /policy-compliance?namespace=&range=  -> per control: how many calls it WOULD have blocked, which
                                             agent classes and tools they came from, and a sample.

This is what makes monitor mode actionable rather than merely quiet. Every baseline control ships
observing, so the engine is already recording "this call violates control X" — but until now the only
way to read that was to grep the audit log for a rule_id prefix. The question an operator actually has
before promoting a control to Enforce is "what will this break?", and that is a blast-radius question,
not a log-search question.

The unit is deliberately the CONTROL, not the call. A control with 4,000 hits across one agent class
is a very different decision from one with 12 hits across nine — the first is probably a false
positive worth investigating before enforcing, the second is probably real.

`would_block` rows are the only input. A row that already `block`ed is not evidence about a
prospective promotion — it is a control that is already enforcing, and counting it here would inflate
the projected impact of turning something on with calls it is already turning away.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.synthetic import is_synthetic_identity  # the ONE shared classifier (do not fork)
from norviq.engine.evaluator import WOULD_BLOCK_RULE_PREFIXES

log = structlog.get_logger()
router = APIRouter()

_RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}

# How many distinct example calls to keep per control. Enough to see a pattern ("every one of these is
# an order id"), few enough that the response stays a summary rather than a log export — the Audit Log
# already exists for the full list, deep-linked from the console.
_MAX_SAMPLES = 5


def _strip_prefix(rule_id: str) -> str | None:
    """`monitor_would_block:deny_shell_execution` -> `deny_shell_execution`; None if not a would-block.

    Both prefixes fold to the same control. They record WHY the block was softened — namespace posture
    vs the policy's own mode — which matters for debugging but not for "what would this control break",
    and splitting them would show one control twice with a divided count.
    """
    for prefix in WOULD_BLOCK_RULE_PREFIXES:
        if rule_id.startswith(prefix):
            inner = rule_id[len(prefix) :]
            # Defensive: a doubly-prefixed rule_id is reachable when a policy-audit softening is cached
            # and namespace posture is then applied on top of the cache hit.
            return _strip_prefix(inner) or inner
    return None


@router.get("/policy-compliance")
async def policy_compliance(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Non-compliant traffic grouped by the control that flagged it (RBAC-scoped, real traffic only)."""
    namespace = read_namespace(user, namespace)
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS[range])

    query = select(AuditLogEntry).where(AuditLogEntry.timestamp_utc >= since)
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    rows = (await session.execute(query)).scalars().all()

    controls: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "agent_classes": defaultdict(int), "tools": defaultdict(int),
                 "namespaces": set(), "first_seen": None, "last_seen": None, "samples": []}
    )
    scanned = 0
    excluded = 0
    for row in rows:
        # Same real-traffic population as the Overview and Compliance. A red-team probe that trips a
        # control is not a customer workload about to break, and counting it would overstate the blast
        # radius of enforcing — the one number this endpoint exists to get right.
        if str(getattr(row, "framework", "") or "") == "redteam" or is_synthetic_identity(
            str(getattr(row, "agent_class", "") or "")
        ):
            excluded += 1
            continue
        scanned += 1
        control_id = _strip_prefix(str(row.rule_id or ""))
        if control_id is None:
            continue
        entry = controls[control_id]
        entry["count"] += 1
        entry["agent_classes"][str(row.agent_class or "")] += 1
        entry["tools"][str(row.tool_name or "")] += 1
        entry["namespaces"].add(str(row.namespace or ""))
        ts = row.timestamp_utc
        if ts is not None:
            if entry["first_seen"] is None or ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if entry["last_seen"] is None or ts > entry["last_seen"]:
                entry["last_seen"] = ts
        if len(entry["samples"]) < _MAX_SAMPLES:
            entry["samples"].append({
                "tool_name": str(row.tool_name or ""),
                "agent_class": str(row.agent_class or ""),
                "at": ts.isoformat() if ts is not None else None,
            })

    out = [
        {
            "control_id": cid,
            "count": e["count"],
            "agent_classes": [{"name": k, "count": v} for k, v in sorted(e["agent_classes"].items(), key=lambda kv: -kv[1])],
            "tools": [{"name": k, "count": v} for k, v in sorted(e["tools"].items(), key=lambda kv: -kv[1])],
            "namespaces": sorted(n for n in e["namespaces"] if n),
            "first_seen": e["first_seen"].isoformat() if e["first_seen"] else None,
            "last_seen": e["last_seen"].isoformat() if e["last_seen"] else None,
            "samples": e["samples"],
        }
        for cid, e in controls.items()
    ]
    # Worst blast radius first — the control an operator most needs to think about before promoting.
    out.sort(key=lambda c: -c["count"])

    log.info("nrvq.api.policy_compliance.read", namespace=namespace, range=range,
             controls=len(out), scanned=scanned, code="NRVQ-API-7113")
    return {
        "namespace": namespace or "all",
        "range": range,
        # `scanned` is what makes an empty list readable. Zero non-compliant calls out of zero traffic
        # means "nothing has happened here yet"; zero out of 40,000 means "genuinely compliant". The
        # console renders those differently, and without this number it cannot tell them apart.
        "scanned": scanned,
        "excluded_synthetic": excluded,
        "controls": out,
    }
