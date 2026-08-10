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

from norviq.api import baseline as baseline_lib
from norviq.api.auth import get_current_user, read_namespace
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.routers.system_health import non_policy_rule_for  # one resolver: 'did a POLICY decide this?'
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


def _enforced_violation_for(row_decision: str, rule_id: str, known: frozenset[str]) -> str | None:
    """The control a row VIOLATED and was refused by, or None.

    The sibling of `_control_for`, and it exists because the two consumers of this endpoint ask
    opposite questions of the same rows.

    Baseline blast radius asks "if I promote this control, what breaks?" — and a call the control
    ALREADY blocked is not evidence about that, so `_control_for` excludes it. Remediation asks "which
    resources are violating this policy?" — and there a blocked call is the strongest evidence there
    is. Observed live: a policy that had refused four real exfiltration attempts reported "1 resource
    to remediate, 1 call flagged", the 1 being an old monitor-mode row. The four actual violations,
    the ones an operator would want to go and fix, were invisible.
    """
    if row_decision not in ("block", "escalate"):
        return None
    if non_policy_rule_for(rule_id) is not None:
        return None
    return rule_id if rule_id and rule_id != "default_allow" else None


def _control_for(row_decision: str, rule_id: str, known: frozenset[str]) -> str | None:
    """The control a row is evidence about, or None.

    TWO shapes reach the audit log, and counting only the first is how this endpoint reported 7 of 33
    would-blocks on a live cluster:

      1. PREFIXED — `policy_audit_would_block:deny_sql_injection`. A hard `block` that was SOFTENED,
         either by the policy's own audit mode or by namespace monitor posture.
      2. BARE + decision=audit — `deny_sql_injection`. The rego itself decided `audit`, because the
         baseline compiler put that control's head in `audits[]`. Nothing softened it, so nothing
         prefixed it.

    Shape 2 is the NORMAL case for this product now: every baseline control ships on `monitor`, which
    is implemented precisely by emitting an `audits[]` head. So this endpoint was blind to the default
    configuration of the feature it exists to serve — it looked correct on a fresh install and emptied
    out the moment a customer used it.

    A bare id counts only when it names a control we actually ship. `default_allow` and a hand-written
    policy's own rule id are audits too, and neither is evidence about promoting a baseline control.

    INFRA rules are excluded outright. `evaluator_error` and friends are minted by the engine when it
    fails, not by any policy, and monitor mode softens them exactly like a real block — so they arrive
    here wearing the same `monitor_would_block:` prefix as a genuine control. Reporting them as
    non-compliant traffic reads an availability incident as a policy decision ("38 calls would have
    been blocked" was really "the evaluator errored 38 times"). They already have a home on
    /system-health, which states the outage in those terms and tells the operator what to do.
    """
    stripped = _strip_prefix(rule_id)
    if stripped is not None:
        return None if non_policy_rule_for(stripped) is not None else stripped
    if row_decision == "audit" and rule_id in known:
        return rule_id
    return None


def _own_policy_control_for(row_decision: str, rule_id: str, known: frozenset[str]) -> str | None:
    """A CUSTOMER-AUTHORED rule that flagged this row in monitor mode, or None.

    The third sibling of `_control_for` / `_enforced_violation_for`, and it exists because the bare-id
    branch above deliberately admits only the 14 shipped control ids — correct for the question that
    branch answers ("if I promote this baseline control, what breaks?"), where a hand-written policy's
    own rule id is not evidence.

    It is wrong for the OTHER consumer. The Visual Builder ships `audit` as a first-class rule decision
    (`BuilderSheet.tsx` DECISIONS, `builderCompile.ts` emits an `audits[...]` head with the customer's
    own rule id), so a customer trialling their own policy in monitor mode emits a BARE audit id that
    is not a shipped control — and `_control_for` correctly returns None for it. The console's "Your
    own policies" section, added so that trialling a custom policy is visible at all, then rendered
    zero for precisely the case it was built to serve: the rows were read, counted in `scanned`, and
    discarded.

    Measured: 12 bare `refund_over_limit` audit rows plus 2 prefixed ones reported a count of 2.

    So this is one filter that had to answer two opposite questions. Adding a bucket rather than
    loosening `_control_for` keeps the blast-radius number honest — the same resolution already used
    for `_enforced_violation_for`.

    Prefixed shapes are NOT handled here: `monitor_would_block:` / `policy_audit_would_block:` already
    reach `_control_for`, which returns the stripped id for any non-shipped rule. Claiming them here
    too would double-count the customer's own policy against itself.
    """
    if row_decision != "audit":
        return None
    if _strip_prefix(rule_id) is not None:  # already claimed by _control_for
        return None
    if non_policy_rule_for(rule_id) is not None:
        return None
    if not rule_id or rule_id == "default_allow" or rule_id in known:
        return None
    return rule_id


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

    # The shipped control ids, so a BARE audit rule_id can be recognised as a baseline control rather
    # than a hand-written policy's own rule. Best-effort: if the presets cannot be read (an image that
    # did not COPY them), fall back to prefixed-only rather than failing the whole read — a partial
    # answer beats a 500 on a page an operator opens during an incident.
    try:
        known_controls = frozenset(baseline_lib.control_ids("strict"))
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.policy_compliance.controls_unavailable", error=str(exc), code="NRVQ-API-7114")
        known_controls = frozenset()

    query = select(AuditLogEntry).where(AuditLogEntry.timestamp_utc >= since)
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    rows = (await session.execute(query)).scalars().all()

    controls: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "enforced": 0, "agent_classes": defaultdict(int), "tools": defaultdict(int),
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
            # Count only what the exclusion actually SUPPRESSED — a synthetic row that would have
            # landed in a control. It used to increment on every excluded row, so a 30d window read
            # "scanned 5930, excluded 21338": 78% of the window apparently withheld, when almost none
            # of it was a would-block and the number an operator was reading it as ("how much
            # evidence am I not being shown") was off by three orders of magnitude. The arithmetic was
            # right; the label was not, and the label is what gets acted on.
            _d, _r = str(row.decision or ""), str(row.rule_id or "")
            if (
                _control_for(_d, _r, known_controls) is not None
                or _own_policy_control_for(_d, _r, known_controls) is not None
            ):
                excluded += 1
            continue
        scanned += 1
        decision, rule = str(row.decision or ""), str(row.rule_id or "")
        enforced_id = _enforced_violation_for(decision, rule, known_controls)
        if enforced_id is not None:
            eb = controls[enforced_id]
            eb["enforced"] += 1
            eb["agent_classes"][str(row.agent_class or "")] += 0  # keep the class visible, not double-counted
            eb["namespaces"].add(str(row.namespace or ""))
        # Shipped control first, then the customer's own monitor-mode rule. The two are mutually
        # exclusive by construction (`_own_policy_control_for` declines anything `_control_for`
        # claims), so this cannot double-count a row.
        control_id = _control_for(decision, rule, known_controls) or _own_policy_control_for(
            decision, rule, known_controls
        )
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
        # Collect them all; the newest _MAX_SAMPLES are selected after the scan. Taking the first
        # five in DB order made the samples contradict the counts they sit beside: one control showed
        # 13 of 18 hits from a single tool while 4 of its 5 samples named a different one. A sample
        # that misrepresents the pattern is worse than no sample — it is the part an operator reads
        # instead of the aggregate.
        entry["samples"].append({
            "tool_name": str(row.tool_name or ""),
            "agent_class": str(row.agent_class or ""),
            "at": ts.isoformat() if ts is not None else None,
            "_ts": ts,
        })

    out = [
        {
            "control_id": cid,
            # Which KIND of rule this row is, stated rather than left for each consumer to re-derive.
            #
            # This endpoint now returns two populations: the 14 shipped controls, and rules from
            # policies the customer wrote themselves (see `_own_policy_control_for`). A consumer that
            # cannot tell them apart will present a hand-written rule as though it were a baseline
            # control with a Promote button behind it — the failure the older
            # "a bare non-shipped audit is ignored" test existed to prevent, and it was right to
            # worry. Omitting the row is one way to prevent it; SAYING WHICH IT IS is the other, and
            # it is the one that lets a customer see their own monitor-mode trial at all.
            "origin": "baseline" if cid in known_controls else "custom",
            # `count` is the WOULD-block population: what promoting this control would newly break.
            # `enforced` is what it already refused. The two answer opposite questions and must not be
            # summed into one number by this endpoint — the callers choose.
            "count": e["count"],
            "enforced": e["enforced"],
            "agent_classes": [{"name": k, "count": v} for k, v in sorted(e["agent_classes"].items(), key=lambda kv: -kv[1])],
            "tools": [{"name": k, "count": v} for k, v in sorted(e["tools"].items(), key=lambda kv: -kv[1])],
            "namespaces": sorted(n for n in e["namespaces"] if n),
            "first_seen": e["first_seen"].isoformat() if e["first_seen"] else None,
            "last_seen": e["last_seen"].isoformat() if e["last_seen"] else None,
            # Newest first, then capped — see the collection comment above.
            "samples": [
                {k: v for k, v in sample.items() if k != "_ts"}
                for sample in sorted(
                    e["samples"],
                    key=lambda x: (x["_ts"] is not None, x["_ts"]),
                    reverse=True,
                )[:_MAX_SAMPLES]
            ],
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
