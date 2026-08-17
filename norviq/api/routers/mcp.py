# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""MCP inventory + tool-definition pin/approval API.

This is the control-plane half of Gate A. The proxy (`norviq/mcp`) OBSERVES what each MCP server
serves; this router is where those observations become durable, tenant-scoped, auditable APPROVALS
that survive a pod restart and that an operator can actually see and act on.

Division of responsibility, deliberately:

  * The PROXY decides what the model sees. It has to — it is the only thing on the wire, and the
    decision has to be made in the microseconds before a `tools/list` response is forwarded.
  * The CONTROL PLANE decides what is APPROVED. That is a durable, human-owned judgement, so it
    lives with the policies, under the same RBAC, in the same database, visible in the same console.

The proxy calls `POST /mcp/pins/observe` with a service credential (the same one it uses for
`/evaluate`), and the SERVER computes the verdict. Putting the verdict here rather than trusting a
`status` field from the proxy matters: the approved digest never leaves the control plane, so a
compromised proxy cannot mark its own drift as approved — the worst it can do is fail to report,
which leaves the previous state standing.
"""

from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, scoped_namespace
from norviq.api.db.models import McpServer, McpToolPin
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()

# Verdicts. Mirrors norviq/mcp/pins.py so the proxy and the control plane speak one vocabulary; the
# duplication is intentional — importing the proxy package into the API would drag the MCP data plane
# into the control-plane image for three string constants.
PIN_OK = "pinned"
PIN_FIRST_SEEN = "first_seen"
PIN_DRIFT = "drift"
PIN_QUARANTINED = "quarantined"

# Registry statuses, mirroring norviq/mcp/servers.py for the same reason.
STATUS_DISCOVERED = "discovered"
STATUS_REGISTERED = "registered"
STATUS_BLOCKED = "blocked"

_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: The server-level roll-up, worst first. An ORDERING, not a set — the console sorts on it.
#:
#: `blocked` outranks every observation because it answers a stronger question: telling an operator
#: that a server they have already refused has "drift" sends them to re-approve a definition on a
#: server they do not want reachable at all. `drift` beats a scan finding because drift means the
#: thing that was approved is not the thing being served — a different class of problem from "this
#: description looks suspicious". `unreviewed` sits above `ok`, not beside it: only a decision moves a
#: server out of that state, and a fresh install is entirely made of it.
#:
#: Declared here rather than imported from `norviq.mcp.servers` for the same reason the pin verdicts
#: above are: `norviq/mcp/__init__` imports the firewall, so one import for an ordering would pull the
#: MCP data plane into the control-plane image. Health is a control-plane roll-up over pins AND
#: decisions; the proxy has no use for it, so there is nothing shared to factor out.
_HEALTH_ORDER: tuple[str, ...] = ("blocked", "drift", "quarantined", "flagged", "unreviewed", "ok")


def _health_rank(health: str) -> int:
    """Sort key for `_HEALTH_ORDER`. An unrecognised word sorts FIRST, not last — a health string
    nothing here produces is a bug, and burying it at the bottom is how it stays one."""
    try:
        return _HEALTH_ORDER.index(health)
    except ValueError:
        return -1


class ObservedTool(BaseModel):
    """One tool definition as the proxy saw it."""

    tool_name: str = Field(max_length=255)
    digest: str = Field(max_length=64)
    canonical: str = ""
    scan_severity: str = "none"
    findings: list = Field(default_factory=list)


class ObserveRequest(BaseModel):
    """A proxy reporting one server's catalog at discovery time."""

    namespace: str = Field(default="", max_length=255)
    server_id: str = Field(max_length=255)
    transport: str = Field(default="stdio", max_length=16)
    # 'tofu'  -> an unseen tool is pinned and allowed, and CHANGE is what gets enforced.
    # 'strict'-> an unseen tool is quarantined until an operator approves it.
    mode: str = "tofu"
    tools: list[ObservedTool] = Field(default_factory=list)


class ApproveRequest(BaseModel):
    namespace: str = Field(max_length=255)
    server_id: str = Field(max_length=255)
    tool_name: str = Field(max_length=255)
    # Named EXPLICITLY, never "whatever it says now": a server that changes its definition again
    # between the operator reading it and the approval landing would otherwise get the new one
    # blessed by a click meant for the old one.
    digest: str = Field(max_length=64)


class RevokeRequest(BaseModel):
    namespace: str = Field(max_length=255)
    server_id: str = Field(max_length=255)
    tool_name: str = Field(max_length=255)


def _row_dict(row: McpToolPin) -> dict:
    return {
        "namespace": row.namespace,
        "server_id": row.server_id,
        "tool_name": row.tool_name,
        "approved_digest": row.approved_digest,
        "last_digest": row.last_digest,
        "approved": row.approved,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "scan_severity": row.scan_severity,
        "findings": row.findings or [],
        "drift_count": row.drift_count,
        "transport": row.transport,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "status": _status_of(row),
        "approved_canonical": row.approved_canonical,
        "last_canonical": row.last_canonical,
    }


def _status_of(row: McpToolPin) -> str:
    """Derived display status. Drift outranks everything — the FACT of the change is the finding."""
    if row.last_digest and row.last_digest != row.approved_digest:
        return PIN_DRIFT
    if not row.approved:
        return PIN_QUARANTINED
    return PIN_OK


@router.post("/mcp/pins/observe")
async def observe(
    body: ObserveRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Record what a server served, and return the per-tool verdict.

    Called by the proxy on the DISCOVERY path only (`tools/list`, and again after a
    `notifications/tools/list_changed`) — never per tool call. The namespace is bound to the CALLER's
    credential rather than taken from the body, exactly as `/evaluate` does, so a service token
    scoped to one tenant cannot write another tenant's pins.
    """
    namespace = scoped_namespace(user, body.namespace or None) or body.namespace
    if not namespace:
        raise HTTPException(status_code=400, detail="namespace is required")
    if not body.server_id:
        raise HTTPException(status_code=400, detail="server_id is required")
    mode = body.mode if body.mode in ("tofu", "strict") else "strict"  # unknown mode -> stricter

    now = datetime.now(timezone.utc)
    existing = {
        r.tool_name: r
        for r in (
            await session.scalars(
                select(McpToolPin).where(
                    McpToolPin.namespace == namespace, McpToolPin.server_id == body.server_id
                )
            )
        ).all()
    }

    verdicts: dict[str, dict] = {}
    for tool in body.tools:
        row = existing.get(tool.tool_name)
        if row is None:
            approved = mode == "tofu"
            row = McpToolPin(
                namespace=namespace, server_id=body.server_id, tool_name=tool.tool_name,
                approved_digest=tool.digest, last_digest=tool.digest,
                approved_canonical=tool.canonical, last_canonical=tool.canonical,
                approved=approved, approved_by="tofu" if approved else "",
                approved_at=now if approved else None,
                scan_severity=tool.scan_severity, findings=tool.findings,
                transport=body.transport, first_seen_at=now, last_seen_at=now,
                # Set explicitly rather than relying on the column default. SQLAlchemy applies
                # `default=` at FLUSH time, so between `add()` and `commit()` the attribute is None —
                # and this handler reads it back in the same request when a catalog contains the same
                # tool twice. Depending on flush ordering for a value the code then does arithmetic on
                # is the kind of thing that works until it doesn't.
                drift_count=0,
            )
            session.add(row)
            status = PIN_FIRST_SEEN if approved else PIN_QUARANTINED
            log.info("nrvq.mcp.pin.first_seen", namespace=namespace, server=body.server_id,
                     tool=tool.tool_name, mode=mode, status=status, code="NRVQ-MCP-5041")
        else:
            row.last_seen_at = now
            row.last_digest = tool.digest
            row.last_canonical = tool.canonical
            # The scan verdict tracks the CURRENT definition, so it is always refreshed — otherwise
            # a drifted-and-then-approved tool would keep displaying the old definition's findings.
            row.scan_severity = tool.scan_severity
            row.findings = tool.findings
            if tool.digest == row.approved_digest:
                status = PIN_OK if row.approved else PIN_QUARANTINED
            else:
                # NOT re-pinned. See the model docstring: adopting the new digest here would mean an
                # attacker only has to absorb one blocked call.
                row.drift_count = (row.drift_count or 0) + 1
                status = PIN_DRIFT
                log.warning("nrvq.mcp.pin.drift", namespace=namespace, server=body.server_id,
                            tool=tool.tool_name, approved=row.approved_digest[:16],
                            served=tool.digest[:16], code="NRVQ-MCP-5042")
        verdicts[tool.tool_name] = {
            "status": status,
            "approved_digest": row.approved_digest,
            "scan_severity": tool.scan_severity,
        }

    await session.commit()
    return {"namespace": namespace, "server_id": body.server_id, "mode": mode, "verdicts": verdicts}


@router.get("/mcp/pins")
async def list_pins(
    namespace: str | None = Query(default=None),
    server_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Every pinned tool the caller may see. `namespace=all` (or omitted) = every readable namespace."""
    ns = read_namespace(user, namespace)
    stmt = select(McpToolPin)
    if ns:
        stmt = stmt.where(McpToolPin.namespace == ns)
    if server_id:
        stmt = stmt.where(McpToolPin.server_id == server_id)
    rows = [_row_dict(r) for r in (await session.scalars(stmt.order_by(McpToolPin.server_id, McpToolPin.tool_name))).all()]
    if status:
        rows = [r for r in rows if r["status"] == status]
    return rows


@router.get("/mcp/servers")
async def list_servers(
    namespace: str | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Server-level inventory: one row per MCP server with its risk roll-up.

    This is the view an operator actually wants first — "which MCP servers is my agent estate
    talking to, and is any of them misbehaving?" — rather than a flat list of every tool.
    """
    ns = read_namespace(user, namespace)
    stmt = select(McpToolPin)
    if ns:
        stmt = stmt.where(McpToolPin.namespace == ns)
    rows = (await session.scalars(stmt)).all()

    servers: dict[tuple[str, str], dict] = {}
    for r in rows:
        key = (r.namespace, r.server_id)
        entry = servers.setdefault(key, {
            "namespace": r.namespace, "server_id": r.server_id, "transport": r.transport,
            "tools": 0, "drifted": 0, "quarantined": 0, "flagged": 0,
            "worst_severity": "none", "last_seen_at": None, "first_seen_at": None,
        })
        entry["tools"] += 1
        st = _status_of(r)
        if st == PIN_DRIFT:
            entry["drifted"] += 1
        elif st == PIN_QUARANTINED:
            entry["quarantined"] += 1
        if _SEVERITY_ORDER.get(r.scan_severity, 0) > 0:
            entry["flagged"] += 1
        if _SEVERITY_ORDER.get(r.scan_severity, 0) > _SEVERITY_ORDER.get(entry["worst_severity"], 0):
            entry["worst_severity"] = r.scan_severity
        for field, value in (("last_seen_at", r.last_seen_at), ("first_seen_at", r.first_seen_at)):
            iso = value.isoformat() if value else None
            cur = entry[field]
            if iso and (cur is None or (field == "last_seen_at" and iso > cur) or (field == "first_seen_at" and iso < cur)):
                entry[field] = iso

    # The operator's DECISION, joined onto what was observed. A server with a decision but no pins yet
    # still appears: registering a server before its first tools/list is a legitimate thing to do, and a
    # listing that only shows servers it has seen cannot express it.
    decisions = {}
    dstmt = select(McpServer)
    if ns:
        dstmt = dstmt.where(McpServer.namespace == ns)
    for row in (await session.scalars(dstmt)).all():
        decisions[(row.namespace, row.server_id)] = row
        servers.setdefault((row.namespace, row.server_id), {
            "namespace": row.namespace, "server_id": row.server_id, "transport": row.transport,
            "tools": 0, "drifted": 0, "quarantined": 0, "flagged": 0,
            "worst_severity": "none", "last_seen_at": None, "first_seen_at": None,
        })

    for key, entry in servers.items():
        row = decisions.get(key)
        entry["status"] = row.status if row else STATUS_DISCOVERED
        entry["writable"] = bool(row.writable) if row else False
        entry["decided_by"] = (row.decided_by if row else "") or ""
        entry["note"] = (row.note if row else "") or ""
        entry["identity_drift_count"] = row.identity_drift_count if row else 0

    out = list(servers.values())
    for entry in out:
        # TWO roll-ups, because they answer different questions and a console showed the same word
        # twice when they were one.
        #
        # `observed_health` is what the ESTATE says: drift, quarantine, scan findings. It knows
        # nothing about decisions.
        #
        # `health` folds the DECISION in, and is what the list sorts on — `blocked` has to outrank
        # every observation there or a server the operator already refused sinks below one that
        # merely drifted.
        #
        # Measured live: `rugpull` rendered as "BLOCKED | BLOCKED" across the two columns, so an
        # operator deciding whether to unblock could not see that its definitions were in fact clean —
        # which is precisely the fact that decision turns on.
        entry["observed_health"] = (
            "drift" if entry["drifted"]
            else "quarantined" if entry["quarantined"]
            else "flagged" if entry["flagged"]
            else "unreviewed" if entry["status"] == STATUS_DISCOVERED
            else "ok"
        )
        entry["health"] = (
            "blocked" if entry["status"] == STATUS_BLOCKED else entry["observed_health"]
        )
    # Worst first, by the real ordering. Sorting on `health == "ok"` was fine while an undecided server
    # read as "ok", and became wrong the moment it read as "unreviewed": every row on a fresh install
    # is then non-ok, the boolean collapses, and the drifted server sorts wherever its id happens to
    # fall. Ties break on server_id so the list is stable between reloads.
    out.sort(key=lambda e: (_health_rank(e["health"]), e["server_id"]))
    return out


@router.post("/mcp/pins/approve")
async def approve_pin(
    body: ApproveRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Adopt a specific digest as the approved definition (admin).

    This is the operator action that clears a drift or a quarantine. It refuses a digest the server
    has not actually served, so an approval cannot be issued for a definition nobody has seen.
    """
    require_admin(user)
    scoped_namespace(user, body.namespace)
    row = await session.get(McpToolPin, (body.namespace, body.server_id, body.tool_name))
    if row is None:
        raise HTTPException(status_code=404, detail="pin not found")
    if body.digest not in (row.approved_digest, row.last_digest):
        raise HTTPException(
            status_code=409,
            detail="digest does not match the approved or the currently-served definition; "
                   "re-read the pin and approve the digest you actually reviewed",
        )
    row.approved_digest = body.digest
    if body.digest == row.last_digest:
        row.approved_canonical = row.last_canonical
    row.approved = True
    row.approved_by = str(user.get("sub", "") or "admin")
    row.approved_at = datetime.now(timezone.utc)
    await session.commit()
    log.info("nrvq.mcp.pin.approved", namespace=body.namespace, server=body.server_id,
             tool=body.tool_name, digest=body.digest[:16], by=row.approved_by, code="NRVQ-MCP-5043")
    return _row_dict(row)


@router.post("/mcp/pins/revoke")
async def revoke_pin(
    body: RevokeRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Withdraw approval (admin): the tool is withheld from the model until re-approved."""
    require_admin(user)
    scoped_namespace(user, body.namespace)
    row = await session.get(McpToolPin, (body.namespace, body.server_id, body.tool_name))
    if row is None:
        raise HTTPException(status_code=404, detail="pin not found")
    row.approved = False
    row.approved_by = ""
    row.approved_at = None
    await session.commit()
    log.warning("nrvq.mcp.pin.revoked", namespace=body.namespace, server=body.server_id,
                tool=body.tool_name, by=user.get("sub"), code="NRVQ-MCP-5044")
    return _row_dict(row)


#: Priority for the generated registry module. Sits with `__controls__` in the base band: it is a
#: namespace's own tuning, not a cluster-wide floor, so it must not outrank a policy a tenant wrote
#: for themselves. Collected as a tighten-only overlay regardless, so priority is not what makes it
#: hold — see `evaluator._append_controls_floor`.
_MCP_SCOPE_PRIORITY = 2


async def _materialize_mcp_registry(request: Request, session: AsyncSession, namespace: str) -> int:
    """Recompile this namespace's `__mcp__` module from the registry. Returns the server count.

    CALLED FROM EVERY WRITE PATH, and that is the whole point of it existing in this file rather than
    only as a compiler. `norviq/api/egress_allowlist.py` is a complete, tested compiler with
    engine-side collection and NO ROUTER: its only importer is its own test, so the control has never
    been reachable by a customer. A generated module that nothing regenerates is indistinguishable
    from a feature that was never built.

    Never raises into the caller. The decision is already committed and is the durable record; the
    module is derived from it, so a failure here means the control is stale until the next write, not
    that an operator's decision was lost. It is logged at ERROR so "stale" is never silent.
    """
    from norviq.api import mcp_controls

    try:
        rows = (await session.scalars(
            select(McpServer).where(McpServer.namespace == namespace)
        )).all()
        registered = [r.server_id for r in rows if r.status == STATUS_REGISTERED]
        writable = [r.server_id for r in rows if r.status == STATUS_REGISTERED and r.writable]
        rego = mcp_controls.compile(registered, writable)
        loader = request.app.state.loader
        await loader.create(
            namespace, mcp_controls.SCOPE, rego,
            saved_by="mcp-registry",
            priority=_MCP_SCOPE_PRIORITY,
            # Always "block". The module carries each control's own decision in its generated heads,
            # exactly as the baseline compiler does — softening the whole module on top would make the
            # per-control choice unreachable.
            enforcement_mode="block",
            policy_name="mcp-server-registry",
        )
        cache = getattr(loader, "_cache", None)
        if cache is not None:
            # The registry applies to every agent class in the namespace, so the whole namespace's
            # eval cache goes: `loader.create` only invalidates the (ns, __mcp__) scope, and a cached
            # decision from before the change would keep enforcing the old registry for up to
            # redis_ttl_eval_s.
            await cache.invalidate_eval_scope(namespace)
        log.info("nrvq.mcp.registry.materialized", namespace=namespace,
                 registered=len(registered), writable=len(writable), code="NRVQ-MCP-5074")
        return len(registered)
    except Exception as exc:  # noqa: BLE001 — see the docstring: derived state, never the record
        log.error("nrvq.mcp.registry.materialize_failed", namespace=namespace, error=str(exc),
                  code="NRVQ-MCP-5075",
                  hint="the decision is saved; the registry-backed controls are stale until the "
                       "next server decision in this namespace")
        return -1


class ServerDecisionBody(BaseModel):
    """An operator decision about one MCP server."""

    namespace: str = Field(max_length=255)
    server_id: str = Field(max_length=255)
    status: str = Field(pattern="^(discovered|registered|blocked)$")
    # Only meaningful with status=registered; a blocked server is not writable whatever this says.
    writable: bool = False
    note: str = Field(default="", max_length=1024)


@router.post("/mcp/servers/decision")
async def decide_server(
    body: ServerDecisionBody,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Register, block, or return a server to unreviewed. Admin-only, audited.

    This is the write half of the registry, and it ships in the same change as the module that reads
    it on purpose: `norviq/api/egress_allowlist.py` has a complete compiler and engine-side collection
    and no router, so its only importer is its own test and the feature has never been reachable. A
    control that reads a list nobody can populate is the same shape.
    """
    require_admin(user)
    scoped_namespace(user, body.namespace)

    row = (await session.scalars(
        select(McpServer).where(McpServer.namespace == body.namespace,
                                McpServer.server_id == body.server_id)
    )).first()
    if row is None:
        # `status` is set explicitly rather than left to the column default, which SQLAlchemy applies
        # at FLUSH: read before that, `row.status` is None, and the audit line and the response then
        # said the previous status was nothing at all. "discovered" IS the state of a server with no
        # decision row — that is the whole meaning of the default — so reporting it is not a guess.
        row = McpServer(namespace=body.namespace, server_id=body.server_id,
                        status=STATUS_DISCOVERED)
        session.add(row)

    previous = row.status
    row.status = body.status
    # A blocked server is never writable. Keeping the flag set would leave a latent grant that takes
    # effect the moment somebody unblocks it, which is not what "block" is understood to mean.
    row.writable = bool(body.writable) and body.status == STATUS_REGISTERED
    row.note = body.note
    row.decided_by = str(user.get("sub") or "")
    row.decided_at = datetime.now(timezone.utc)
    await session.commit()

    registered = await _materialize_mcp_registry(request, session, body.namespace)

    log.warning("nrvq.mcp.server.decision", namespace=body.namespace, server=body.server_id,
                previous=previous, status=row.status, writable=row.writable,
                by=user.get("sub"), code="NRVQ-MCP-5069")
    return {"namespace": row.namespace, "server_id": row.server_id, "status": row.status,
            "writable": row.writable, "previous_status": previous, "note": row.note,
            # Reported so the console can say the registry-backed controls actually moved. -1 means
            # the module could not be rebuilt and the decision is saved but not yet enforced —
            # silence there would be the same class of defect as a block with no audit row.
            "registered_servers": registered}


@router.delete("/mcp/servers/{namespace}/{server_id}")
async def forget_server(
    namespace: str,
    server_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Forget every pin for a server (admin) — for decommissioning, or a deliberate re-TOFU.

    Destructive in the security-relevant direction: the next `tools/list` re-pins whatever the server
    serves at that moment. Admin-only and logged at WARNING for exactly that reason.
    """
    require_admin(user)
    scoped_namespace(user, namespace)
    result = await session.execute(
        delete(McpToolPin).where(McpToolPin.namespace == namespace, McpToolPin.server_id == server_id)
    )
    # THE DECISION IS NOT AN OBSERVATION AND DOES NOT GO WITH THEM. Forget clears what the server was
    # SEEN to serve, so the next tools/list re-pins from scratch. A `blocked` decision is the opposite
    # kind of fact — an operator's refusal — and dropping it here would make "forget" a way to launder
    # a refusal into a clean first sight, which is precisely the re-TOFU laundering the DELETE handler
    # in firewall.py already refuses to allow for Gate-A state. A registration is dropped, because
    # re-registering after a decommission should be a deliberate act.
    kept = (await session.scalars(
        select(McpServer).where(McpServer.namespace == namespace, McpServer.server_id == server_id)
    )).first()
    decision_kept = bool(kept and kept.status == "blocked")
    if kept and not decision_kept:
        await session.delete(kept)
    await session.commit()
    # Forget can DROP a registration (it keeps only a refusal), which changes the generated set. A
    # forgotten-but-still-registered server would keep its write grant in the module until somebody
    # happened to make an unrelated decision in the same namespace.
    await _materialize_mcp_registry(request, session, namespace)
    log.warning("nrvq.mcp.server.forgotten", namespace=namespace, server=server_id,
                removed=result.rowcount, decision_kept=decision_kept,
                by=user.get("sub"), code="NRVQ-MCP-5045")
    return {"namespace": namespace, "server_id": server_id, "removed": result.rowcount,
            "decision_kept": decision_kept}
