# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The backing endpoint for the console's ⌘K search.

`GET /api/v1/search` is one bounded, server-scoped call — instead of the header search fanning out to
`/audit/records`, `/agents` and `/policies` from the browser, pulling the ENTIRE agent and policy lists
on every (debounced) keystroke and matching client-side.

Scoping is the same contract every read route uses (`auth.read_namespace`): an admin (or a `*` claim,
or a machine `service` principal with no claim) may search every namespace; a scoped tenant is pinned
to its own namespace even when it asks for "all"; a non-admin human with NO namespace claim gets 403
(the least-privilege floor). Tenant isolation is enforced by the namespace COLUMN filter, never
by the substring match.

The query is matched with SQLAlchemy's `icontains(..., autoescape=True)` so it is parameterized AND
`%`/`_` in the caller's text are escaped to literals (a `q` of "%" matches a literal percent, not
everything). Every section is capped and the audit scan is time-bounded, so a keystroke can never turn
into an unbounded table scan.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace
from norviq.api.db.models import AgentRegistryEntry, AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()

# Per-section cap. The console renders 3; 5 leaves headroom without ever paging a big result set.
_LIMIT = 5
# The audit scan is bounded to the same window the header's tool search always used.
_AUDIT_WINDOW_HOURS = 24
# Managed policy scopes are not user-facing "policies" — don't surface them as search hits.
_RESERVED_CLASSES = ("__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__")
_RESERVED_NAMESPACES = ("__cluster__",)


async def _search_tools(session: AsyncSession, q: str, namespace: str | None) -> list[dict]:
    """Recent audited tool calls whose tool_name contains `q` (24h window, namespace-scoped)."""
    since = datetime.now(timezone.utc) - timedelta(hours=_AUDIT_WINDOW_HOURS)
    stmt = (
        select(AuditLogEntry.tool_name, AuditLogEntry.decision, AuditLogEntry.timestamp_utc)
        .where(AuditLogEntry.timestamp_utc >= since)
        .where(AuditLogEntry.tool_name.icontains(q, autoescape=True))
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)  # isolation: the COLUMN, not the match
    stmt = stmt.order_by(AuditLogEntry.timestamp_utc.desc()).limit(_LIMIT)
    rows = (await session.execute(stmt)).all()
    return [
        {"tool_name": r.tool_name, "decision": r.decision,
         "timestamp": r.timestamp_utc.isoformat() if r.timestamp_utc else None}
        for r in rows
    ]


async def _search_agents(session: AsyncSession, q: str, namespace: str | None) -> list[dict]:
    """Registered agents whose spiffe_id or agent_class contains `q` (namespace-scoped)."""
    stmt = select(
        AgentRegistryEntry.spiffe_id, AgentRegistryEntry.agent_class, AgentRegistryEntry.trust_score
    ).where(
        AgentRegistryEntry.spiffe_id.icontains(q, autoescape=True)
        | AgentRegistryEntry.agent_class.icontains(q, autoescape=True)
    )
    if namespace:
        stmt = stmt.where(AgentRegistryEntry.namespace == namespace)  # isolation: the COLUMN
    stmt = stmt.order_by(AgentRegistryEntry.last_seen.desc()).limit(_LIMIT)
    rows = (await session.execute(stmt)).all()
    return [
        {"spiffe_id": r.spiffe_id, "agent_class": r.agent_class, "trust_score": r.trust_score}
        for r in rows
    ]


def _search_policies(request: Request, q: str, namespace: str | None) -> list[dict]:
    """Loaded policies whose namespace or agent_class contains `q` (namespace-scoped, in-memory)."""
    loader = getattr(request.app.state, "loader", None)
    policies = getattr(loader, "_policies", {}) if loader is not None else {}
    lower = q.lower()
    out: list[dict] = []
    for key in policies:
        ns, _, agent_class = str(key).partition(":")
        if namespace and ns != namespace:  # isolation: exact namespace, never the substring match
            continue
        if ns in _RESERVED_NAMESPACES or agent_class in _RESERVED_CLASSES:
            continue
        if lower not in ns.lower() and lower not in agent_class.lower():
            continue
        # No `mode`: the loader's in-memory entry carries only {rego, priority} — the real enforcement_mode
        # would need a DB read. Never fabricate one (a hardcoded "block" would mislabel every audit/escalate
        # policy). Omitting it leaves the console's existing fallback exactly as the old /policies flow did.
        out.append({"namespace": ns, "agent_class": agent_class})
        if len(out) >= _LIMIT:
            break
    return out


@router.get("/search")
async def search(
    request: Request,
    q: str = Query(..., min_length=1, max_length=128),
    namespace: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Scoped global search across audited tools, registered agents and loaded policies (⌘K)."""
    ns = read_namespace(user, namespace)  # None => every namespace (admin); own ns for a tenant; 403 floor
    tools = await _search_tools(session, q, ns)
    agents = await _search_agents(session, q, ns)
    policies = _search_policies(request, q, ns)
    log.info(
        "nrvq.api.search.served",
        namespace=ns or "all",
        tools=len(tools), agents=len(agents), policies=len(policies),
        code="NRVQ-API-7115",
    )
    return {"tools": tools, "agents": agents, "policies": policies}
