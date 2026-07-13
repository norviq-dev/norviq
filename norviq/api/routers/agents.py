# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import json
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, require_target_cluster
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()
router = APIRouter()

# A bound so one agent's history query never loads an unbounded slice of audit_log into memory.
_AGENT_AUDIT_LIMIT = 5000


def _since_for_range(range_value: str) -> datetime:
    """Convert an API range token to a UTC lower bound (matches the audit route's tokens)."""
    range_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
    return datetime.now(timezone.utc) - timedelta(hours=range_map.get(range_value, 168))


def _namespace_from_spiffe(spiffe_id: str) -> str | None:
    """Extract the namespace from spiffe://.../ns/{namespace}/sa/... ."""
    parts = spiffe_id.split("/")
    if "ns" in parts:
        idx = parts.index("ns")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _class_from_spiffe(spiffe_id: str) -> str | None:
    """B4: extract the agent_class from spiffe://.../sa/{agent_class} (the SVID encodes it)."""
    parts = spiffe_id.split("/")
    if "sa" in parts:
        idx = parts.index("sa")
        if idx + 1 < len(parts) and parts[idx + 1]:
            return parts[idx + 1]
    return None


async def _registry_last_seen(namespace: str | None) -> dict[str, str]:
    """B4: batch-load {spiffe_id: last_seen ISO} from the persistent agent_registry in ONE query, so the
    Agents table can show a real Last Seen even when an agent's live trust cache entry has aged out. Never
    raises into the request path — a registry read failure just yields an empty map (Last Seen falls to '–')."""
    try:
        from norviq.api.db.models import AgentRegistryEntry
        from norviq.api.db.session import get_session

        provider = get_session()
        session = await provider.__anext__()
        try:
            stmt = select(AgentRegistryEntry.spiffe_id, AgentRegistryEntry.last_seen)
            if namespace:
                stmt = stmt.where(AgentRegistryEntry.namespace == namespace)
            rows = (await session.execute(stmt)).all()
        finally:
            await provider.aclose()
        return {str(sid): ls.isoformat() for sid, ls in rows if ls is not None}
    except Exception as exc:  # noqa: BLE001 — best-effort enrichment, never fail the list
        log.warning("nrvq.api.agents.last_seen_failed", error=str(exc), code="NRVQ-API-7033")
        return {}


class TrustUpdate(BaseModel):
    """Manual trust update payload."""

    score: float = Field(ge=0.0, le=1.0)


@router.get("/agents")
async def list_agents(
    request: Request,
    namespace: str | None = Query(default=None),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List agents with trust scores, scoped to the caller's namespace.

    Reads the live ``trust:*`` cache first; when it is cold (entries past their TTL)
    it falls back to the persistent ``agent_registry`` so the Agents view stays populated.
    """
    namespace = read_namespace(user, namespace)  # None => all namespaces (admin); own ns for a tenant
    cache = request.app.state.cache
    last_seen_map = await _registry_last_seen(namespace)  # B4: real Last Seen, batched
    rows = []
    async for key in cache._client().scan_iter("trust:*"):
        spiffe_id = str(key).replace("trust:", "", 1)
        if namespace and _namespace_from_spiffe(spiffe_id) != namespace:
            continue
        trust = await cache.get_trust(spiffe_id)
        if trust:
            details = await _trust_details(request, spiffe_id, trust.factors)
            rows.append(
                {
                    "spiffe_id": spiffe_id,
                    # B4: the SVID encodes ns + class — parse them so the table stops showing "–".
                    "namespace": _namespace_from_spiffe(spiffe_id),
                    "agent_class": _class_from_spiffe(spiffe_id),
                    "last_seen": last_seen_map.get(spiffe_id),
                    "score": trust.score,
                    "category": trust.category.lower(),
                    "violation_count": trust.violation_count,
                    "signals": details["signals"],
                    "dominant_signal": details["dominant_signal"],
                    "recommendation": details["recommendation"],
                }
            )
    if not rows:
        rows = await _agents_from_registry(namespace)
    log.debug("nrvq.api.agents.listed", count=len(rows), code="NRVQ-API-7030")
    return rows


async def _agents_from_registry(namespace: str) -> list[dict]:
    """Read agents from the persistent registry when the trust cache is cold."""
    try:
        from sqlalchemy import select

        from norviq.api.db.models import AgentRegistryEntry
        from norviq.api.db.session import get_session

        provider = get_session()
        session = await provider.__anext__()
        try:
            stmt = select(AgentRegistryEntry)
            if namespace:
                stmt = stmt.where(AgentRegistryEntry.namespace == namespace)
            result = await session.execute(stmt)
            entries = result.scalars().all()
        finally:
            await provider.aclose()
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.api.agents.registry_read_failed", error=str(exc), code="NRVQ-API-7032")
        return []
    return [
        {
            "spiffe_id": entry.spiffe_id,
            # B4: the registry already stores ns/class/last_seen — surface them (was dropped → "–").
            "namespace": entry.namespace or _namespace_from_spiffe(entry.spiffe_id),
            "agent_class": entry.agent_class or _class_from_spiffe(entry.spiffe_id),
            "last_seen": entry.last_seen.isoformat() if entry.last_seen else None,
            "score": entry.trust_score,
            "category": entry.trust_category.lower(),
            "violation_count": entry.violation_count,
            "signals": {},
            "dominant_signal": "",
            "recommendation": "",
        }
        for entry in entries
    ]


# NOTE: these specific routes MUST be declared before the greedy /agents/{spiffe_id:path} GET below,
# otherwise the path converter swallows the "/tool-usage" / "/trust-history" suffix.
@router.get("/agents/{spiffe_id:path}/tool-usage")
async def agent_tool_usage(
    spiffe_id: str,
    namespace: str | None = Query(None),
    range_: str = Query("7d", alias="range"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """Real per-tool call counts for one agent, aggregated from audit_log over the range."""
    namespace = read_namespace(user, namespace)
    stmt = select(AuditLogEntry.tool_name, AuditLogEntry.decision).where(
        AuditLogEntry.agent_id == spiffe_id,
        AuditLogEntry.timestamp_utc >= _since_for_range(range_),
    )
    if namespace and namespace != "all":
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    rows = (await session.execute(stmt.limit(_AGENT_AUDIT_LIMIT))).all()

    # CAP-2: tag each tool with its risk tier (the SAME TOOL_RISK_MAP the asset graph uses) so the Tool
    # Usage bars can be coloured by RISK, not just call volume — an agent hammering a destructive tool no
    # longer looks identical to one hammering a benign search.
    from norviq.engine.graph.asset_graph import TOOL_RISK_MAP
    from norviq.engine.graph.models import RiskLevel

    usage: dict[str, dict] = {}
    for tool_name, decision in rows:
        name = str(tool_name)
        entry = usage.setdefault(
            name,
            {"tool": name, "count": 0, "blocked": 0, "risk": TOOL_RISK_MAP.get(name, RiskLevel.MEDIUM).value},
        )
        entry["count"] += 1
        if decision == "block":
            entry["blocked"] += 1
    result = sorted(usage.values(), key=lambda item: item["count"], reverse=True)
    log.debug("nrvq.api.agent.tool_usage", spiffe_id=spiffe_id, tools=len(result), code="NRVQ-API-7082")
    return result


@router.get("/agents/{spiffe_id:path}/trust-history")
async def agent_trust_history(
    spiffe_id: str,
    namespace: str | None = Query(None),
    range_: str = Query("7d", alias="range"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """Real per-day allow/block counts + average trust for one agent, aggregated from audit_log."""
    namespace = read_namespace(user, namespace)
    stmt = select(
        AuditLogEntry.timestamp_utc, AuditLogEntry.decision, AuditLogEntry.trust_score
    ).where(
        AuditLogEntry.agent_id == spiffe_id,
        AuditLogEntry.timestamp_utc >= _since_for_range(range_),
    )
    if namespace and namespace != "all":
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    rows = (await session.execute(stmt.limit(_AGENT_AUDIT_LIMIT))).all()

    buckets: dict[str, dict] = {}
    for ts, decision, trust in rows:
        day = ts.date().isoformat()
        bucket = buckets.setdefault(day, {"time": day, "allow": 0, "block": 0, "_tsum": 0.0, "_n": 0})
        if decision == "block":
            bucket["block"] += 1
        else:
            bucket["allow"] += 1
        if trust is not None:
            bucket["_tsum"] += float(trust)
            bucket["_n"] += 1

    history = [
        {
            "time": b["time"],
            "allow": b["allow"],
            "block": b["block"],
            "trust_score": round(b["_tsum"] / b["_n"], 3) if b["_n"] else None,
        }
        for _, b in sorted(buckets.items())
    ]
    log.debug("nrvq.api.agent.trust_history", spiffe_id=spiffe_id, days=len(history), code="NRVQ-API-7083")
    return history


@router.get("/agents/{spiffe_id:path}")
async def get_agent(spiffe_id: str, request: Request, user: dict = Depends(get_current_user)) -> dict:
    """Get one agent trust score."""
    # H2: the sibling routes (list_agents, agent_tool_usage, agent_trust_history) all scope by namespace —
    # this one trusted the spiffe_id path param outright, letting any authenticated caller read another
    # tenant's agent trust signals (cross-tenant IDOR) by simply guessing/enumerating a spiffe_id. Parse the
    # namespace out of the SVID (same helper the list route uses) and enforce the same scope here.
    read_namespace(user, _namespace_from_spiffe(spiffe_id))
    trust = await request.app.state.cache.get_trust(spiffe_id)
    if trust is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    details = await _trust_details(request, spiffe_id, trust.factors)
    return {
        "spiffe_id": spiffe_id,
        "score": trust.score,
        "category": trust.category.lower(),
        "violation_count": trust.violation_count,
        "signals": details["signals"],
        "dominant_signal": details["dominant_signal"],
        "recommendation": details["recommendation"],
    }


@router.put("/agents/{spiffe_id:path}/trust")
async def update_trust(
    spiffe_id: str, body: TrustUpdate, request: Request, user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Set an agent trust score manually.

    AGT-TRUST-02: the score is now a DURABLE, ENFORCED control (previously it was displayed but ignored by the
    evaluator — only freeze acted). Full-state semantics, mutually exclusive:
      score == 0    → FREEZE (block every call) + clear any cap.
      0 < score < 1 → a tighten-only trust CAP: the engine uses min(computed, score), so this can force a
                      misbehaving agent toward escalate/frozen but never RAISE trust above what behavior earns.
      score == 1.0  → CLEAR both the freeze and the cap (back to purely behavioral trust)."""
    require_admin(user)
    cache = request.app.state.cache
    if body.score == 0:
        await cache._client().set(f"agent_frozen:{spiffe_id}", "1")
        await cache.clear_trust_override(spiffe_id)
    elif body.score >= 1.0:
        await cache._client().delete(f"agent_frozen:{spiffe_id}")
        await cache.clear_trust_override(spiffe_id)
    else:
        await cache._client().delete(f"agent_frozen:{spiffe_id}")
        await cache.set_trust_override(spiffe_id, body.score)
    trust = TrustScore(score=body.score, category="frozen" if body.score == 0 else "")
    await cache.set_trust(spiffe_id, trust)
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": trust.score, "category": trust.category.lower()}


async def _trust_details(request: Request, spiffe_id: str, factors: dict) -> dict:
    """Return latest trust signal breakdown for one agent."""
    raw = await request.app.state.cache._client().get(f"trustcalc:{spiffe_id}")
    if raw:
        payload = json.loads(raw)
        return {
            "signals": payload.get("signals", {}),
            "dominant_signal": payload.get("dominant_signal", ""),
            "recommendation": payload.get("recommendation", ""),
        }
    return {
        "signals": factors.get("signals", {}),
        "dominant_signal": factors.get("dominant_signal", ""),
        "recommendation": factors.get("recommendation", ""),
    }
