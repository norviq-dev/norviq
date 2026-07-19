# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import json
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, require_target_cluster
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.synthetic import is_synthetic_identity  # the ONE shared synthetic/probe classifier
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()
router = APIRouter()

# A bound so one agent's history query never loads an unbounded slice of audit_log into memory.
_AGENT_AUDIT_LIMIT = 5000

# Perf: default + hard caps on the number of agent rows /agents returns, so one request can
# never fan out into an O(total-fleet) list. The namespace-scoped SCAN already bounds a tenant to its own
# agents; this additionally bounds the admin / all-namespaces view.
_AGENT_LIST_DEFAULT_LIMIT = 1000
_AGENT_LIST_MAX_LIMIT = 5000


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
    limit: int = Query(default=_AGENT_LIST_DEFAULT_LIMIT, ge=1, le=_AGENT_LIST_MAX_LIMIT),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List agents with trust scores, scoped to the caller's namespace.

    Reads the live ``trust:*`` cache first; when it is cold (entries past their TTL)
    it falls back to the persistent ``agent_registry`` so the Agents view stays populated.
    """
    namespace = read_namespace(user, namespace)  # None => all namespaces (admin); own ns for a tenant
    cache = request.app.state.cache
    last_seen_map = await _registry_last_seen(namespace)  # real Last Seen, batched
    client = cache._client()
    # Perf: scope the SCAN Redis-side to the caller's namespace instead of walking the ENTIRE
    # cluster-wide ``trust:*`` keyspace and filtering in Python — a single-tenant list is then O(its own
    # agents), not O(total fleet). The SVID encodes ns as ``.../ns/<ns>/...`` so a ns-anchored glob returns
    # only that tenant's keys. The exact ``_namespace_from_spiffe`` check stays as a hard scoping backstop
    # (the glob merely bounds the scan; the check guarantees correctness even for an odd namespace value).
    match = f"trust:spiffe://*/ns/{namespace}/*" if namespace else "trust:*"
    spiffe_ids: list[str] = []
    async for key in client.scan_iter(match):
        spiffe_id = str(key).replace("trust:", "", 1)
        if namespace and _namespace_from_spiffe(spiffe_id) != namespace:
            continue
        spiffe_ids.append(spiffe_id)
        if len(spiffe_ids) >= limit:  # cap the returned list
            break
    rows = await _hydrate_agent_rows(request, cache, spiffe_ids, last_seen_map)
    if not rows:
        rows = await _agents_from_registry(namespace)
    log.debug("nrvq.api.agents.listed", count=len(rows), code="NRVQ-API-7030")
    return rows


async def _hydrate_agent_rows(request: Request, cache, spiffe_ids: list[str], last_seen_map: dict) -> list[dict]:
    """Build the list rows for a set of spiffe_ids while BATCHING the two per-agent reads
    (``trust:`` + ``trustcalc:``) into two pipelined MGETs, instead of two sequential GETs per agent (avoids
    an N+1). A real Redis client (has ``mget``) collapses N agents to ~2 round-trips; a
    unit-test / legacy client without ``mget`` degrades to the per-agent path (small N). The emitted row
    shape is identical on both paths (including the ``synthetic`` flag)."""
    if not spiffe_ids:
        return []
    client = cache._client()
    mget = getattr(client, "mget", None)
    rows: list[dict] = []
    if mget is not None:
        trust_vals = list(await mget([f"trust:{sid}" for sid in spiffe_ids]))
        calc_vals = list(await mget([f"trustcalc:{sid}" for sid in spiffe_ids]))
        for sid, tval, cval in zip(spiffe_ids, trust_vals, calc_vals):
            if not tval:
                continue  # entry aged out between the SCAN and the MGET
            trust = TrustScore.model_validate_json(tval)
            rows.append(_agent_row(sid, trust, _details_from_raw(cval, trust.factors), last_seen_map.get(sid)))
        return rows
    for sid in spiffe_ids:
        trust = await cache.get_trust(sid)
        if trust:
            details = await _trust_details(request, sid, trust.factors)
            rows.append(_agent_row(sid, trust, details, last_seen_map.get(sid)))
    return rows


def _agent_row(spiffe_id: str, trust: TrustScore, details: dict, last_seen: str | None) -> dict:
    """The single shared shape for one ``/agents`` list row (used by both the batched and legacy paths)."""
    agent_class = _class_from_spiffe(spiffe_id)
    return {
        "spiffe_id": spiffe_id,
        # The SVID encodes ns + class — parse them so the table shows real values instead of "–".
        "namespace": _namespace_from_spiffe(spiffe_id),
        "agent_class": agent_class,
        "last_seen": last_seen,
        "score": trust.score,
        "category": trust.category.lower(),
        "violation_count": trust.violation_count,
        "signals": details["signals"],
        "dominant_signal": details["dominant_signal"],
        "recommendation": details["recommendation"],
        # Flag synthetic/probe/eval identities (the ONE shared classifier) so the Overview trust
        # donut + Agent Monitor exclude them and RECONCILE with the asset/attack graph, which already hides
        # exactly these probes by default.
        "synthetic": is_synthetic_identity(agent_class, spiffe_id),
    }


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
    rows = []
    for entry in entries:
        agent_class = entry.agent_class or _class_from_spiffe(entry.spiffe_id)
        rows.append(
            {
                "spiffe_id": entry.spiffe_id,
                # The registry already stores ns/class/last_seen — surface them.
                "namespace": entry.namespace or _namespace_from_spiffe(entry.spiffe_id),
                "agent_class": agent_class,
                "last_seen": entry.last_seen.isoformat() if entry.last_seen else None,
                "score": entry.trust_score,
                "category": entry.trust_category.lower(),
                "violation_count": entry.violation_count,
                "signals": {},
                "dominant_signal": "",
                "recommendation": "",
                # Same synthetic flag on the cold-cache (registry) path so the list reconciles
                # with the graph whether it is served hot (trust:*) or cold (agent_registry).
                "synthetic": is_synthetic_identity(agent_class, entry.spiffe_id),
            }
        )
    return rows


async def _agent_from_registry(spiffe_id: str) -> dict | None:
    """One agent from the persistent registry — the single-identity counterpart of
    ``_agents_from_registry``. ``trust:*`` cache entries carry a TTL, so an agent that still shows in
    the (registry-backed) list would 404 in its detail view once its hot entry lapses. ``get_agent``
    falls back here for cold-cache parity with ``list_agents``. Returns None when the identity isn't in
    the registry either (a genuine 404). Namespace scoping is enforced by the caller BEFORE this runs."""
    try:
        from sqlalchemy import select

        from norviq.api.db.models import AgentRegistryEntry
        from norviq.api.db.session import get_session

        provider = get_session()
        session = await provider.__anext__()
        try:
            entry = (
                await session.execute(
                    select(AgentRegistryEntry).where(AgentRegistryEntry.spiffe_id == spiffe_id)
                )
            ).scalar_one_or_none()
        finally:
            await provider.aclose()
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.api.agent.registry_read_failed", spiffe_id=spiffe_id, error=str(exc), code="NRVQ-API-7033")
        return None
    if entry is None:
        return None
    return {
        "spiffe_id": entry.spiffe_id,
        "score": entry.trust_score,
        "category": (entry.trust_category or "unknown").lower(),
        "violation_count": entry.violation_count,
        # No live behavioral factors when served from the registry snapshot (the hot signals expired
        # with the cache entry); the detail view shows the persisted score without the signal breakdown.
        "signals": {},
        "dominant_signal": "",
        "recommendation": "",
    }


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

    # Tag each tool with its risk tier (the SAME TOOL_RISK_MAP the asset graph uses) so the Tool
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
    # The sibling routes (list_agents, agent_tool_usage, agent_trust_history) all scope by namespace —
    # this one must not trust the spiffe_id path param outright, or any authenticated caller could read
    # another tenant's agent trust signals (cross-tenant IDOR) by guessing/enumerating a spiffe_id. Mirror
    # list_agents' scoping EXACTLY: resolve the caller's namespace scope, then require the agent's own
    # namespace to match it. Comparing the agent's ns against the caller's RESOLVED scope (rather than
    # passing it as the *requested* value) also blocks a scoped tenant from reading a NAMESPACELESS agent —
    # exactly the agent list_agents hides. Treat a non-matching (namespaceless or other-ns) agent as 404,
    # the same "not visible" outcome as the list.
    scope_ns = read_namespace(user, None)  # None => admin/all; own ns for a tenant; 403 for a no-scope viewer
    if scope_ns and _namespace_from_spiffe(spiffe_id) != scope_ns:
        raise HTTPException(status_code=404, detail="Agent not found")
    trust = await request.app.state.cache.get_trust(spiffe_id)
    if trust is None:
        # Cold-cache parity with list_agents (which falls back to the persistent registry when the
        # trust:* cache is cold): the hot entry has a TTL, so without this a listed agent's detail view
        # 404s once its entry lapses. Scope was already enforced above, so this fallback stays tenant-safe.
        fallback = await _agent_from_registry(spiffe_id)
        if fallback is not None:
            return fallback
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
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Set an agent trust score manually.

    The score is a DURABLE, ENFORCED control. Full-state semantics, mutually exclusive:
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
    # SECURITY (fail-open fix): persist the freeze/cap DURABLY (source of truth) so a Redis flush/restart can
    # never silently lift the kill-switch. Warm-seeded back into Redis at startup (warm_agent_overrides).
    # Best-effort UPDATE of the registered agent's row; an unregistered agent gets its durable state stamped
    # on its next registration path if needed — the common case (freezing a known misbehaving agent) is covered.
    frozen = body.score == 0
    cap = body.score if (0 < body.score < 1.0) else None
    try:
        await session.execute(
            text("UPDATE agent_registry SET frozen = :f, trust_cap = :c WHERE spiffe_id = :s"),
            {"f": frozen, "c": cap, "s": spiffe_id},
        )
        await session.commit()
    except Exception as exc:  # noqa: BLE001 - durability is best-effort; the Redis write already took effect
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=str(exc), code="NRVQ-API-7033")
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, frozen=frozen, cap=cap,
             code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": trust.score, "category": trust.category.lower()}


async def warm_agent_overrides(cache, session_factory=get_session) -> int:
    """SECURITY (fail-open fix): at startup, re-seed durable admin freeze/cap from agent_registry into Redis so
    a Redis restart/flush (which loses the ephemeral agent_frozen:/override keys) can NEVER leave a killed or
    capped agent running unpoliced. Mirrors settings_router.warm_ns_settings. Best-effort; returns count seeded."""
    provider = session_factory()
    session = await provider.__anext__()
    seeded = 0
    try:
        rows = (await session.execute(
            text("SELECT spiffe_id, frozen, trust_cap FROM agent_registry WHERE frozen = true OR trust_cap IS NOT NULL")
        )).mappings().all()
        for r in rows:
            if r["frozen"]:
                await cache._client().set(f"agent_frozen:{r['spiffe_id']}", "1")
                seeded += 1
            elif r["trust_cap"] is not None:
                await cache.set_trust_override(r["spiffe_id"], float(r["trust_cap"]))
                seeded += 1
        log.info("nrvq.api.agent.overrides_warmed", count=seeded, code="NRVQ-API-7034")
    except Exception as exc:  # noqa: BLE001 - warm is best-effort; a DB hiccup must not block startup
        log.warning("nrvq.api.agent.overrides_warm_failed", error=str(exc), code="NRVQ-API-7035")
    finally:
        await provider.aclose()
    return seeded


@router.delete("/agents/{spiffe_id:path}")
async def deregister_agent(
    spiffe_id: str, request: Request, user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Admin removal of a decommissioned agent identity from the registry. The background pruner ages
    stale agents out after agent_registry_retention_days; this is the immediate manual path (without it a
    decommissioned agent lingers and surfaces as a phantom 'awaiting' node on the asset graph).
    Registry + trust-cache only — never touches policies or audit history; a live agent that calls
    again is simply re-registered on its next evaluated call."""
    require_admin(user)
    from norviq.api.db.models import AgentRegistryEntry

    row = (
        await session.execute(select(AgentRegistryEntry).where(AgentRegistryEntry.spiffe_id == spiffe_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found in registry")
    await session.delete(row)
    await session.commit()
    # Best-effort: drop the live trust/freeze cache entries so a deleted identity doesn't linger there.
    try:
        cache = request.app.state.cache
        await cache._client().delete(f"agent_frozen:{spiffe_id}")
        await cache.clear_trust_override(spiffe_id)
    except Exception:  # noqa: BLE001 - cache cleanup is cosmetic; the registry row is already gone
        pass
    log.info("nrvq.api.agent.deregistered", spiffe_id=spiffe_id, actor=user.get("sub"),
             actor_role=user.get("role"), code="NRVQ-API-7121")
    return {"deleted": True, "spiffe_id": spiffe_id}


def _details_from_raw(raw: str | None, factors: dict) -> dict:
    """Build the trust-signal breakdown from a raw ``trustcalc:`` payload, falling back to the trust
    score's own ``factors`` when no live breakdown is cached. Shared by the batched list path
    (``_hydrate_agent_rows``) and the single-agent detail route so both stay byte-identical."""
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


async def _trust_details(request: Request, spiffe_id: str, factors: dict) -> dict:
    """Return latest trust signal breakdown for one agent."""
    raw = await request.app.state.cache._client().get(f"trustcalc:{spiffe_id}")
    return _details_from_raw(raw, factors)
