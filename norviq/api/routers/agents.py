# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, require_target_cluster
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.graph_maintenance import try_remove_graph_node
from norviq.api.synthetic import is_synthetic_identity  # the ONE shared synthetic/probe classifier
from norviq.sdk.core.trust import TrustScore
from norviq.startup_retry import warm_with_backoff

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
    """Extract the agent_class from spiffe://.../sa/{agent_class} (the SVID encodes it)."""
    parts = spiffe_id.split("/")
    if "sa" in parts:
        idx = parts.index("sa")
        if idx + 1 < len(parts) and parts[idx + 1]:
            return parts[idx + 1]
    return None


async def _registry_last_seen(namespace: str | None) -> dict[str, str]:
    """Batch-load {spiffe_id: last_seen ISO} from the persistent agent_registry in ONE query, so the
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

    Returns the FULL governed fleet: the authoritative roster from ``agent_registry`` unioned with the live
    ``trust:*`` cache, so an agent shows its live score where its cache entry is still warm and its last-known
    registry score where the entry has aged out (trust TTL is short — ``redis_ttl_trust_s``). This avoids the
    list collapsing to only agents evaluated within the TTL window when the cache is partially warm.
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
    warm_rows = await _hydrate_agent_rows(request, cache, spiffe_ids, last_seen_map)
    # Union the live cache with the authoritative registry roster. Previously the registry was consulted ONLY
    # when the cache scan returned zero rows, so on a partially-warm cache the list collapsed to just the
    # agents evaluated within the trust TTL — a quiet-but-governed agent vanished from the Agents view until
    # the whole fleet went idle (cache fully empty). Merging keeps the list at the full governed fleet.
    registry_rows = await _agents_from_registry(namespace)
    rows = _merge_roster(registry_rows, warm_rows)[:limit]
    log.debug("nrvq.api.agents.listed", count=len(rows), code="NRVQ-API-7030")
    return rows


# Live-trust fields overlaid from the warm cache onto the authoritative registry row (everything else —
# spiffe/ns/class/last_seen/synthetic — stays from the registry, the source of truth for the roster).
# violation_count is DELIBERATELY not overlaid. _safe_set_trust builds the cached TrustScore without
# one, so it is always 0 there — overlaying it hid the registry's real count for the whole 30s cache TTL,
# i.e. for exactly the agent being blocked right now, and the number only surfaced once the agent went
# QUIET. The Agent Monitor's amber(>3)/red(>8) thresholds were unreachable during an incident, which is
# the only time anyone looks. The registry row is the source of truth for it.
_LIVE_TRUST_FIELDS = ("score", "category", "signals", "dominant_signal", "recommendation")


def _merge_roster(registry_rows: list[dict], warm_rows: list[dict]) -> list[dict]:
    """Union the authoritative ``agent_registry`` roster with the live ``trust:*`` cache.

    Every registered agent is listed. Where an agent's cache entry is still warm (written on its last
    ``/evaluate``, TTL ``redis_ttl_trust_s``), its LIVE score/category/violations/signals are shown; where the
    entry has aged out, the agent keeps its last-known registry score instead of disappearing from the view.
    A cache-warm agent not yet persisted to the registry is still included (never drop a live agent).
    """
    warm_by_id = {r["spiffe_id"]: r for r in warm_rows}
    seen: set[str] = set()
    merged: list[dict] = []
    for base in registry_rows:
        sid = base["spiffe_id"]
        seen.add(sid)
        live = warm_by_id.get(sid)
        merged.append({**base, **{f: live[f] for f in _LIVE_TRUST_FIELDS}} if live else base)
    for sid, live in warm_by_id.items():
        if sid not in seen:
            merged.append(live)
    # Freshest first, so the perf cap keeps the most-recently-seen agents when a fleet exceeds the limit.
    merged.sort(key=lambda r: r.get("last_seen") or "", reverse=True)
    return merged


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


def _mark_truncated(response: Response, truncated: bool, spiffe_id: str, view: str) -> None:
    """Say so when a series was cut, instead of returning a shorter one that looks complete (F-042).

    These endpoints cap at `_AGENT_AUDIT_LIMIT` rows, and the cap is reached by exactly the agents an
    operator most wants to look at. Nothing in the response said so, so a busy agent's chart rendered
    as a confident, complete picture drawn from a partial slice.

    A header rather than a field in the body: both routes return a bare `list[dict]` that the console
    already consumes, and changing the response shape to carry a flag would break every existing
    caller to fix a reporting problem. A header is additive — the console can read it when it is ready
    to render the warning, and a script can check it today.
    """
    response.headers["X-Nrvq-Truncated"] = "true" if truncated else "false"
    if truncated:
        response.headers["X-Nrvq-Truncated-Limit"] = str(_AGENT_AUDIT_LIMIT)
        log.warning(
            "nrvq.api.agent.series_truncated",
            spiffe_id=spiffe_id,
            view=view,
            limit=_AGENT_AUDIT_LIMIT,
            code="NRVQ-API-7084",
        )


# NOTE: these specific routes MUST be declared before the greedy /agents/{spiffe_id:path} GET below,
# otherwise the path converter swallows the "/tool-usage" / "/trust-history" suffix.
@router.get("/agents/{spiffe_id:path}/tool-usage")
async def agent_tool_usage(
    spiffe_id: str,
    response: Response,
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
    # ORDERED before the limit (F-042). `limit` without `order_by` takes whatever rows the planner
    # happens to emit first, so a busy agent's chart was drawn from an ARBITRARY 5000 of its
    # calls — not the most recent, not a sample, just whatever came back. Two identical requests
    # could disagree, and neither was wrong to the reader, because nothing said the series was cut.
    # Newest-first is the honest choice for a time series: a truncated chart then shows a shorter
    # recent window rather than a full window with holes in it.
    rows = (await session.execute(
        stmt.order_by(AuditLogEntry.timestamp_utc.desc()).limit(_AGENT_AUDIT_LIMIT)
    )).all()
    truncated = len(rows) >= _AGENT_AUDIT_LIMIT

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
    _mark_truncated(response, truncated, spiffe_id, "tool-usage")
    log.debug("nrvq.api.agent.tool_usage", spiffe_id=spiffe_id, tools=len(result), code="NRVQ-API-7082")
    return result


@router.get("/agents/{spiffe_id:path}/trust-history")
async def agent_trust_history(
    spiffe_id: str,
    response: Response,
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
    # ORDERED before the limit (F-042). `limit` without `order_by` takes whatever rows the planner
    # happens to emit first, so a busy agent's chart was drawn from an ARBITRARY 5000 of its
    # calls — not the most recent, not a sample, just whatever came back. Two identical requests
    # could disagree, and neither was wrong to the reader, because nothing said the series was cut.
    # Newest-first is the honest choice for a time series: a truncated chart then shows a shorter
    # recent window rather than a full window with holes in it.
    rows = (await session.execute(
        stmt.order_by(AuditLogEntry.timestamp_utc.desc()).limit(_AGENT_AUDIT_LIMIT)
    )).all()
    truncated = len(rows) >= _AGENT_AUDIT_LIMIT

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
    _mark_truncated(response, truncated, spiffe_id, "trust-history")
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


# The shape the rest of the product accepts for an agent id: the evaluator requires the "spiffe://" prefix
# (Evaluator._validate_spiffe) and POST /keys mints any spiffe_id up to 512 characters (keys.py), so an
# operator-chosen id such as "spiffe://acme-agent" or ".../sa/agent:v2" is registered and listed and must
# stay freezable. On top of that rule these routes refuse only what is dangerous to WRITE under: an empty
# id, whitespace or control characters, and the glob characters * ? [ ] (PUT .../trust used to create a
# frozen registry row for "*" or " " alike). 512 is also the registry column's width.
_AGENT_ID_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f*?\[\]]")


def _require_agent_id(spiffe_id: str) -> None:
    """422 unless ``spiffe_id`` is an agent id the evaluator and the key API accept, and safe to write under."""
    if (not spiffe_id.startswith("spiffe://") or len(spiffe_id) <= len("spiffe://") or len(spiffe_id) > 512
            or _AGENT_ID_FORBIDDEN.search(spiffe_id)):
        raise HTTPException(status_code=422, detail="Not a valid agent id (spiffe://..., at most 512 characters, "
                                                    "no whitespace or * ? [ ])")


# How long an admin trust write waits for another one on the same agent before answering 503. Below the
# 10 s asyncpg command timeout, so a contended lock is told apart from a database that does not answer.
_LOCK_TIMEOUT = "5s"
# The bound on every store (Redis) call made while an agent's lock — and so a DB connection — is held. A
# store that hangs rather than refuses used to keep both for ~20 s per request (redis-py's own socket
# timeout, retried), and 20 concurrent admin writes exhausted the DB pool. A timeout is a store failure.
_STORE_TIMEOUT_S = 2.0
# Agents per transaction in the boot warm. Measured on loopback: one transaction per agent cost 3.4 ms
# per agent, so ~2.8k frozen or capped agents filled the warm's 10 s attempt bound and the rest were never
# written back; see warm_agent_overrides for the batched figures.
_WARM_BATCH = 500


class _LockContended(Exception):
    """Another admin trust write holds this agent's lock for longer than _LOCK_TIMEOUT."""


class _StoreUnconfirmed(Exception):
    """The registry was read under the lock, but the store did not confirm the write made from it."""


def _is_lock_timeout(exc: BaseException) -> bool:
    """True for Postgres' lock_timeout (SQLSTATE 55P03), however SQLAlchemy and asyncpg wrap it."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if getattr(exc, "sqlstate", None) == "55P03" or getattr(exc, "pgcode", None) == "55P03":
            return True
        exc = getattr(exc, "orig", None) or exc.__cause__
    return False


async def _lock_agent(session: AsyncSession, spiffe_id: str) -> None:
    """Serialize every admin trust write for one agent — PUT .../trust in all directions, DELETE, the
    reset, and the boot warm — for the rest of this transaction, across API replicas.

    Each of them changes Postgres and Redis, and two of them interleaved used to leave the two disagreeing
    with both callers told 200: a clear committed, a freeze set Redis and committed, then the clear's
    Redis DEL landed, so the registry said frozen and the agent ran unfrozen until an API restart; and a
    DELETE that had checked the row deleted it after a freeze committed onto it. A row lock cannot cover
    this, because the row may not exist yet (a first freeze creates it). An advisory lock on the id can.
    Held until commit or rollback, so every Redis write below happens while it is held. Raises
    _LockContended after _LOCK_TIMEOUT; any other failure is the database's."""
    await session.execute(text(f"SET LOCAL lock_timeout = '{_LOCK_TIMEOUT}'"))
    try:
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"agent_trust:{spiffe_id}"})
    except Exception as exc:
        if _is_lock_timeout(exc):
            raise _LockContended(spiffe_id) from exc
        raise


async def _store(awaitable):
    """One store call made under an agent's lock, bounded by _STORE_TIMEOUT_S."""
    return await asyncio.wait_for(awaitable, _STORE_TIMEOUT_S)


async def _live_control(cache, spiffe_id: str) -> tuple[bool, float | None]:
    """The admin freeze/cap as Redis holds it now (what the trust calculator enforces)."""
    frozen = await _store(cache._client().get(f"agent_frozen:{spiffe_id}"))
    cap = await _store(cache._client().get(f"agent_trust_override:{spiffe_id}"))
    return bool(frozen), (float(cap) if cap is not None else None)


async def _registry_control(session: AsyncSession, spiffe_id: str) -> tuple[bool, float | None] | None:
    """The agent's durable freeze/cap, or None when it has no registry row."""
    row = (await session.execute(
        text("SELECT frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"), {"s": spiffe_id}
    )).mappings().first()
    return None if row is None else (bool(row["frozen"]), row["trust_cap"])


def _stricter(a: tuple[bool, float | None], b: tuple[bool, float | None]) -> tuple[bool, float | None]:
    """The tighter of two freeze/cap states: frozen if either is, else the lower cap."""
    caps = [c for c in (a[1], b[1]) if c is not None]
    return (a[0] or b[0]), (min(caps) if caps else None)


async def _rollback(session: AsyncSession) -> None:
    try:
        await session.rollback()
    except Exception:  # noqa: BLE001 - the session is being abandoned; the original error is what we report
        pass


def _uncertain(spiffe_id: str, user: dict, error: BaseException, outcome: str) -> HTTPException:
    log.error("nrvq.api.agent.trust_state_uncertain", spiffe_id=spiffe_id, error=f"{type(error).__name__}: {error}",
              outcome=outcome, actor=user.get("sub"), code="NRVQ-API-7148")
    return HTTPException(status_code=503, detail=(
        "State uncertain: the change may be live but is NOT confirmed persisted, and the store could not be "
        "set from the registry. Retry, then check the agent."))


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
      score == 1.0  → CLEAR both the freeze and the cap (back to purely behavioral trust).

    200 means the registry row and Redis both hold the new state. Under the per-agent lock (_lock_agent) the
    row is written, then Redis is written in one MULTI, then the transaction commits. An identity with no
    registry row gets one carrying the freeze or cap: the evaluator's first-call upsert
    (``upsert_agent_registry``) does not touch ``frozen``/``trust_cap``.

    Every failure is a 503 that says what is true, and errs toward the freeze:
      - the lock is held by another admin write past _LOCK_TIMEOUT: nothing applied (7149);
      - Postgres down: a freeze is still applied live (outside the lock — the one unserialized write, and it
        only tightens), a cap or clear changes nothing (7033);
      - Redis down: a freeze is committed (durable; applied at the next API start), a cap or clear is rolled
        back and Redis is set back to the registry's state under the lock (7147);
      - the commit fails: the lock is gone with it, so Redis is set from the registry under a NEW lock in a
        new transaction — the row is the truth, and also tells a lost commit ack from a failed commit
        (7033, reconciled=). If Postgres cannot be reached for that, no other admin write can commit either,
        and Redis gets the stricter of the old and new state;
      - anything Redis could not be brought back from: "state uncertain" (7148, ERROR).
    A cap or clear can lift a freeze, and cannot land in Redis after its commit without leaving the lock
    (an xact lock ends at commit), so the reconcile above is what keeps that window from sticking."""
    require_admin(user)
    _require_agent_id(spiffe_id)
    cache = request.app.state.cache
    frozen = body.score == 0
    cap = body.score if (0 < body.score < 1.0) else None
    display = TrustScore(score=body.score, category="frozen" if frozen else "")
    try:
        await _lock_agent(session, spiffe_id)
        prior = await _registry_control(session, spiffe_id) or (False, None)
        await _persist_trust_control(session, spiffe_id, frozen, cap, body.score)
    except _LockContended:
        await _rollback(session)
        log.warning("nrvq.api.agent.trust_write_contended", spiffe_id=spiffe_id, score=body.score,
                    actor=user.get("sub"), code="NRVQ-API-7149")
        raise HTTPException(status_code=503, detail=(
            "Another admin change to this agent is in progress; nothing was applied. Retry.")) from None
    except Exception as exc:  # noqa: BLE001 - any failure here means the control is not durable
        await _rollback(session)
        live = False
        if frozen:
            try:
                await _store(cache.apply_admin_trust_control(spiffe_id, frozen=True, cap=None, display=display))
                live = True
            except Exception:  # noqa: BLE001 - reported in the 503 below
                pass
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=str(exc), live=live,
                    actor=user.get("sub"), code="NRVQ-API-7033")
        detail = ("Freeze applied live but NOT persisted; it is lost on a Redis flush or restart. Retry."
                  if live else "Trust change not applied: the registry write failed. Retry.")
        raise HTTPException(status_code=503, detail=detail) from exc
    try:
        await _store(cache.apply_admin_trust_control(spiffe_id, frozen=frozen, cap=cap, display=display))
    except Exception as exc:  # noqa: BLE001 - Redis did not confirm it; decide what Postgres keeps
        durable = False
        if frozen:
            try:
                await session.commit()
                durable = True
            except Exception:  # noqa: BLE001 - reported in the 503 below
                await _rollback(session)
        else:
            # A timed-out MULTI may still have landed. Still under the lock, put Redis back to the registry's
            # state before rolling back, so a loosening can never stay live without its durable copy.
            try:
                await _store(cache.apply_admin_trust_control(spiffe_id, frozen=prior[0], cap=prior[1]))
            except Exception:  # noqa: BLE001 - the store is now in an unknown state
                await _rollback(session)
                raise _uncertain(spiffe_id, user, exc, "store_not_reset_after_failed_write") from exc
            await _rollback(session)
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    score=body.score, durable=durable, actor=user.get("sub"), code="NRVQ-API-7147")
        detail = ("Freeze persisted but NOT live: the store did not answer. It is applied at the next API "
                  "start, or retry now." if durable else "Trust change not applied: the store did not answer. Retry.")
        raise HTTPException(status_code=503, detail=detail) from exc
    try:
        await session.commit()
    except Exception as exc:  # noqa: BLE001 - outcome unknown: a failed commit or a lost ack
        await _rollback(session)
        factory = request.app.dependency_overrides.get(get_session, get_session)
        try:
            durable = await _reconcile_from_registry(factory, cache, spiffe_id)
        except _LockContended:
            # Another admin write took the agent after ours ended and owns Redis now; it is serialized.
            durable = None
        except _StoreUnconfirmed:
            raise _uncertain(spiffe_id, user, exc, "commit_failed_store_not_set_from_registry") from exc
        except Exception:  # noqa: BLE001 - Postgres unreachable: no other admin write can commit either
            try:
                strict_frozen, strict_cap = _stricter(prior, (frozen, cap))
                await _store(cache.apply_admin_trust_control(spiffe_id, frozen=strict_frozen, cap=strict_cap))
            except Exception:  # noqa: BLE001 - neither store can be confirmed
                raise _uncertain(spiffe_id, user, exc, "commit_failed_registry_unreachable_store_unset") from exc
            raise _uncertain(spiffe_id, user, exc, "commit_unconfirmed_stricter_state_live") from exc
        applied = durable == (frozen, cap)
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=str(exc), reconciled=True,
                    applied=applied, actor=user.get("sub"), code="NRVQ-API-7033")
        if not applied:
            raise HTTPException(status_code=503, detail=(
                "Trust change not applied: the registry write failed; the store matches the registry. Retry."
            )) from exc
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, frozen=frozen, cap=cap,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": display.score, "category": display.category.lower()}


async def _reconcile_from_registry(session_factory, cache, spiffe_id: str) -> tuple[bool, float | None]:
    """In a new transaction under the agent's lock, set Redis from the registry row and return that state.

    Used after a commit whose outcome is unknown: the lock died with the transaction, so writing back what
    Redis held before (the first version of this code) could erase a freeze another replica committed in
    between. The row read under a fresh lock is the truth, whether our commit landed or not."""
    provider = session_factory()
    session = await provider.__anext__()
    try:
        await _lock_agent(session, spiffe_id)
        state = await _registry_control(session, spiffe_id) or (False, None)
        try:
            await _store(cache.apply_admin_trust_control(spiffe_id, frozen=state[0], cap=state[1]))
        except Exception as exc:  # noqa: BLE001 - Postgres answered; it is the store that did not
            raise _StoreUnconfirmed(spiffe_id) from exc
        await session.commit()
        return state
    finally:
        await _rollback(session)
        await provider.aclose()


async def _persist_trust_control(session: AsyncSession, spiffe_id: str, frozen: bool, cap: float | None,
                                 score: float) -> None:
    """Write the freeze/cap to agent_registry (uncommitted), the durable copy warm_agent_overrides
    re-seeds Redis from.

    A freeze or cap UPSERTS: the previous plain UPDATE matched no row for an identity that had never called
    in (or had been deregistered), so the control lived only in Redis while the route said 200. A clear only
    UPDATEs — with no row there is nothing durable to clear, and inserting one would list a phantom agent."""
    from sqlalchemy.dialects.postgresql import insert

    from norviq.api.db.models import AgentRegistryEntry

    if frozen or cap is not None:
        now = datetime.now(timezone.utc)
        stmt = insert(AgentRegistryEntry).values(
            spiffe_id=spiffe_id,
            # The same fallbacks the evaluator's write-through uses, so its first call lands on this row.
            namespace=_namespace_from_spiffe(spiffe_id) or "default",
            agent_class=_class_from_spiffe(spiffe_id) or "",
            # Display only, until the evaluator's first call overwrites them: a cap is the highest score
            # the agent can have, so it is shown in the band the console would put that score in.
            trust_score=score,
            trust_category="Frozen" if frozen else ("High" if score >= 0.7 else "Medium" if score >= 0.4 else "Low"),
            violation_count=0,
            last_seen=now,
            created_at=now,
            frozen=frozen,
            trust_cap=cap,
        )
        # Only the two control columns on conflict: the row's identity, score and counters belong to the
        # evaluator's write-through and are not the admin's to overwrite.
        stmt = stmt.on_conflict_do_update(index_elements=["spiffe_id"], set_={"frozen": frozen, "trust_cap": cap})
        await session.execute(stmt)
    else:
        await session.execute(
            text("UPDATE agent_registry SET frozen = false, trust_cap = NULL WHERE spiffe_id = :s"),
            {"s": spiffe_id},
        )


async def warm_agent_overrides(cache, session_factory=get_session, progress: dict | None = None,
                               batch_size: int = _WARM_BATCH) -> int:
    """SECURITY (fail-open fix): at startup, re-seed durable admin freeze/cap from agent_registry into Redis so
    a store that lost the agent_frozen:/override keys before this process started does not leave a killed or
    capped agent running unpoliced. Runs only at process start: a loss while the API runs is not repaired
    until an API process starts again. Adds what Postgres holds and deletes nothing. Returns the count
    seeded.

    RAISES on any failure. It used to catch its own error, log a WARNING and return the count reached (0 when
    the query failed), which reads exactly like "nothing is frozen" while every freeze stayed absent until
    the next restart. The SETs are idempotent, so the caller can simply run it again.

    Batched, in spiffe_id order, under the admin lock. Each batch is one transaction: take every agent's
    _lock_agent lock in hashtext order, re-read the batch's rows, write them in one pipeline, commit. Locked
    and re-read, an admin write on another replica lands wholly before the read or wholly after the write, so
    a stale snapshot can no longer put back a looser cap or a lifted freeze. Taking many locks cannot
    deadlock with an admin write, which holds exactly one; two warms take theirs in the same (lock-key)
    order. `progress` carries the last committed spiffe_id across the caller's retries, so a retry resumes
    where the previous attempt was cut off instead of re-warming the same head of the table.
    Measured on loopback (Postgres 5433, Redis 6379), batches of 500: 5 000 frozen or capped agents in 0.3 s and
    20 000 in 1.0-1.1 s, against the 10 s attempt bound; with the bound forced down to 0.45 s, 20 000 still
    completed on the third attempt because each retry resumed. One transaction per agent took 16.9 s for
    5 000 and never finished past ~2.8k at startup."""
    progress = progress if progress is not None else {}
    progress.setdefault("after", "")
    progress.setdefault("seeded", 0)
    provider = session_factory()
    session = await provider.__anext__()
    try:
        while True:
            ids = [r["spiffe_id"] for r in (await session.execute(
                text("SELECT spiffe_id FROM agent_registry WHERE (frozen = true OR trust_cap IS NOT NULL) "
                     "AND spiffe_id > :after ORDER BY spiffe_id LIMIT :n"),
                {"after": progress["after"], "n": batch_size},
            )).mappings().all()]
            if not ids:
                break
            await session.execute(
                text("SELECT count(pg_advisory_xact_lock(k)) FROM (SELECT DISTINCT hashtext('agent_trust:' || i) AS k "
                     "FROM unnest(CAST(:ids AS text[])) AS i ORDER BY k) AS keys"),
                {"ids": ids},
            )
            rows = (await session.execute(
                text("SELECT spiffe_id, frozen, trust_cap FROM agent_registry WHERE spiffe_id = ANY(:ids)"),
                {"ids": ids},
            )).mappings().all()
            seeded = 0
            async with cache._client().pipeline(transaction=False) as pipe:
                for r in rows:
                    if r["frozen"]:
                        await pipe.set(f"agent_frozen:{r['spiffe_id']}", "1")
                        seeded += 1
                    elif r["trust_cap"] is not None:
                        await pipe.set(f"agent_trust_override:{r['spiffe_id']}", str(float(r["trust_cap"])))
                        seeded += 1
                await pipe.execute()
            await session.commit()
            progress["after"] = ids[-1]
            progress["seeded"] += seeded
        log.info("nrvq.api.agent.overrides_warmed", count=progress["seeded"], code="NRVQ-API-7034")
    finally:
        await _rollback(session)
        await provider.aclose()
    return progress["seeded"]


async def warm_agent_overrides_at_startup(cache, session_factory=get_session) -> int | None:
    """warm_agent_overrides under norviq.startup_retry.warm_with_backoff: 3 attempts, 1 s then 2 s apart,
    each cut off at 10 s, logging nrvq.startup.agent_overrides_warm_retry (WARNING, NRVQ-API-7158) per
    failed attempt and nrvq.startup.agent_overrides_warm_failed (ERROR, NRVQ-API-7035) when all fail.
    Returns the count seeded, or None. Never raises. Nothing else writes these back while this process
    runs, so a transient failure here would otherwise leave them absent until the next restart. The
    attempts share one progress cursor: a retry resumes after the last committed batch."""
    progress: dict = {}
    return await warm_with_backoff(
        lambda: warm_agent_overrides(cache, session_factory, progress),
        "agent_overrides_warm",
        retry_code="NRVQ-API-7158",
        fail_code="NRVQ-API-7035",
    )


async def _reset_multi(cache, history_key: str, profile_key: str) -> tuple[list, bool, bool]:
    """Read what is about to be removed and remove it, in one MULTI: the counts are exactly what went."""
    async with cache._client().pipeline(transaction=True) as pipe:
        await pipe.zrange(history_key, 0, -1)
        await pipe.exists(history_key)
        await pipe.exists(profile_key)
        await pipe.delete(history_key, profile_key)
        history, has_history, has_profile, _ = await pipe.execute()
    return history, bool(has_history), bool(has_profile)


@router.post("/agents/{spiffe_id:path}/trust/reset")
async def reset_agent_trust_history(
    spiffe_id: str, request: Request, user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Admin-only, audited clean slate for an agent's BEHAVIOURAL record: deletes its rolling decision
    history (``AgentHistoryStore``, which drives violation_rate) and its learned profile
    (``AgentProfileStore``: known tools, entropy baselines), so trust is recomputed from the next call.

    Deliberately narrow. It does NOT lift a freeze or a trust cap (``PUT .../trust`` with 1.0 does, and is
    logged as its own action), does not touch the registry's cumulative ``violation_count`` or audit_log,
    and is the only API path that clears history: DELETE /agents keeps it, so wiping a misbehaving agent's
    record is never a side effect of housekeeping. The NRVQ-API-7145 line is the audit record — actor,
    the score and violation count it had before, and exactly what it removed: the counts are read in the
    same MULTI as the DEL, so an entry the evaluator records meanwhile is either counted or survives."""
    require_admin(user)
    _require_agent_id(spiffe_id)
    from norviq.api.db.models import AgentRegistryEntry
    from norviq.engine.trust.history import AgentHistoryStore
    from norviq.engine.trust.profile import AgentProfileStore

    cache = request.app.state.cache
    history_key = AgentHistoryStore(cache)._key(spiffe_id)
    profile_key = AgentProfileStore(cache)._key(spiffe_id)
    try:
        await _lock_agent(session, spiffe_id)
        row = (
            await session.execute(select(AgentRegistryEntry).where(AgentRegistryEntry.spiffe_id == spiffe_id))
        ).scalar_one_or_none()
        # Copied out now: ending the transaction below expires the ORM row.
        reg = None if row is None else SimpleNamespace(trust_score=row.trust_score, violation_count=row.violation_count,
                                                       frozen=bool(row.frozen), trust_cap=row.trust_cap)
        trust = await _store(cache.get_trust(spiffe_id))
        history, has_history, has_profile = await _store(_reset_multi(cache, history_key, profile_key))
    except Exception as exc:  # noqa: BLE001 - nothing is reported as cleared unless the MULTI answered
        await _rollback(session)
        contended = isinstance(exc, _LockContended)
        log.warning("nrvq.api.agent.trust_reset_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    contended=contended, actor=user.get("sub"), code="NRVQ-API-7146")
        detail = ("Another admin change to this agent is in progress; nothing was cleared. Retry." if contended
                  else "Trust history reset not confirmed: the store did not answer, so it may or may not have "
                       "cleared the history. Retry.")
        raise HTTPException(status_code=503, detail=detail) from exc
    # The MULTI ran: the record is gone, so from here on the audit line is written whatever else happens.
    # The transaction wrote nothing; ending it only releases the lock, and a failure to end it cannot undo
    # the reset (it used to answer 503 "nothing was cleared" with the history already deleted).
    await _rollback(session)
    present = [k for k, there in ((history_key, has_history), (profile_key, has_profile)) if there]
    if reg is None and trust is None and not present:
        raise HTTPException(status_code=404, detail="Agent not found")  # the MULTI found nothing to delete
    blocks = 0
    for raw in history:
        try:
            blocks += json.loads(raw).get("decision") == "block"
        except (TypeError, ValueError, AttributeError):
            continue  # a malformed entry was still removed; it is counted in history_entries_cleared
    audit = {
        "spiffe_id": spiffe_id,
        "score_before": trust.score if trust is not None else (reg.trust_score if reg is not None else None),
        # The registry's cumulative count (what the Agent Monitor shows; this reset leaves it alone),
        # and what the cleared window held, so the record says how much behaviour was wiped.
        "violation_count": reg.violation_count if reg is not None else (trust.violation_count if trust else 0),
        "history_entries_cleared": len(history),
        "history_blocks_cleared": blocks,
        "keys_cleared": present,
        "frozen": reg.frozen if reg is not None else False,
        "trust_cap": reg.trust_cap if reg is not None else None,
    }
    log.info("nrvq.api.agent.trust_reset", **audit, actor=user.get("sub"), actor_role=user.get("role"),
             code="NRVQ-API-7145")
    return {"reset": True, **audit}


@router.delete("/agents/{spiffe_id:path}")
async def deregister_agent(
    spiffe_id: str, request: Request, user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Admin removal of a decommissioned agent identity from the registry. The background pruner ages
    stale agents out after agent_registry_retention_days; this is the immediate manual path (without it a
    decommissioned agent lingers and surfaces as a phantom 'awaiting' node on the asset graph).

    What it removes: the agent_registry row and the agent's asset-graph node. What it keeps: policies,
    audit_log, and the agent's behavioural history (1 h window) and learned profile (7 d) in Redis — an
    identity that calls again is re-registered on its next evaluated call and is scored on that record.
    Clearing that record is its own audited action, POST .../trust/reset (reset_agent_trust_history).

    Refused with 409 while the agent is FROZEN or under a trust CAP. The registry row is the durable copy
    of both, so deleting it used to lift them as a side effect, with a log line that did not say so: the
    identity came back unfrozen on its next call or the next Redis restart. Lift the control first with
    PUT .../trust (score 1.0), which is logged with its actor, then deregister. The check and the delete run
    under the per-agent lock PUT .../trust takes (_lock_agent), and the delete is itself conditional on
    the row carrying neither control, so a freeze cannot commit between them."""
    require_admin(user)
    _require_agent_id(spiffe_id)
    from norviq.api.db.models import AgentRegistryEntry

    try:
        await _lock_agent(session, spiffe_id)
        row = (
            await session.execute(select(AgentRegistryEntry).where(AgentRegistryEntry.spiffe_id == spiffe_id))
        ).scalar_one_or_none()
        if row is None:
            await _rollback(session)
            raise HTTPException(status_code=404, detail="Agent not found in registry")
        ns = row.namespace
        # The live keys as well as the row: a freeze set before the registry carried it durably exists only
        # in Redis. A Redis that cannot answer is a refusal too — fail closed rather than delete what may be
        # the last record of a freeze.
        live_frozen, live_cap = await _live_control(request.app.state.cache, spiffe_id)
        frozen = bool(row.frozen) or live_frozen
        capped = row.trust_cap is not None or live_cap is not None
        deleted = 0
        if not (frozen or capped):
            result = await session.execute(
                text("DELETE FROM agent_registry WHERE spiffe_id = :s AND frozen = false AND trust_cap IS NULL"),
                {"s": spiffe_id},
            )
            deleted = result.rowcount or 0
            # rowcount 0 here means the row gained a control after it was read — refused, like any other.
            frozen = frozen or not deleted
        if not deleted:
            await _rollback(session)
            log.info("nrvq.api.agent.deregister_refused", spiffe_id=spiffe_id, frozen=frozen, capped=capped,
                     actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7143")
            control = "frozen" if frozen else "under a trust cap"
            raise HTTPException(
                status_code=409,
                detail=(f"Agent is {control}. Deleting it would lift that control. Lift it first "
                        f"(PUT /api/v1/agents/{{id}}/trust with score 1.0), then delete."),
            )
        await session.commit()
    except HTTPException:
        raise
    except _LockContended:
        await _rollback(session)
        log.warning("nrvq.api.agent.trust_write_contended", spiffe_id=spiffe_id, op="delete",
                    actor=user.get("sub"), code="NRVQ-API-7149")
        raise HTTPException(status_code=503, detail=(
            "Another admin change to this agent is in progress; nothing was deleted. Retry.")) from None
    except Exception as exc:  # noqa: BLE001 - see above
        await _rollback(session)
        log.warning("nrvq.api.agent.deregister_check_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    actor=user.get("sub"), code="NRVQ-API-7144")
        raise HTTPException(status_code=503, detail="Could not confirm the agent is not frozen; not deleted") from exc
    # ALSO prune the asset-graph node. Deleting the registry row alone only removes agents the graph
    # was rendering from the registry — the never-observed "awaiting" ones. An agent that actually ran
    # has its node baked into the persisted asset_graph snapshot, so it survived this call and stayed
    # on the console while the response still said {"deleted": true}. That is the case that matters:
    # an agent worth decommissioning is usually one that ran. See norviq/api/graph_maintenance.py.
    graph_node_removed = await try_remove_graph_node(request, ns, spiffe_id)
    # No Redis cleanup any more: it deleted the agent_frozen:/agent_trust_override: keys, i.e. the live
    # freeze. Past the check above neither key exists, and history/profile are deliberately kept.
    log.info("nrvq.api.agent.deregistered", spiffe_id=spiffe_id, namespace=ns,
             graph_node_removed=graph_node_removed, frozen=False, capped=False, actor=user.get("sub"),
             actor_role=user.get("role"), code="NRVQ-API-7121")
    # Report the graph outcome rather than folding it into `deleted`. False is legitimate — the agent
    # may never have been observed, so it had no snapshot node — but it also covers a prune that
    # failed, and a caller that cannot tell the two apart is back to guessing whether the console will
    # still show the agent.
    return {"deleted": True, "spiffe_id": spiffe_id, "namespace": ns,
            "graph_node_removed": graph_node_removed}


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
