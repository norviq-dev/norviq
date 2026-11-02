# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent trust score routes."""

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
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
from norviq.config import settings
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


# The agent ids the product itself accepts: POST /keys mints any spiffe_id up to 512 characters (keys.py) and
# the evaluator requires only the "spiffe://" prefix (Evaluator._validate_spiffe), so an operator-chosen id
# such as "spiffe://acme-agent", ".../sa/agent:v2" or one with a space or "*" in it is registered, enforced
# and listed — and must stay freezable. These routes refuse exactly what that rule refuses, plus an id that
# is empty after the prefix. The id only ever names Redis keys used with GET/SET/DEL/EVAL, never a SCAN or
# KEYS pattern, so glob characters in it are inert. 512 is also the registry column's width.
def _require_agent_id(spiffe_id: str) -> None:
    """422 unless ``spiffe_id`` is an agent id the key API mints and the evaluator enforces."""
    if not spiffe_id.startswith("spiffe://") or not spiffe_id[len("spiffe://"):].strip() or len(spiffe_id) > 512:
        raise HTTPException(status_code=422, detail="Not a valid agent id (spiffe://..., at most 512 characters)")


# The bound on every store (Redis) call made while an agent's lock is held. A store that hangs rather than
# refuses used to keep the lock and a DB connection ~20 s per request (redis-py's socket timeout, retried),
# and 20 concurrent admin writes exhausted the DB pool. A timeout is a store failure.
_STORE_TIMEOUT_S = 2.0
# Agents per transaction in the boot warm; see warm_agent_overrides for the measured figures.
_WARM_BATCH = 500


def _lock_timeout_ms() -> int:
    """How long an admin trust write waits for another one on the same agent: 3 s, or db_command_timeout − 2 s
    when that is smaller (never under 0.2 s), so a contended lock is told apart from a database that does not
    answer (which would take the outage path). At the default db_command_timeout of 5 s: 3 s."""
    return int(min(3.0, max(0.2, float(settings.db_command_timeout) - 2.0)) * 1000)


class _LockContended(Exception):
    """Another admin trust write holds this agent's lock for longer than _lock_timeout_ms()."""


class _AdminDbUnavailable(Exception):
    """No connection, no lock (other than contention) or no read: the registry cannot be used."""


class _PoolExhausted(_AdminDbUnavailable):
    """This process' DB connection pool had no connection free within its pool timeout."""


def _is_lock_timeout(exc: BaseException) -> bool:
    """True for Postgres' lock_timeout (SQLSTATE 55P03), however SQLAlchemy and asyncpg wrap it."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if getattr(exc, "sqlstate", None) == "55P03" or getattr(exc, "pgcode", None) == "55P03":
            return True
        exc = getattr(exc, "orig", None) or exc.__cause__
    return False


class _EngineConnector:
    """Opens the dedicated connection one admin trust write holds its agent's lock on."""

    async def connect(self):
        from norviq.api.db import session as db

        if db._engine is None:
            raise RuntimeError("Database not initialized. Call init_db() first.")
        return await db._engine.connect()


def get_admin_db() -> _EngineConnector:
    """Dependency (overridable in tests): where admin trust writes get their own connection."""
    return _EngineConnector()


async def _quietly(awaitable) -> None:
    try:
        await awaitable
    except Exception:  # noqa: BLE001 - cleanup on a connection being abandoned; the original error is reported
        pass


def _lock_key(spiffe_id: str) -> dict:
    return {"k": f"agent_trust:{spiffe_id}"}


# In-process gate in front of the Postgres lock: one waiter per agent per process holds a pool connection,
# the rest wait here without one. A burst on one agent while the store hangs used to park every request on
# pg_advisory_lock with a pooled connection each and exhaust the pool. Entries are dropped when unused.
_local_gates: dict[str, list] = {}


@asynccontextmanager
async def _local_gate(spiffe_id: str):
    entry = _local_gates.setdefault(spiffe_id, [asyncio.Lock(), 0])
    entry[1] += 1
    try:
        try:
            await asyncio.wait_for(entry[0].acquire(), _lock_timeout_ms() / 1000)
        except TimeoutError:
            raise _LockContended(spiffe_id) from None
        try:
            yield
        finally:
            entry[0].release()
    finally:
        entry[1] -= 1
        if entry[1] == 0 and _local_gates.get(spiffe_id) is entry:
            del _local_gates[spiffe_id]


@asynccontextmanager
async def _agent_lock(db, spiffe_id: str):
    """Serialize every admin trust write for one agent — PUT .../trust in all directions, DELETE, the reset —
    and the boot warm, across API replicas, for the WHOLE operation including its store write.

    A SESSION-level advisory lock on a connection of its own, so it outlives the registry commit: the
    ordering in update_trust (a loosening reaches the store only after its commit) needs the lock held across
    both. It is released with pg_advisory_unlock. If that does not answer true — or if the lock statement was
    sent and anything after it failed or was cancelled, so the lock may be held — the connection is
    invalidated: the backend ends and Postgres drops the lock. A connection that may hold an agent's lock is
    never handed back to the pool, where it would block that agent's next admin write. The boot warm takes
    the same keys as transaction-level locks, which conflict with these.

    Raises _LockContended after _lock_timeout_ms() (in-process or in Postgres); _PoolExhausted when no pooled
    connection is free; _AdminDbUnavailable for any other failure to connect or lock. Exceptions from the
    body pass through unchanged."""
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    async with _local_gate(spiffe_id):
        try:
            conn = await db.connect()
        except PoolTimeout as exc:
            raise _PoolExhausted(spiffe_id) from exc
        except Exception as exc:
            raise _AdminDbUnavailable(spiffe_id) from exc
        state = "none"  # none -> maybe (lock statement sent) -> held (granted and committed)
        try:
            try:
                await conn.execute(text(f"SET LOCAL lock_timeout = '{_lock_timeout_ms()}ms'"))
                state = "maybe"
                await conn.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), _lock_key(spiffe_id))
                await conn.commit()
                state = "held"
            except Exception as exc:
                if _is_lock_timeout(exc):
                    state = "none"  # Postgres refused the lock: nothing is held
                    await _quietly(conn.rollback())
                    raise _LockContended(spiffe_id) from exc
                raise _AdminDbUnavailable(spiffe_id) from exc
            yield conn
        finally:
            if state == "held":
                await _release_agent_lock(conn, spiffe_id)
            elif state == "maybe":
                await _quietly(conn.invalidate())
            await _quietly(conn.close())


async def _release_agent_lock(conn, spiffe_id: str) -> None:
    released = False
    try:
        await conn.rollback()  # a transaction the body left open (or failed) must not outlive the request
        released = bool((await conn.execute(
            text("SELECT pg_advisory_unlock(hashtext(:k))"), _lock_key(spiffe_id))).scalar())
        await conn.commit()
    except BaseException as exc:  # noqa: BLE001 - handled below: the connection is in doubt (incl. cancellation)
        log.warning("nrvq.api.agent.trust_lock_release_failed", spiffe_id=spiffe_id,
                    error=f"{type(exc).__name__}: {exc}", code="NRVQ-API-7150")
    if not released:
        await _quietly(conn.invalidate())


async def _store(awaitable):
    """One store call made under an agent's lock, bounded by _STORE_TIMEOUT_S. A call cut off here may still
    land later; every admin trust store write is fenced (agent_trust_owner:<id>), so a late one is a no-op
    once another writer has claimed the agent."""
    return await asyncio.wait_for(awaitable, _STORE_TIMEOUT_S)


async def _live_control(cache, spiffe_id: str) -> tuple[bool, float | None]:
    """The admin freeze/cap as Redis holds it now (what the trust calculator enforces)."""
    frozen = await _store(cache._client().get(f"agent_frozen:{spiffe_id}"))
    cap = await _store(cache._client().get(f"agent_trust_override:{spiffe_id}"))
    return bool(frozen), (float(cap) if cap is not None else None)


async def _registry_control(conn, spiffe_id: str) -> tuple[bool, float | None] | None:
    """The agent's durable freeze/cap, or None when it has no registry row."""
    row = (await conn.execute(
        text("SELECT frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"), {"s": spiffe_id}
    )).mappings().first()
    return None if row is None else (bool(row["frozen"]), row["trust_cap"])


def _is_tightening(prior: tuple[bool, float | None], new: tuple[bool, float | None]) -> bool:
    """True when ``new`` is at least as strict as ``prior`` in every dimension: a freeze is the strictest
    state; otherwise no freeze may be lifted and the cap may only be added, kept or lowered. Equal counts
    as tightening, so re-sending the current state rewrites the store first."""
    (prior_frozen, prior_cap), (new_frozen, new_cap) = prior, new
    if new_frozen:
        return True
    if prior_frozen:
        return False
    if new_cap is None:
        return prior_cap is None
    return prior_cap is None or new_cap <= prior_cap


async def _fenced_write(cache, spiffe_id, token, frozen, cap, display) -> tuple[int | None, str]:
    """Claim the agent for ``token`` and write the state through the fence. (outcome, error text)."""
    from norviq.engine.cache import RedisCache

    try:
        await _store(cache.claim_admin_trust_owner(spiffe_id, token))
        outcome = await _store(cache.apply_admin_trust_control_if_owner(
            spiffe_id, token, frozen=frozen, cap=cap, display=display))
    except Exception as exc:  # noqa: BLE001 - the caller reports it
        return None, f"{type(exc).__name__}: {exc}"
    errors = {RedisCache.FENCE_LOST: "fence: another admin write owns the agent",
              RedisCache.FENCE_MISSING: "fence: the owner key is gone (store flushed or evicted)"}
    return outcome, errors.get(outcome, "")


@router.put("/agents/{spiffe_id:path}/trust")
async def update_trust(
    spiffe_id: str, body: TrustUpdate, request: Request, user: dict = Depends(get_current_user),
    db=Depends(get_admin_db),
    _target: None = Depends(require_target_cluster)
) -> dict:
    """Set an agent trust score manually.

    The score is a DURABLE, ENFORCED control. Full-state semantics, mutually exclusive:
      score == 0    → FREEZE (block every call) + clear any cap.
      0 < score < 1 → a tighten-only trust CAP: the engine uses min(computed, score), so this can force a
                      misbehaving agent toward escalate/frozen but never RAISE trust above what behavior earns.
      score == 1.0  → CLEAR both the freeze and the cap (back to purely behavioral trust).

    200 means the registry row and the store both hold the new state. The whole write runs under one
    per-agent lock (_agent_lock); every store write is fenced on agent_trust_owner:<id>, claimed under the
    lock, so a write that outlives its lock is a no-op. The ORDER depends on the direction against the
    registry state read under the lock:
      TIGHTENING (freeze added, cap added or lowered, or no change): the store first, then the registry. A
        failed or unacknowledged commit leaves the store stricter-or-equal: 503 "applied live, may not be
        persisted". If the store cannot be written the registry still commits and the store stays at the
        previous, LOOSER state: 503 "persisted, NOT live" (7147) — the one case where the store is looser
        than the registry; it ends at the next successful write for the agent or the next API start.
      LOOSENING (a freeze lifted, a cap raised or removed): the registry first; the store only after a
        successful commit. A failed commit: the store is untouched and still stricter, 503 "not applied". A
        store failure or a lost fence after the commit: 503 saying the store still enforces the previous,
        stricter state (or, if the fence key vanished in a flush, that the store's state is unknown) (7147).
    Contention past the lock timeout, or no database: nothing is applied — except a freeze, which is the
    kill switch: it STEALS the fence (claims the owner key without the lock) and is written live, so a
    stranded lock holder's later fenced write becomes a no-op; 503 "freeze applied live, NOT persisted".
    An identity with no registry row gets one carrying the freeze or cap: the evaluator's first-call upsert
    (``upsert_agent_registry``) does not touch ``frozen``/``trust_cap``."""
    require_admin(user)
    _require_agent_id(spiffe_id)
    cache = request.app.state.cache
    frozen = body.score == 0
    cap = body.score if (0 < body.score < 1.0) else None
    display = TrustScore(score=body.score, category="frozen" if frozen else "")
    try:
        async with _agent_lock(db, spiffe_id) as conn:
            try:
                prior = await _registry_control(conn, spiffe_id) or (False, None)
            except Exception as exc:
                raise _AdminDbUnavailable(spiffe_id) from exc
            if _is_tightening(prior, (frozen, cap)):
                await _tighten(conn, cache, spiffe_id, frozen, cap, display, body.score, user)
            else:
                await _loosen(conn, cache, spiffe_id, frozen, cap, display, body.score, user)
    except (_LockContended, _AdminDbUnavailable) as exc:
        contended = isinstance(exc, _LockContended)
        live = False
        if frozen:
            outcome, _ = await _fenced_write(cache, spiffe_id, uuid.uuid4().hex, True, None, display)
            live = outcome == 1
        if contended:
            log.warning("nrvq.api.agent.trust_write_contended", spiffe_id=spiffe_id, score=body.score, live=live,
                        actor=user.get("sub"), code="NRVQ-API-7149")
            reason = "another admin change to this agent is in progress"
        else:
            log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id,
                        error=str(exc.__cause__ or exc), live=live, pool=isinstance(exc, _PoolExhausted),
                        actor=user.get("sub"), code="NRVQ-API-7033")
            reason = ("the API's database connection pool is exhausted" if isinstance(exc, _PoolExhausted)
                      else "the registry could not be reached")
        if live:
            detail = f"Freeze applied live but NOT persisted ({reason}); it is lost on a store flush or restart. Retry."
        else:
            detail = f"Trust change not applied: {reason}. Retry."
        raise HTTPException(status_code=503, detail=detail) from None if contended else exc
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, frozen=frozen, cap=cap,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": display.score, "category": display.category.lower()}


async def _tighten(conn, cache, spiffe_id, frozen, cap, display, score, user) -> None:
    """Store first, then registry. Every failure leaves the store stricter than or equal to Postgres, except a
    store that did not take the write — then Postgres holds the stricter state and the 503 says 'NOT live'."""
    outcome, store_error = await _fenced_write(cache, spiffe_id, uuid.uuid4().hex, frozen, cap, display)
    live = outcome == 1
    try:
        await _persist_trust_control(conn, spiffe_id, frozen, cap, score)
        await conn.commit()
    except Exception as exc:  # noqa: BLE001 - a failed commit or a lost acknowledgement: unknown which
        await _quietly(conn.rollback())
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    direction="tightening", live=live, actor=user.get("sub"), code="NRVQ-API-7033")
        raise HTTPException(status_code=503, detail=(
            "Applied live, but it may NOT be persisted (the registry write failed or its result was lost). Retry."
            if live else "Not confirmed: the change may be persisted (the registry did not confirm it), and the "
                         "store did not take it, so it is NOT live. Retry.")) from exc
    if not live:
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=store_error, score=score,
                    direction="tightening", durable=True, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Persisted but NOT live: the store did not take it. It is applied by the next successful change to "
            "this agent or the next API start; retry now."))


async def _loosen(conn, cache, spiffe_id, frozen, cap, display, score, user) -> None:
    """Registry first; the store only after a successful commit, and only while this request still owns
    the agent. Every failure leaves the store enforcing the previous, stricter state (or, after a flush, an
    unknown one — said so)."""
    from norviq.engine.cache import RedisCache

    token = uuid.uuid4().hex
    try:
        await _store(cache.claim_admin_trust_owner(spiffe_id, token))
    except Exception as exc:  # noqa: BLE001 - without the fence the store write could not be made safely
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    score=score, direction="loosening", durable=False, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Trust change not applied: the store did not answer. Retry.")) from exc
    try:
        await _persist_trust_control(conn, spiffe_id, frozen, cap, score)
        await conn.commit()
    except Exception as exc:  # noqa: BLE001 - the store is untouched, so it still holds the stricter state
        await _quietly(conn.rollback())
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    direction="loosening", live=False, actor=user.get("sub"), code="NRVQ-API-7033")
        raise HTTPException(status_code=503, detail=(
            "Trust change not applied. If the registry write did land, the store still enforces the previous, "
            "stricter state. Retry.")) from exc
    try:
        outcome = await _store(cache.apply_admin_trust_control_if_owner(
            spiffe_id, token, frozen=frozen, cap=cap, display=display))
        error = {RedisCache.FENCE_LOST: "fence: another admin write owns the agent",
                 RedisCache.FENCE_MISSING: "fence: the owner key is gone (store flushed or evicted)"}.get(outcome, "")
    except Exception as exc:  # noqa: BLE001 - reported below
        outcome, error = None, f"{type(exc).__name__}: {exc}"
    if outcome != RedisCache.FENCE_APPLIED:
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=error, score=score,
                    direction="loosening", durable=True, actor=user.get("sub"), code="NRVQ-API-7147")
        if outcome == RedisCache.FENCE_MISSING:
            raise HTTPException(status_code=503, detail=(
                "Persisted, but the store's state for this agent is unknown: its keys were lost (a flush or an "
                "eviction), possibly with the previous freeze or cap. The next API start writes the registry's "
                "state back; retry now."))
        raise HTTPException(status_code=503, detail=(
            "Persisted, but the store still enforces the previous, stricter state until the change is retried."))


async def _persist_trust_control(conn, spiffe_id: str, frozen: bool, cap: float | None, score: float) -> None:
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
            id=uuid.uuid4(),
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
        await conn.execute(stmt)
    else:
        await conn.execute(
            text("UPDATE agent_registry SET frozen = false, trust_cap = NULL WHERE spiffe_id = :s"),
            {"s": spiffe_id},
        )


async def _rollback(session) -> None:
    await _quietly(session.rollback())


async def warm_agent_overrides(cache, session_factory=get_session, progress: dict | None = None,
                               batch_size: int | None = None) -> int:
    """SECURITY (fail-open fix): at startup, re-seed durable admin freeze/cap from agent_registry into Redis so
    a store that lost the agent_frozen:/override keys before this process started does not leave a killed or
    capped agent running unpoliced. Runs only at process start: a loss while the API runs is not repaired
    until an API process starts again. Adds what Postgres holds and deletes nothing. Returns the count
    seeded.

    RAISES on any failure. It used to catch its own error, log a WARNING and return the count reached (0 when
    the query failed), which reads exactly like "nothing is frozen" while every freeze stayed absent until
    the next restart. The SETs are idempotent, so the caller can simply run it again.

    Batched, in spiffe_id order, under the admin lock. Each batch is one transaction: take every agent's lock
    key (the one _agent_lock takes session-level; these transaction-level requests conflict with it, so an
    admin write holding an agent until after its store write blocks the warm for that agent) in hashtext
    order, re-read the batch's rows, claim each agent's store fence and add its freeze or cap through it
    (RedisCache.warm_admin_trust_controls), commit. A cut-off attempt's late writes are then no-ops. Locked
    and re-read, an admin write on another replica lands wholly before the read or wholly after the write, so
    a stale snapshot can no longer put back a looser cap or a lifted freeze. Taking many locks cannot
    deadlock with an admin write, which holds exactly one; two warms take theirs in the same (lock-key)
    order. `progress` carries the last committed spiffe_id across the caller's retries, so a retry resumes
    where the previous attempt was cut off instead of re-warming the same head of the table.
    Measured on loopback (Postgres 5433, Redis 6379), batches of 500: 5 000 frozen or capped agents in 0.3 s and
    20 000 in 1.0-1.1 s, against the 10 s attempt bound; with the bound forced down to 0.45 s, 20 000 still
    completed on the third attempt because each retry resumed. One transaction per agent took 16.9 s for
    5 000 and never finished past ~2.8k at startup. Each batch costs about four database round trips, so the
    time grows with the round-trip time to Postgres: at 5 ms RTT, 20 000 agents add roughly 0.8 s. The
    resumable cursor, not the batch size, is what keeps a slow link from losing the tail."""
    batch_size = batch_size or _WARM_BATCH
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
            # Fenced like every admin trust write: the batch claims its agents, then adds through the fence. An
            # attempt cut off by warm_with_backoff's bound may still land its pipeline later; by then any admin
            # write has re-claimed the agent, so the late write is a no-op instead of a stale value.
            entries = [(r["spiffe_id"], bool(r["frozen"]), r["trust_cap"]) for r in rows
                       if r["frozen"] or r["trust_cap"] is not None]
            seeded = 0
            if entries:
                outcomes = await cache.warm_admin_trust_controls(uuid.uuid4().hex, entries)
                seeded = sum(1 for o in outcomes if o == 1)
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
    db=Depends(get_admin_db),
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
    from norviq.engine.trust.history import AgentHistoryStore
    from norviq.engine.trust.profile import AgentProfileStore

    cache = request.app.state.cache
    history_key = AgentHistoryStore(cache)._key(spiffe_id)
    profile_key = AgentProfileStore(cache)._key(spiffe_id)
    stage = "lock"
    try:
        async with _agent_lock(db, spiffe_id) as conn:
            stage = "read"
            row = (await conn.execute(
                text("SELECT trust_score, violation_count, frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"),
                {"s": spiffe_id},
            )).mappings().first()
            reg = None if row is None else SimpleNamespace(**row)
            trust = await _store(cache.get_trust(spiffe_id))
            stage = "multi"
            history, has_history, has_profile = await _store(_reset_multi(cache, history_key, profile_key))
    except Exception as exc:  # noqa: BLE001 - nothing is reported as cleared unless the MULTI answered
        contended = isinstance(exc, _LockContended)
        log.warning("nrvq.api.agent.trust_reset_failed", spiffe_id=spiffe_id,
                    error=f"{type(exc.__cause__ or exc).__name__}: {exc.__cause__ or exc}",
                    contended=contended, stage=stage, actor=user.get("sub"), code="NRVQ-API-7146")
        if contended:
            detail = "Another admin change to this agent is in progress; nothing was cleared. Retry."
        elif stage == "multi":
            detail = ("Trust history reset not confirmed: the store did not answer, so it may or may not "
                      "have cleared the history. Retry.")
        else:
            detail = "Trust history reset failed before anything was cleared. Retry."
        raise HTTPException(status_code=503, detail=detail) from exc
    # The MULTI answered: the record is gone, so from here on the audit line is written whatever else
    # happens. Nothing after the MULTI can raise into the except above — releasing the lock never raises
    # (_release_agent_lock invalidates the connection instead) — so the first version's 503 "nothing was
    # cleared" after a failure to end its transaction cannot recur.
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
    db=Depends(get_admin_db),
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
    under the per-agent lock PUT .../trust takes (_agent_lock), and the delete is itself conditional on
    the row carrying neither control, so a freeze cannot commit between them."""
    require_admin(user)
    _require_agent_id(spiffe_id)
    committing = False
    try:
        async with _agent_lock(db, spiffe_id) as conn:
            row = (await conn.execute(
                text("SELECT namespace, frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"), {"s": spiffe_id}
            )).mappings().first()
            if row is None:
                raise HTTPException(status_code=404, detail="Agent not found in registry")
            ns = row["namespace"]
            # The live keys as well as the row: a freeze set before the registry carried it durably exists
            # only in Redis. A Redis that cannot answer is a refusal too — fail closed rather than delete what
            # may be the last record of a freeze.
            live_frozen, live_cap = await _live_control(request.app.state.cache, spiffe_id)
            frozen = bool(row["frozen"]) or live_frozen
            capped = row["trust_cap"] is not None or live_cap is not None
            deleted = 0
            if not (frozen or capped):
                result = await conn.execute(
                    text("DELETE FROM agent_registry WHERE spiffe_id = :s AND frozen = false AND trust_cap IS NULL"),
                    {"s": spiffe_id},
                )
                deleted = result.rowcount or 0
                # rowcount 0 here means the row gained a control after it was read — refused, like any other.
                frozen = frozen or not deleted
            if not deleted:
                log.info("nrvq.api.agent.deregister_refused", spiffe_id=spiffe_id, frozen=frozen, capped=capped,
                         actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7143")
                control = "frozen" if frozen else "under a trust cap"
                raise HTTPException(
                    status_code=409,
                    detail=(f"Agent is {control}. Deleting it would lift that control. Lift it first "
                            f"(PUT /api/v1/agents/{{id}}/trust with score 1.0), then delete."),
                )
            committing = True
            await conn.commit()
    except HTTPException:
        raise
    except _LockContended:
        log.warning("nrvq.api.agent.trust_write_contended", spiffe_id=spiffe_id, op="delete",
                    actor=user.get("sub"), code="NRVQ-API-7149")
        raise HTTPException(status_code=503, detail=(
            "Another admin change to this agent is in progress; nothing was deleted. Retry.")) from None
    except Exception as exc:  # noqa: BLE001 - see above
        cause = exc.__cause__ if isinstance(exc, _AdminDbUnavailable) and exc.__cause__ else exc
        log.warning("nrvq.api.agent.deregister_check_failed", spiffe_id=spiffe_id, committing=committing,
                    error=f"{type(cause).__name__}: {cause}", actor=user.get("sub"), code="NRVQ-API-7144")
        if committing:  # a failed commit or a lost acknowledgement: the row may be gone
            detail = ("Not confirmed: the agent may have been deleted (the registry did not confirm it). "
                      "Check with GET /api/v1/agents/{id}.")
        elif isinstance(exc, _PoolExhausted):
            detail = "Not deleted: the API's database connection pool is exhausted. Retry."
        else:
            detail = "Could not confirm the agent is not frozen; not deleted"
        raise HTTPException(status_code=503, detail=detail) from exc
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
