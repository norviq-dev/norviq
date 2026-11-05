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


# The agent ids the product accepts — one rule, norviq/engine/identity.py::is_controllable_spiffe_id, shared
# with POST /keys and the evaluator, so every identity that can get a decision can be frozen. Operator-chosen
# ids such as "spiffe://acme-agent", ".../sa/agent:v2" or ones with a space or "*" are accepted; the id only
# ever names Redis keys used with GET/SET/DEL/EVAL, never a SCAN or KEYS pattern, so glob characters are inert.
def _require_agent_id(spiffe_id: str) -> None:
    """422 unless ``spiffe_id`` is an agent id: the one rule the key API, the evaluator and these routes share."""
    from norviq.engine.identity import is_controllable_spiffe_id

    if not is_controllable_spiffe_id(spiffe_id):
        raise HTTPException(status_code=422, detail="Not a valid agent id (spiffe://..., at most 512 characters, valid UTF-8 without NUL)")


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

def _set_local_lock_timeout_sql(ms: int):
    """`SET LOCAL lock_timeout = '<ms>ms'` with the value BOUND: Postgres' SET takes no parameters, but
    set_config(..., is_local => true) is the same transaction-local setting and does."""
    return text("SELECT set_config('lock_timeout', :v, true)").bindparams(v=f"{int(ms)}ms")



def _owner_ttl_ms() -> int:
    """How long a writer's claim on agent_trust_owner:<id> lives: at least 30 s and longer than the worst case of
    one admin operation (lock wait, three database round trips at db_command_timeout, six store calls), so a
    live writer never finds its own fence expired. Also the admin connection's idle_session_timeout and
    idle_in_transaction_session_timeout (_admin_session_values): a backend whose API side vanished is ended
    after that long idle, in or out of a transaction, and its TCP keepalives (10 s + 3 x 5 s) catch a dead
    peer sooner when the socket is in use."""
    worst_s = _lock_timeout_ms() / 1000 + 3 * float(settings.db_command_timeout) + 6 * _STORE_TIMEOUT_S + 5
    return int(max(30.0, worst_s) * 1000)


class _LockContended(Exception):
    """Another admin trust write holds this agent's lock for longer than _lock_timeout_ms()."""


class _AdminDbUnavailable(Exception):
    """No connection, no lock (other than contention) or no read: the registry cannot be used."""

    def __init__(self, spiffe_id: str, stage: str = "registry") -> None:
        super().__init__(spiffe_id)
        self.stage = stage


class _PoolExhausted(_AdminDbUnavailable):
    """This process' DB connection pool had no connection free within its pool timeout."""


class _AdminBusy(_AdminDbUnavailable):
    """This process already has its share of admin trust writes holding connections (_admin_slots)."""


# Process-wide cap on admin trust writes holding a lock connection at once: half the pool. The per-agent gate
# does not bound writes to DIFFERENT agents, and each holds a pooled connection through its store calls; 60
# freezes on distinct agents during a store hang starved every other DB user for ~5 s (review round 5).
_slots: dict[int, asyncio.Semaphore] = {}


def _admin_slots() -> asyncio.Semaphore:
    loop_id = id(asyncio.get_running_loop())
    sem = _slots.get(loop_id)
    if sem is None:
        _slots.clear()  # one event loop per process in production; tests start a new one per test
        sem = _slots[loop_id] = asyncio.Semaphore(max(1, int(settings.pg_pool_size) // 2))
    return sem


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
    connection is free; _AdminBusy when this process already has half its pool in admin writes;
    _AdminDbUnavailable for any other failure to connect or lock. Exceptions from the body pass through."""
    # Order: the per-agent gate first, so writers queued behind one agent wait without a slot; then a slot;
    # then the connection and the Postgres lock.
    async with _local_gate(spiffe_id):
        slots = _admin_slots()
        try:
            await asyncio.wait_for(slots.acquire(), _lock_timeout_ms() / 1000)
        except TimeoutError:
            raise _AdminBusy(spiffe_id) from None
        try:
            async with _agent_lock_held(db, spiffe_id) as conn:
                yield conn
        finally:
            slots.release()


# Session settings on the admin connection for the duration of one operation. A backend whose API side vanished
# (partition, node loss) kept the agent's lock until TCP keepalive noticed — 7200 s by default. Postgres ends a
# session idle for longer than these, in or out of a transaction (review round 6: idle_session_timeout alone does
# not apply while a transaction is open, which is most of an operation), and the keepalives detect a dead peer
# in about 25 s even mid-statement. Each is put back to the server's value before the connection is pooled.
_ADMIN_SESSION_SETTINGS = ("idle_session_timeout", "idle_in_transaction_session_timeout",
                           "tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count")
# A connect that does not answer (a partitioned Postgres) used to wait for the driver's own timeout (60 s here)
# before a freeze fell back to being applied live; the CLI had given up by then.
_CONNECT_TIMEOUT_S = 3.0
# The same for statements once the lock is held: a Postgres that stops answering mid-request (a partition after
# the lock was granted) made the registry read wait for the driver's command timeout and the release's rollback
# another ~60 s, so a freeze reached the live path after ~67 s (review round 8). The request's own statements
# are bounded by _db_statement_timeout_s(), and releasing the lock by _RELEASE_TIMEOUT_S, after which the connection is
# invalidated (the backend then ends, and Postgres drops the lock, once it notices: the admin session's idle
# and keepalive settings).
_DB_STATEMENT_MIN_S = 3.0
_RELEASE_TIMEOUT_S = 2.0


def _db_statement_timeout_s() -> float:
    """The bound on one admin statement: the driver's own command timeout (db_command_timeout, 5 s by default),
    never under 3 s. Tied to the setting so an operator who raised it for a slow database is not told the
    registry is unreachable, and a read waiting a few seconds on a table lock still completes (review round 8)."""
    return max(_DB_STATEMENT_MIN_S, float(settings.db_command_timeout))


def _consume(task: asyncio.Task) -> None:
    if not task.cancelled():
        task.exception()  # retrieved, so an abandoned statement's error is not reported as unhandled


async def _db(awaitable):
    """One statement on the admin connection, bounded by _db_statement_timeout_s(). On timeout the statement is
    cancelled but NOT waited for: cancelling a query on a partitioned connection itself waited ~2 s (the
    driver's cancel request goes nowhere). The connection is then abandoned — the release finds it busy and
    invalidates it."""
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=_db_statement_timeout_s())
    except BaseException:
        task.cancel()
        task.add_done_callback(_consume)
        raise
    if task in done:
        return task.result()
    task.cancel()
    task.add_done_callback(_consume)
    raise AdminStatementTimeout(f"admin statement did not answer within {_db_statement_timeout_s():g}s")


class AdminStatementTimeout(TimeoutError):
    """An admin statement cut off by _db: its connection still has it in flight and is given up on."""


def _abandoned(exc: BaseException | None) -> bool:
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, AdminStatementTimeout):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def _admin_session_values() -> dict[str, str]:
    bound = f"{_owner_ttl_ms()}ms"
    return {"idle_session_timeout": bound, "idle_in_transaction_session_timeout": bound,
            "tcp_keepalives_idle": "10", "tcp_keepalives_interval": "5", "tcp_keepalives_count": "3"}


async def _apply_admin_session(conn) -> None:
    for name, value in _admin_session_values().items():
        await conn.execute(
            text("SELECT set_config(:n, :v, false) WHERE current_setting(:n, true) IS NOT NULL"), {"n": name, "v": value}
        )


async def _reset_admin_session(conn) -> None:
    await conn.execute(
        text("SELECT set_config(name, reset_val, false) FROM pg_settings WHERE name = ANY(:names)"),
        {"names": list(_ADMIN_SESSION_SETTINGS)},
    )


@asynccontextmanager
async def _agent_lock_held(db, spiffe_id: str):
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    try:
        conn = await asyncio.wait_for(db.connect(), _CONNECT_TIMEOUT_S)
    except PoolTimeout as exc:
        raise _PoolExhausted(spiffe_id) from exc
    except Exception as exc:
        raise _AdminDbUnavailable(spiffe_id) from exc
    # none -> configured (session settings changed) -> maybe (lock statement sent) -> held (granted, committed)
    state, abandoned = "none", False
    try:
        try:
            state = "configured"
            await _apply_admin_session(conn)
            await conn.execute(_set_local_lock_timeout_sql(_lock_timeout_ms()))
            state = "maybe"
            await conn.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), _lock_key(spiffe_id))
            await conn.commit()
            state = "held"
        except Exception as exc:
            if _is_lock_timeout(exc):
                state = "configured"  # Postgres refused the lock: nothing is held
                await _quietly(conn.rollback())
                raise _LockContended(spiffe_id) from exc
            raise _AdminDbUnavailable(spiffe_id) from exc
        try:
            yield conn
        except BaseException as exc:
            abandoned = _abandoned(exc)
            raise
    finally:
        if state == "held" and abandoned:
            # A statement is still in flight on it: a rollback would wait behind it. Give the connection up at
            # once; Postgres drops the lock with the backend (after the admin idle/keepalive bounds).
            # Invalidating closes it gracefully first (the driver waits up to 2 s for a partitioned peer), so it
            # is done in the background: the answer (a freeze applied live) must not wait for it.
            log.warning("nrvq.api.agent.trust_lock_release_failed", spiffe_id=spiffe_id,
                        error="statement abandoned: the connection is invalidated", code="NRVQ-API-7150")
            _in_background(_discard(conn))  # closes it too; no `return` here, which would swallow the error
        elif state == "held":
            await _release_agent_lock(conn, spiffe_id)
        elif state == "maybe":
            await _quietly(conn.invalidate())
        elif state == "configured":
            async def reset() -> None:
                await conn.rollback()
                await _reset_admin_session(conn)
                await conn.commit()

            try:
                await asyncio.wait_for(reset(), _RELEASE_TIMEOUT_S)
            except BaseException:  # noqa: BLE001 - a connection whose settings could not be put back is not pooled
                await _quietly(conn.invalidate())
        if not (state == "held" and abandoned):
            await _quietly(conn.close())


_background: set[asyncio.Task] = set()


def _in_background(coro) -> None:
    task = asyncio.ensure_future(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


async def _discard(conn) -> None:
    await _quietly(conn.invalidate())
    await _quietly(conn.close())


async def _release_agent_lock(conn, spiffe_id: str) -> None:
    async def release() -> bool:
        await conn.rollback()  # a transaction the body left open (or failed) must not outlive the request
        unlocked = bool((await conn.execute(
            text("SELECT pg_advisory_unlock(hashtext(:k))"), _lock_key(spiffe_id))).scalar())
        await _reset_admin_session(conn)
        await conn.commit()
        return unlocked

    released = False
    try:
        released = await asyncio.wait_for(release(), _RELEASE_TIMEOUT_S)
    except BaseException as exc:  # noqa: BLE001 - handled below: the connection is in doubt (incl. cancellation)
        released = False
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


async def _fence_token(conn) -> int:
    """A monotonic fence token, taken while holding the agent's lock: a later lock holder always gets a larger
    one, so a writer whose lock died cannot claim over it (RedisCache._CLAIM_LUA)."""
    return int((await _db(conn.execute(text("SELECT nextval('agent_trust_fence_seq')")))).scalar())


async def _fenced_write(cache, spiffe_id, frozen, cap, display, attempts: int = 2, conn=None,
                        token: int | None = None) -> tuple[int | None, str]:
    """Claim the agent with ``token`` (from _fence_token; None = steal, without the lock) and write the state
    through the fence; once more if the store failed or the owner key was gone, never over a newer claim.
    (outcome, error text). Only ever writes the state the caller is making (or, for a loosening, has
    committed)."""
    from norviq.engine.cache import RedisCache

    outcome, error = None, ""
    for _ in range(attempts):
        if conn is not None and not await _still_connected(conn):
            # The lock went with the connection (checked before the FIRST claim too: a backend killed after the
            # registry read). A claim already on the wire when the connection dies can still land; it carries
            # this writer's token, smaller than any later lock holder's, so it is refused once they claim.
            break
        try:
            claimed = await _store(cache.claim_admin_trust_owner(spiffe_id, token, _owner_ttl_ms()))
            if claimed is None:
                return RedisCache.FENCE_LOST, "fence: a newer admin write owns the agent"
            outcome = await _store(cache.apply_admin_trust_control_if_owner(
                spiffe_id, claimed, frozen=frozen, cap=cap, display=display))
        except Exception as exc:  # noqa: BLE001 - the caller reports it
            outcome, error = None, f"{type(exc).__name__}: {exc}"
            continue
        if outcome == RedisCache.FENCE_APPLIED:
            return outcome, ""
        error = {RedisCache.FENCE_LOST: "fence: another admin write owns the agent",
                 RedisCache.FENCE_MISSING: "fence: the owner key is gone (expired, or the store lost it)"}.get(outcome, "")
        if outcome == RedisCache.FENCE_LOST:
            # Someone claimed after us — a freeze stealing the fence, or a newer writer. Writing over it is
            # exactly what the fence is for not doing, so this write gives up and says it did not land.
            break
    return outcome, error


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
        successful commit, retried once under a fresh claim. A failed commit: the store is untouched, 503 "not
        confirmed". A store that still did not take it: 503 "persisted, the store did not confirm the update"
        — it holds whatever it held before this change, which is the previous, stricter state unless an
        earlier change was itself answered "NOT live" (7147).
    Contention past the lock timeout, no database, an exhausted pool or too many admin writes in this process:
    nothing is applied — except a freeze, the kill switch: it claims the fence without the lock and is written
    live (503 "freeze applied live, NOT persisted"). That stops any write claimed BEFORE it; a change already
    under way that claims after it (it claims once it has the lock and has read the registry) replaces it with
    the state that change commits, and answers for it.
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
                prior = await _db(_registry_control(conn, spiffe_id)) or (False, None)
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
            outcome, _ = await _fenced_write(cache, spiffe_id, True, None, display)
            live = outcome == 1
        if contended:
            log.warning("nrvq.api.agent.trust_write_contended", spiffe_id=spiffe_id, score=body.score, live=live,
                        actor=user.get("sub"), code="NRVQ-API-7149")
            reason = "another admin change to this agent is in progress"
        else:
            cause = exc.__cause__
            log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id,
                        error=f"{type(cause).__name__}: {cause}" if cause is not None else type(exc).__name__,
                        stage=("pool" if isinstance(exc, _PoolExhausted) else "admin_slots"
                               if isinstance(exc, _AdminBusy) else exc.stage),
                        live=live, pool=isinstance(exc, _PoolExhausted), actor=user.get("sub"),
                        code="NRVQ-API-7033")
            reason = ("the API's database connection pool is exhausted" if isinstance(exc, _PoolExhausted)
                      else "too many admin trust changes are in progress in this API process"
                      if isinstance(exc, _AdminBusy) else "the registry could not be reached or did not answer in time")
        if live:
            detail = (f"Freeze applied live but NOT persisted ({reason}). A change to this agent that was already "
                      "under way may replace it when it finishes, and a store flush or restart loses it. Check the "
                      "agent and retry.")
        else:
            detail = f"Trust change not applied: {reason}. Retry."
        raise HTTPException(status_code=503, detail=detail) from None if contended else exc
    log.info("nrvq.api.agent.trust_updated", spiffe_id=spiffe_id, score=body.score, frozen=frozen, cap=cap,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7031")
    return {"spiffe_id": spiffe_id, "score": display.score, "category": display.category.lower()}


async def _tighten(conn, cache, spiffe_id, frozen, cap, display, score, user) -> None:
    """Store first, then registry. Every failure leaves the store stricter than or equal to Postgres, except a
    store that did not take the write — then Postgres holds the stricter state and the 503 says 'NOT live'.

    A database that fails part-way never leaves a FREEZE un-applied (review round 8: Postgres stopping after the
    registry read failed the fence token, nothing was written, and the answer said 'may or may not be live'):
    without a fence token nothing has been written anywhere, so the change is treated like an unreachable
    registry (update_trust: a freeze steals the fence and is applied live); and a freeze whose store write did
    not land and whose registry write failed is applied live by stealing the fence before answering."""
    from norviq.engine.cache import RedisCache

    try:
        token = await _fence_token(conn)
    except Exception as exc:  # noqa: BLE001 - nothing written yet: the same as a registry that cannot be read
        raise _AdminDbUnavailable(spiffe_id, stage="fence_token") from exc
    outcome, store_error = await _fenced_write(cache, spiffe_id, frozen, cap, display, conn=conn, token=token)
    live = outcome == RedisCache.FENCE_APPLIED
    refused = outcome == RedisCache.FENCE_LOST  # the store answered, and a newer change owns the agent
    try:
        await _db(_persist_trust_control(conn, spiffe_id, frozen, cap, score))
        await _db(conn.commit())
    except Exception as exc:  # noqa: BLE001 - a failed commit or a lost acknowledgement: unknown which
        if frozen and not live:
            # The kill switch must not end un-applied: steal the fence, as a freeze without the lock does.
            stolen, _ = await _fenced_write(cache, spiffe_id, True, None, display)
            live = stolen == RedisCache.FENCE_APPLIED
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    direction="tightening", stage="persist", live=live, actor=user.get("sub"),
                    code="NRVQ-API-7033")
        raise HTTPException(status_code=503, detail=(
            "Applied live, but it may NOT be persisted (the registry write failed or its result was lost). Retry."
            if live else "Not confirmed: the change may be persisted (the registry did not confirm it), and the "
                         "store write was refused: a newer change owns the agent. Check the agent and retry."
            if refused
            else "Not confirmed: the change may be persisted (the registry did not confirm it), and the "
                 "store did not confirm it either, so it may or may not be live. Retry.")) from exc
    if not live:
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=store_error, score=score,
                    direction="tightening", durable=True, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Persisted but NOT live: the store write was refused, because a newer change owns the agent (a "
            "freeze applied while this change waited, or a later change). Check the agent; retry to apply this "
            "one." if refused
            else "Persisted but NOT confirmed live: the store did not confirm it (it may or may not have taken it). "
                 "It is applied by the next successful change to this agent or the next API start; retry now."))


async def _loosen(conn, cache, spiffe_id, frozen, cap, display, score, user) -> None:
    """Registry first; the store only after a successful commit, and only through the fence. On any failure the
    answer says what is known: the store was not updated by this change and holds whatever it held before it —
    the previous, stricter state, unless an earlier change was itself reported 'NOT live', in which case it is
    older and looser than the registry."""
    from norviq.engine.cache import RedisCache

    try:
        token = await _fence_token(conn)
    except Exception as exc:  # noqa: BLE001 - the database failed, not the store: nothing was applied
        await _quietly(conn.rollback())
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    direction="loosening", stage="fence_token", live=False, actor=user.get("sub"),
                    code="NRVQ-API-7033")
        raise HTTPException(status_code=503, detail=(
            "Trust change not applied: the registry could not be reached or did not answer in time. Retry.")) from exc
    try:
        claimed = await _store(cache.claim_admin_trust_owner(spiffe_id, token, _owner_ttl_ms()))
    except Exception as exc:  # noqa: BLE001 - without the fence the store write could not be made safely
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    score=score, direction="loosening", durable=False, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Trust change not applied: the store did not answer. Retry.")) from exc
    if claimed is None:
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id,
                    error="fence: a newer admin write owns the agent", score=score, direction="loosening",
                    durable=False, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Trust change not applied: refused, a newer change owns the agent (a freeze applied while this change "
            "waited, or a later change). Check the agent and retry."))
    try:
        await _db(_persist_trust_control(conn, spiffe_id, frozen, cap, score))
        await _db(conn.commit())
    except Exception as exc:  # noqa: BLE001 - the store is untouched by this change (the release rolls back)
        log.warning("nrvq.api.agent.trust_persist_failed", spiffe_id=spiffe_id, error=f"{type(exc).__name__}: {exc}",
                    direction="loosening", stage="persist", live=False, actor=user.get("sub"), code="NRVQ-API-7033")
        raise HTTPException(status_code=503, detail=(
            "Trust change not confirmed: the registry did not confirm it, and the store was not touched — it holds "
            "whatever it held before this change. Retry.")) from exc
    try:
        outcome = await _store(cache.apply_admin_trust_control_if_owner(
            spiffe_id, token, frozen=frozen, cap=cap, display=display))
        error = ""
    except Exception as exc:  # noqa: BLE001 - retried below
        outcome, error = None, f"{type(exc).__name__}: {exc}"
    if outcome == RedisCache.FENCE_LOST:
        error = "fence: a newer admin write owns the agent"
    if outcome not in (RedisCache.FENCE_APPLIED, RedisCache.FENCE_LOST) and await _still_connected(conn):
        # The change is committed and we still hold the lock (its connection answers): one more attempt to bring
        # the store to exactly the state the registry now holds, under a fresh claim. Not after FENCE_LOST — a
        # newer claim (a stolen freeze) must not be written over — and not once the connection is gone, because
        # the lock went with it and a claim now could land in the middle of another writer's change.
        outcome, error = await _fenced_write(cache, spiffe_id, frozen, cap, display, attempts=1, conn=conn, token=token)
    if outcome != RedisCache.FENCE_APPLIED:
        log.warning("nrvq.api.agent.trust_live_failed", spiffe_id=spiffe_id, error=error, score=score,
                    direction="loosening", durable=True, actor=user.get("sub"), code="NRVQ-API-7147")
        raise HTTPException(status_code=503, detail=(
            "Persisted, but NOT live: the store write was refused, because a newer change owns the agent (a "
            "freeze applied while this change ran, or a later change). Check the agent and retry."
            if outcome == RedisCache.FENCE_LOST
            else "Persisted, but the store did not confirm the update: it may have taken it, or it still holds "
                 "whatever it held before this change (if an earlier change was answered 'Persisted but NOT "
                 "confirmed live', that may be older than the registry). Retry, or restart the API to re-apply "
                 "the registry."))


async def _still_connected(conn) -> bool:
    """Whether the lock connection still answers, i.e. its session (and so its advisory lock) is alive."""
    try:
        await _db(conn.execute(text("SELECT 1")))  # inside whatever transaction is open; the caller ends it
        return True
    except Exception:  # noqa: BLE001 - any failure means the lock cannot be relied on
        return False


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
            # Truncated to the columns' width: an id whose ns or sa segment is longer would otherwise fail every
            # insert, and its freeze could never be persisted. The evaluator's own upsert sets them from the event.
            namespace=(_namespace_from_spiffe(spiffe_id) or "default")[:255],
            agent_class=(_class_from_spiffe(spiffe_id) or "")[:255],
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


# The skipped-agent retry: per-agent lock wait and total time, well inside warm_with_backoff's 10 s attempt.
_WARM_RETRY_LOCK_MS = 300
_WARM_RETRY_BUDGET_S = 2.0


@asynccontextmanager
async def _warm_session(session_factory):
    """The boot warm's session. With the product's own session factory it runs on a connection configured exactly
    like the admin lock connection (_apply_admin_session: idle and idle-in-transaction timeouts, TCP keepalives),
    because a batch holds up to _WARM_BATCH agents' locks: a replica vanishing mid-warm otherwise kept them for
    TCP keepalive time (review round 7). The settings are put back before the connection is pooled; a connection
    that cannot be reset is invalidated. Any other factory (tests) is used as is."""
    if session_factory is not get_session:
        provider = session_factory()
        session = await provider.__anext__()
        try:
            yield session
        finally:
            await _rollback(session)
            await provider.aclose()
        return
    from sqlalchemy.ext.asyncio import AsyncSession

    conn = await asyncio.wait_for(_EngineConnector().connect(), _CONNECT_TIMEOUT_S)
    try:
        await _apply_admin_session(conn)
        await conn.commit()
        session = AsyncSession(bind=conn, expire_on_commit=False)
        try:
            yield session
        finally:
            await _rollback(session)
            await _quietly(session.close())
    finally:
        try:
            await conn.rollback()
            await _reset_admin_session(conn)
            await conn.commit()
        except BaseException:  # noqa: BLE001 - a connection whose settings could not be put back is not pooled
            await _quietly(conn.invalidate())
        await _quietly(conn.close())


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

    Batched, in spiffe_id order, under the admin lock. Each batch is one transaction: take every agent's lock key
    (the one _agent_lock takes session-level; these transaction-level requests conflict with it, so an admin
    write holding an agent until after its store write keeps the warm off that agent), re-read the locked rows,
    claim each agent's store fence and add its freeze or cap through it (RedisCache.warm_admin_trust_controls),
    commit. A cut-off attempt's late writes are then no-ops. Locked and re-read, an admin write on another
    replica lands wholly before the read or wholly after the write, so a stale snapshot can no longer put back
    a looser cap or a lifted freeze. Batch locks are taken in lock-key order with a timeout, falling back to
    try-locks that skip a held agent, so a deadlock or one stuck agent cannot stall the warm. `progress` carries the
    last committed spiffe_id and the skipped agents across the caller's retries, so a retry resumes where the
    previous attempt stopped instead of re-warming the same head of the table.
    Measured with batches of 500 (round-5 review, TCP delay proxy in front of Postgres): 20 000 frozen or capped
    agents take 1.5-1.6 s on loopback, 5.5 s at ~10 ms round-trip time and 19 s at ~50 ms, against a 10 s attempt
    bound; three replicas warming the same 22 000 rows at once while admin writes run take about 4x one warm's
    time. Past roughly 80 ms RTT, or with several replicas starting together, 20 000 agents can exhaust the
    3 x 10 s budget: the tail then stays unwarmed and NRVQ-API-7035 is logged at ERROR. The resumable cursor
    keeps every attempt's progress; one transaction per agent took 16.9 s for 5 000 even on loopback.
    An agent whose lock is held, or whose fenced add does not land after re-claiming
    (RedisCache.warm_admin_trust_controls), is skipped, not counted, and retried after the rest; if it still
    cannot be written the attempt fails (NRVQ-API-7160 names it) and the caller's retry tries it again."""
    batch_size = batch_size or _WARM_BATCH
    progress = progress if progress is not None else {}
    progress.setdefault("after", "")
    progress.setdefault("seeded", 0)
    skipped: set[str] = progress.setdefault("skipped", set())
    async with _warm_session(session_factory) as session:
        while True:
            ids = [r["spiffe_id"] for r in (await session.execute(
                text("SELECT spiffe_id FROM agent_registry WHERE (frozen = true OR trust_cap IS NOT NULL) "
                     "AND spiffe_id > :after ORDER BY spiffe_id LIMIT :n"),
                {"after": progress["after"], "n": batch_size},
            )).mappings().all()]
            if not ids:
                break
            # Take the batch's locks, waiting at most the admin lock timeout, in lock-key order (two warms taking
            # overlapping batches then cannot deadlock; an admin write holds exactly one lock). If that times out,
            # some agent is held for long — a writer stuck on the store, or a backend whose API node vanished
            # mid-transaction — and used to fail this batch and, the cursor never moving past it, every batch
            # after it on every attempt. Then each agent's lock is TRIED instead: the held ones are skipped here
            # and retried once the rest is written.
            try:
                await session.execute(_set_local_lock_timeout_sql(_lock_timeout_ms()))
                await session.execute(
                    text("SELECT count(pg_advisory_xact_lock(k)) FROM (SELECT DISTINCT hashtext('agent_trust:' || i) "
                         "AS k FROM unnest(CAST(:ids AS text[])) AS i ORDER BY k) AS keys"),
                    {"ids": ids},
                )
                locked = ids
            except Exception as exc:
                await _rollback(session)
                if not _is_lock_timeout(exc):
                    raise
                got = (await session.execute(
                    text("SELECT i, pg_try_advisory_xact_lock(hashtext('agent_trust:' || i)) AS locked "
                         "FROM unnest(CAST(:ids AS text[])) AS i"),
                    {"ids": ids},
                )).mappings().all()
                locked = [r["i"] for r in got if r["locked"]]
                skipped.update(r["i"] for r in got if not r["locked"])
            seeded, missed = await _warm_locked(session, cache, locked)
            skipped.update(missed)
            await session.commit()
            progress["after"] = ids[-1]
            progress["seeded"] += seeded
        if skipped:
            # Named BEFORE the retry: the retry can be cut off by warm_with_backoff's bound, and the ids must be
            # in the log whatever happens next (review round 7: with 4+ held agents 7160 was never logged).
            names = sorted(skipped)
            log.error("nrvq.api.agent.overrides_warm_skipped", count=len(names), spiffe_ids=names[:10],
                      phase="retrying", code="NRVQ-API-7160")
        deadline = asyncio.get_running_loop().time() + _WARM_RETRY_BUDGET_S
        for spiffe_id in sorted(skipped):
            # One at a time, each waiting at most _WARM_RETRY_LOCK_MS for the agent's lock, all of them within
            # _WARM_RETRY_BUDGET_S, so even many held agents stay well inside the 10 s attempt bound.
            if asyncio.get_running_loop().time() >= deadline:
                break
            try:
                await session.execute(_set_local_lock_timeout_sql(_WARM_RETRY_LOCK_MS))
                await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), _lock_key(spiffe_id))
            except Exception as exc:
                await _rollback(session)
                if _is_lock_timeout(exc):
                    continue
                raise
            seeded, missed = await _warm_locked(session, cache, [spiffe_id])
            await session.commit()
            progress["seeded"] += seeded
            if not missed:
                skipped.discard(spiffe_id)
        if skipped:
            names = sorted(skipped)
            log.error("nrvq.api.agent.overrides_warm_skipped", count=len(names), spiffe_ids=names[:10],
                      phase="unwritten", code="NRVQ-API-7160")
            # The attempt fails, so warm_with_backoff retries — only these agents, the cursor is past the rest —
            # and logs NRVQ-API-7035 at ERROR with them if they never take their control.
            raise RuntimeError(f"{len(names)} frozen or capped agent(s) not written back (agent lock held, or the "
                               f"store fence would not take): {', '.join(names[:5])}{' ...' if len(names) > 5 else ''}")
        log.info("nrvq.api.agent.overrides_warmed", count=progress["seeded"], code="NRVQ-API-7034")
    return progress["seeded"]


async def _warm_locked(session, cache, ids: list[str]) -> tuple[int, list[str]]:
    """Re-read ``ids`` (whose locks this transaction holds) and add their freeze or cap through the store fence.
    Returns (agents written, agents whose fenced add did not land after re-claiming)."""
    if not ids:
        return 0, []
    rows = (await session.execute(
        text("SELECT spiffe_id, frozen, trust_cap FROM agent_registry WHERE spiffe_id = ANY(:ids)"),
        {"ids": ids},
    )).mappings().all()
    # Fenced like every admin trust write: the batch claims its agents, then adds through the fence. An attempt
    # cut off by warm_with_backoff's bound may still land its pipeline later; by then any admin write has
    # re-claimed the agent, so the late write is a no-op instead of a stale value.
    entries = [(r["spiffe_id"], bool(r["frozen"]), r["trust_cap"]) for r in rows
               if r["frozen"] or r["trust_cap"] is not None]
    if not entries:
        return 0, []
    token = int((await session.execute(text("SELECT nextval('agent_trust_fence_seq')"))).scalar())
    outcomes = await cache.warm_admin_trust_controls(token, entries)
    return (sum(1 for o in outcomes if o == 1), [e[0] for e, o in zip(entries, outcomes) if o != 1])


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
            row = (await _db(conn.execute(
                text("SELECT trust_score, violation_count, frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"),
                {"s": spiffe_id},
            ))).mappings().first()
            reg = None if row is None else SimpleNamespace(**row)
            trust = await _store(cache.get_trust(spiffe_id))
            stage = "multi"
            history, has_history, has_profile = await _store(_reset_multi(cache, history_key, profile_key))
    except Exception as exc:  # noqa: BLE001 - nothing is reported as cleared unless the MULTI answered
        contended = isinstance(exc, _LockContended)
        # The cause only for this module's own wrappers; a TimeoutError's cause is the CancelledError of the
        # statement it cut off, which would read as a cancelled request (review round 8).
        shown = exc.__cause__ if isinstance(exc, (_LockContended, _AdminDbUnavailable)) and exc.__cause__ else exc
        log.warning("nrvq.api.agent.trust_reset_failed", spiffe_id=spiffe_id,
                    error=f"{type(shown).__name__}: {shown}",
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
            row = (await _db(conn.execute(
                text("SELECT namespace, frozen, trust_cap FROM agent_registry WHERE spiffe_id = :s"), {"s": spiffe_id}
            ))).mappings().first()
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
            await _db(conn.commit())
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
