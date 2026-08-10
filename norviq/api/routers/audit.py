# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Audit query routes."""

import csv
import hashlib
import hmac
import io
import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, scoped_namespace
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.routers.system_health import infra_rule_for  # ONE resolver for 'is this an engine fault'
from norviq.api.synthetic import audit_row_is_non_real, is_synthetic_identity  # the ONE shared synthetic/probe classifier (do not fork)
from norviq.config import settings
from norviq.engine.evaluator import WOULD_BLOCK_RULE_PREFIXES  # softened-would-block rule_id prefixes (do not fork)


def _canonical(record: dict) -> str:
    """Deterministic JSON for hashing (sorted keys, tight separators)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _chain_hash(prev_hash: str, record: dict) -> str:
    """SHA-256 hash-chain link over the previous hash + this record's canonical form."""
    return hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest()

log = structlog.get_logger()
router = APIRouter()

# Bounded page size for streamed export so a large audit_log is never loaded into memory at once.
_EXPORT_PAGE = 500
_EXPORT_FIELDS = (
    "id", "event_id", "tool_name", "decision", "agent_id", "agent_class",
    "namespace", "rule_id", "reason", "session_id", "trust_score", "latency_ms", "timestamp",
)


def _since_for_range(range_value: Literal["1h", "6h", "24h", "7d", "30d"]) -> datetime:
    """Convert API range token to UTC datetime bound."""
    range_map = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
    return datetime.now(timezone.utc) - timedelta(hours=range_map.get(range_value, 24))


# Bucket WIDTH per range, in minutes. Volume was bucketed by hour for every range, so `1h` could only
# ever yield one or two points and `30d` yielded 720 — one axis granularity serving a 720x span. A single
# point is worse than coarse: a line has no segment to draw, so the chart rendered blank while its tooltip
# still reported numbers (see ui VolumeChart). Each entry below keeps a range at roughly 12-30 points.
_BUCKET_MINUTES: dict[str, int] = {"1h": 5, "6h": 15, "24h": 60, "7d": 360, "30d": 1440}


def _bucket_key(ts: datetime, minutes: int) -> str:
    """Floor `ts` to a `minutes`-wide bucket, formatted for the chart's category axis.

    Floors on absolute minutes-since-midnight so bucket edges are stable and aligned across rows
    (e.g. 15-minute buckets always land on :00/:15/:30/:45) rather than drifting with the first row seen.
    """
    floored = (ts.hour * 60 + ts.minute) // minutes * minutes
    return ts.replace(hour=floored // 60, minute=floored % 60, second=0, microsecond=0).strftime(
        "%Y-%m-%d %H:%M"
    )


def _to_dict(row: AuditLogEntry) -> dict:
    """Serialize audit row to API payload."""
    return {
        "id": str(row.id),
        "event_id": str(row.event_id),
        "tool_name": row.tool_name,
        "decision": row.decision,
        "agent_id": row.agent_id,
        "namespace": row.namespace,
        "rule_id": row.rule_id,
        "reason": row.reason,
        "agent_class": getattr(row, "agent_class", ""),
        "session_id": getattr(row, "session_id", ""),
        "trust_score": row.trust_score,
        "latency_ms": row.latency_ms,
        # Decision source (sidecar / sidecar-http / sdk / redteam / ...) for the UI Source column + filter.
        "framework": getattr(row, "framework", ""),
        "timestamp": row.timestamp_utc.isoformat(),
        # MCP provenance, when the decision came over the Model Context Protocol. Lifted out of the
        # JSONB payload so the console can show WHICH integration a decision belongs to without
        # fetching the full record — the first question anyone asks of a chatbot wired to four MCP
        # servers is "which one did this come from?". Absent (None) for every non-MCP row, so the
        # response shape is unchanged for existing consumers.
        "mcp": _mcp_context(row),
    }


def _mcp_context(row: AuditLogEntry) -> dict | None:
    """The `mcp` object the evaluate route stored on the audit payload, or None.

    `getattr`, not `row.payload`, and for the same reason every other optional field in `_to_dict`
    uses it: not all callers pass a full ORM row. The SIEM forwarder builds row-like objects from a
    projected query and has no `payload` column, so a direct attribute read raised AttributeError and
    took the forwarder down — caught by tests/api/test_siem_forwarder.py, which is exactly what that
    defensive style in `_to_dict` exists to prevent.
    """
    payload = getattr(row, "payload", None)
    ctx = payload.get("mcp") if isinstance(payload, dict) else None
    return ctx if isinstance(ctx, dict) else None


@router.get("/audit/records")
async def list_audit_records(
    namespace: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    agent: str | None = Query(default=None),  # SPIFFE/agent-id substring, filtered SERVER-SIDE over the range
    framework: str | None = Query(default=None),  # decision source (sidecar / api / sdk / redteam / ...)
    rule_id: str | None = Query(default=None),  # Compliance deep-link: filter by the enforcing rule (exact match)
    # Real-traffic-only view: drop red-team + synthetic/probe rows so the Audit Log reconciles with the
    # Overview headline (which counts the same real-traffic population). Same exclusion as /audit/stats.
    exclude_synthetic: bool = Query(default=False),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List audit records with pagination and filters. tool_name + agent are CASE-INSENSITIVE SUBSTRING
    matches applied server-side across the whole range (not exact-equality, not a client-side page filter)."""
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    query = (
        select(AuditLogEntry)
        .where(AuditLogEntry.timestamp_utc >= since)
        .order_by(desc(AuditLogEntry.timestamp_utc))
        .limit(limit)
        .offset(offset)
    )
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    if decision:
        query = query.where(AuditLogEntry.decision == decision)
    if tool_name:
        query = query.where(AuditLogEntry.tool_name.icontains(tool_name, autoescape=True))  # substring, not ==
    if agent:
        query = query.where(AuditLogEntry.agent_id.icontains(agent, autoescape=True))  # server-side SPIFFE filter
    if framework:
        query = query.where(AuditLogEntry.framework == framework)  # filter by decision source
    if rule_id:
        query = query.where(AuditLogEntry.rule_id == rule_id)  # Compliance evidence-row deep-link
    if exclude_synthetic:
        query = query.where(~audit_row_is_non_real(AuditLogEntry))  # real traffic only — reconciles with /audit/stats
    rows = (await session.execute(query)).scalars().all()
    log.debug("nrvq.api.audit.listed", count=len(rows), code="NRVQ-API-7020")
    return [_to_dict(row) for row in rows]


@router.get("/audit/records/{record_id}")
async def get_audit_record(
    record_id: str,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Get a single audit record by id."""
    try:
        parsed_id = UUID(record_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Record not found") from exc
    row = await session.scalar(select(AuditLogEntry).where(AuditLogEntry.id == parsed_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Record not found")
    scoped_namespace(user, row.namespace)  # 403 if a non-admin reads another namespace's record
    payload = _to_dict(row)
    payload["payload"] = row.payload
    return payload


@router.get("/audit/stats")
async def audit_stats(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Return aggregate audit stats."""
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    # RECONCILE (real-traffic-only): the Overview KPIs/top-tools must count the SAME population the governance
    # surfaces do (Compliance/MITRE `_activity_by_rule`, RedTeam `compute_efficacy`) — REAL traffic only. So we
    # exclude red-team framework events (efficacy tooling, not live enforcement) and synthetic/probe/eval
    # identities (`is_synthetic_identity`). `is_synthetic_identity` is a Python prefix/regex classifier that
    # is NOT expressible in SQL, so — exactly like `_activity_by_rule` — we GROUP BY the discriminating columns
    # and drop the excluded rows Python-side before aggregating (bounded cardinality, not a full table scan).
    stmt = (
        select(
            AuditLogEntry.tool_name,
            AuditLogEntry.decision,
            AuditLogEntry.agent_class,
            AuditLogEntry.framework,
            AuditLogEntry.rule_id,
            func.count(AuditLogEntry.id),
            func.sum(AuditLogEntry.latency_ms),
            func.count(AuditLogEntry.latency_ms),  # non-null latency count → matches AVG() semantics
        )
        .where(AuditLogEntry.timestamp_utc >= since)
        .group_by(
            AuditLogEntry.tool_name, AuditLogEntry.decision, AuditLogEntry.agent_class,
            AuditLogEntry.framework, AuditLogEntry.rule_id,
        )
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    total = 0
    blocked = 0
    # Monitor mode (namespace enforcement_mode=audit, or a per-policy audit-mode policy) SOFTENS a
    # would-block into an `audit` decision — it never emits `block`. So `blocked` is structurally 0 for a
    # monitored namespace, and the Overview tile (which correctly relabels itself "Would-block") was
    # reading that 0 and reporting "nothing would have been stopped" for a namespace the policy was
    # stopping plenty in. Counted separately rather than folded into `blocked` so an enforcing namespace's
    # number keeps meaning "actually blocked".
    would_blocked = 0
    # Engine (OPA-eval) errors are fail-closed ENGINE faults, not policy decisions. Surface them as a
    # distinct dashboard signal so an `evaluator_error` spike reads as an engine-health problem, not a wall of
    # "policy blocks". A clean input never produces one (transient errors self-heal via the evaluator retry).
    engine_errors = 0
    # Real average end-to-end latency over the SAME window (+ namespace + real-traffic) predicate. latency_ms
    # is the measured evaluate latency stamped on every audit record; summing it and dividing by the count
    # of non-null latencies reproduces AVG() over exactly the rows we kept. The Overview's Avg-latency KPI binds
    # this instead of averaging a capped client-side records sample.
    latency_sum = 0.0
    latency_n = 0
    tool_counts: dict[str, int] = {}
    for tool_name, decision, agent_class, framework, rule_id, count, lat_sum, lat_n in (
        await session.execute(stmt)
    ).all():
        if str(framework or "") == "redteam" or is_synthetic_identity(str(agent_class or "")):
            continue  # excluded from Overview so it reconciles with Compliance/MITRE + RedTeam efficacy
        n = int(count or 0)
        total += n
        if decision == "block":
            blocked += n
        if str(rule_id or "").startswith(WOULD_BLOCK_RULE_PREFIXES):
            would_blocked += n
        # Prefix-aware, and across the whole engine-fault family rather than one id. It matched
        # `evaluator_error` EXACTLY, so the moment a namespace ran monitor mode the stored id became
        # `monitor_would_block:evaluator_error` and the engine-health signal on the Overview read zero
        # during an actual engine fault — the softening that protects customer traffic also hid the
        # reason it was needed. Timeouts and the unhandled-fault path were never counted at all.
        if infra_rule_for(str(rule_id or "")) is not None:
            engine_errors += n
        tool_counts[str(tool_name or "")] = tool_counts.get(str(tool_name or ""), 0) + n
        latency_sum += float(lat_sum or 0.0)
        latency_n += int(lat_n or 0)
    top_tools = [
        {"tool_name": name, "count": count}
        for name, count in sorted(tool_counts.items(), key=lambda kv: -kv[1])[:5]
    ]
    rate = round((blocked / total) * 100, 2) if total else 0.0
    # Companion rate for the monitored case, so the tile and its percentage agree instead of the label
    # flipping to "Would-block Rate %" over a figure derived from live blocks.
    would_block_rate = round((would_blocked / total) * 100, 2) if total else 0.0
    avg_latency_ms = round(latency_sum / latency_n, 2) if latency_n else 0.0
    log.debug("nrvq.api.audit.stats", total=total, blocked=blocked, would_blocked=would_blocked,
              engine_errors=engine_errors, avg_latency_ms=avg_latency_ms, code="NRVQ-API-7021")
    return {"total": total, "blocked": blocked, "allowed": total - blocked, "block_rate_pct": rate,
            "would_blocked": would_blocked, "would_block_rate_pct": would_block_rate,
            "engine_errors": engine_errors, "avg_latency_ms": avg_latency_ms, "top_tools": top_tools}


@router.get("/audit/top-blocked")
async def top_blocked_tools(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=5, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Top blocked tool names by count."""
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    # Reconcile: the Overview headline (audit_stats) already excludes red-team framework events +
    # synthetic/probe identities so it counts the SAME real-traffic population as Compliance/MITRE. This
    # sibling widget must too, or the Top-Blocked-Tools list on the same page contradicts its own headline.
    # is_synthetic_identity is a Python prefix/regex classifier NOT expressible in SQL, so — exactly like
    # audit_stats — we load the blocked rows (already the small decision=='block' subset) and drop the
    # excluded ones Python-side before summing per tool_name and taking the top-N.
    query = (
        select(AuditLogEntry)
        .where(AuditLogEntry.decision == "block")
        .where(AuditLogEntry.timestamp_utc >= since)
    )
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    records = (await session.execute(query)).scalars().all()
    tool_counts: dict[str, int] = {}
    for record in records:
        if str(getattr(record, "framework", "") or "") == "redteam" or is_synthetic_identity(
            str(getattr(record, "agent_class", "") or "")
        ):
            continue  # excluded from the Overview so it reconciles with the headline + Compliance/MITRE
        name = str(record.tool_name or "")
        tool_counts[name] = tool_counts.get(name, 0) + 1
    top = sorted(tool_counts.items(), key=lambda kv: -kv[1])[:limit]
    log.debug("nrvq.api.audit.top_blocked", count=len(top), code="NRVQ-API-7022")
    return [{"tool_name": name, "count": count} for name, count in top]


@router.get("/audit/volume")
async def audit_volume(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Tool call volume, bucketed at a width that follows the requested `range`."""
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    bucket_minutes = _BUCKET_MINUTES.get(range, 60)
    query = select(AuditLogEntry).where(AuditLogEntry.timestamp_utc >= since).order_by(AuditLogEntry.timestamp_utc)
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    records = (await session.execute(query)).scalars().all()
    buckets: dict[str, dict[str, int | str]] = {}
    for record in records:
        # Reconcile: drop red-team + synthetic/probe traffic so the volume chart counts the same
        # real-traffic population as the Overview headline + Compliance/MITRE (this query already loads full
        # rows, so agent_class/framework are on-hand — no extra query).
        if str(getattr(record, "framework", "") or "") == "redteam" or is_synthetic_identity(
            str(getattr(record, "agent_class", "") or "")
        ):
            continue
        key = _bucket_key(record.timestamp_utc, bucket_minutes)
        if key not in buckets:
            buckets[key] = {"time": key, "allow": 0, "block": 0, "escalate": 0, "audit": 0}
        buckets[key][record.decision] = int(buckets[key].get(record.decision, 0)) + 1
    log.debug("nrvq.api.audit.volume", buckets=len(buckets), bucket_minutes=bucket_minutes,
              code="NRVQ-API-7023")
    return list(buckets.values())


async def _stream_audit_rows(
    session: AsyncSession, namespace: str | None, decision: str | None, since: datetime
) -> AsyncIterator[AuditLogEntry]:
    """Yield audit rows in keyset-paged chunks (never loads the whole table into memory)."""
    last_ts: datetime | None = None
    last_id = None
    while True:
        query = (
            select(AuditLogEntry)
            .where(AuditLogEntry.timestamp_utc >= since)
            .order_by(desc(AuditLogEntry.timestamp_utc), desc(AuditLogEntry.id))
            .limit(_EXPORT_PAGE)
        )
        if namespace:
            query = query.where(AuditLogEntry.namespace == namespace)
        if decision:
            query = query.where(AuditLogEntry.decision == decision)
        if last_ts is not None:
            query = query.where(
                or_(
                    AuditLogEntry.timestamp_utc < last_ts,
                    and_(AuditLogEntry.timestamp_utc == last_ts, AuditLogEntry.id < last_id),
                )
            )
        rows = (await session.execute(query)).scalars().all()
        if not rows:
            return
        for row in rows:
            yield row
        if len(rows) < _EXPORT_PAGE:
            return
        last_ts, last_id = rows[-1].timestamp_utc, rows[-1].id


def _export_dict(row: AuditLogEntry) -> dict:
    """Audit row as an export record, including masked_params when captured."""
    record = _to_dict(row)
    payload = row.payload if isinstance(row.payload, dict) else {}
    if "masked_params" in payload:
        record["masked_params"] = payload["masked_params"]
    return record


@router.get("/audit/export")
async def export_audit_records(
    format: Literal["ndjson", "csv"] = Query(default="ndjson"),
    namespace: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    signed: bool = Query(default=False),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> StreamingResponse:
    """Stream audit records for SIEM ingest as NDJSON or CSV, namespace-scoped to the caller.

    signed=true (NDJSON only) emits a tamper-evident, hash-chained stream — each record carries a
    `_chain` link (seq, prev_hash, record_hash) and the stream ends with a `_manifest` line whose
    chain_tip is HMAC-SHA256-signed when an export signing key is configured.
    """
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    log.info("nrvq.api.audit.export", format=format, namespace=namespace, signed=signed, code="NRVQ-API-7024")

    async def _ndjson() -> AsyncIterator[str]:
        async for row in _stream_audit_rows(session, namespace, decision, since):
            yield json.dumps(_export_dict(row), separators=(",", ":")) + "\n"

    async def _ndjson_signed() -> AsyncIterator[str]:
        prev = ""
        count = 0
        async for row in _stream_audit_rows(session, namespace, decision, since):
            record = _export_dict(row)
            record_hash = _chain_hash(prev, record)
            record["_chain"] = {"seq": count, "prev_hash": prev, "record_hash": record_hash}
            prev = record_hash
            count += 1
            yield json.dumps(record, separators=(",", ":")) + "\n"
        manifest = {
            "_manifest": {
                "alg": "sha256-chain",
                "count": count,
                "chain_tip": prev,
                "namespace": namespace or "*",
                "range": range,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "signature": None,
            }
        }
        if settings.audit_export_signing_key:
            sig = hmac.new(settings.audit_export_signing_key.encode("utf-8"), prev.encode("utf-8"), hashlib.sha256)
            manifest["_manifest"]["alg"] = "sha256-chain+HMAC-SHA256"
            manifest["_manifest"]["signature"] = sig.hexdigest()
        yield json.dumps(manifest, separators=(",", ":")) + "\n"

    async def _csv() -> AsyncIterator[str]:
        header = io.StringIO()
        csv.writer(header).writerow(_EXPORT_FIELDS)
        yield header.getvalue()
        async for row in _stream_audit_rows(session, namespace, decision, since):
            record = _to_dict(row)
            buf = io.StringIO()
            csv.writer(buf).writerow([record.get(field, "") for field in _EXPORT_FIELDS])
            yield buf.getvalue()

    if format == "csv":
        return StreamingResponse(
            _csv(), media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=norviq-audit-export.csv"},
        )
    if signed:
        return StreamingResponse(
            _ndjson_signed(), media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=norviq-audit-export.signed.ndjson"},
        )
    return StreamingResponse(
        _ndjson(), media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=norviq-audit-export.ndjson"},
    )
