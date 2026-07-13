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
from norviq.config import settings


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
        # OBS-2: decision source (sidecar / sidecar-http / sdk / redteam / ...) for the UI Source column + filter.
        "framework": getattr(row, "framework", ""),
        "timestamp": row.timestamp_utc.isoformat(),
    }


@router.get("/audit/records")
async def list_audit_records(
    namespace: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    agent: str | None = Query(default=None),  # F-53: SPIFFE/agent-id substring, filtered SERVER-SIDE over the range
    framework: str | None = Query(default=None),  # OBS-2: decision source (sidecar / api / sdk / redteam / ...)
    rule_id: str | None = Query(default=None),  # Compliance deep-link: filter by the enforcing rule (exact match)
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List audit records with pagination and filters. F-53: tool_name + agent are CASE-INSENSITIVE SUBSTRING
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
        query = query.where(AuditLogEntry.tool_name.icontains(tool_name, autoescape=True))  # F-53: substring, not ==
    if agent:
        query = query.where(AuditLogEntry.agent_id.icontains(agent, autoescape=True))  # F-53: server-side SPIFFE filter
    if framework:
        query = query.where(AuditLogEntry.framework == framework)  # OBS-2: filter by decision source
    if rule_id:
        query = query.where(AuditLogEntry.rule_id == rule_id)  # Compliance evidence-row deep-link
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
    base = select(func.count(AuditLogEntry.id)).where(AuditLogEntry.timestamp_utc >= since)
    if namespace:
        base = base.where(AuditLogEntry.namespace == namespace)
    total = int((await session.scalar(base)) or 0)
    blocked = int((await session.scalar(base.where(AuditLogEntry.decision == "block"))) or 0)
    tools_stmt = (
        select(AuditLogEntry.tool_name, func.count(AuditLogEntry.id))
        .group_by(AuditLogEntry.tool_name)
        .order_by(desc(func.count(AuditLogEntry.id)))
        .limit(5)
    )
    if namespace:
        tools_stmt = tools_stmt.where(AuditLogEntry.namespace == namespace)
    top_tools = []
    for row in (await session.execute(tools_stmt)).all():
        if hasattr(row, "tool_name"):
            top_tools.append({"tool_name": row.tool_name, "count": row.count})
        else:
            top_tools.append({"tool_name": row[0], "count": row[1]})
    rate = round((blocked / total) * 100, 2) if total else 0.0
    # FIX-3: engine (OPA-eval) errors are fail-closed ENGINE faults, not policy decisions. Surface them as a
    # distinct dashboard signal so an `evaluator_error` spike reads as an engine-health problem, not a wall of
    # "policy blocks". A clean input never produces one (transient errors self-heal via the evaluator retry).
    engine_errors = int((await session.scalar(base.where(AuditLogEntry.rule_id == "evaluator_error"))) or 0)
    # K2: real average end-to-end latency over the SAME window (+ namespace) predicate. latency_ms is the measured
    # evaluate latency stamped on every audit record (F-13), so this is a real number, not a placeholder 0. The
    # Overview's Avg-latency KPI binds this instead of averaging a capped client-side records sample.
    avg_stmt = select(func.avg(AuditLogEntry.latency_ms)).where(AuditLogEntry.timestamp_utc >= since)
    if namespace:
        avg_stmt = avg_stmt.where(AuditLogEntry.namespace == namespace)
    avg_latency_ms = round(float((await session.scalar(avg_stmt)) or 0.0), 2)
    log.debug("nrvq.api.audit.stats", total=total, blocked=blocked, engine_errors=engine_errors,
              avg_latency_ms=avg_latency_ms, code="NRVQ-API-7021")
    return {"total": total, "blocked": blocked, "allowed": total - blocked, "block_rate_pct": rate,
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
    query = (
        select(AuditLogEntry.tool_name, func.count(AuditLogEntry.id).label("count"))
        .where(AuditLogEntry.decision == "block")
        .where(AuditLogEntry.timestamp_utc >= since)
        .group_by(AuditLogEntry.tool_name)
        .order_by(func.count(AuditLogEntry.id).desc())
        .limit(limit)
    )
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    rows = (await session.execute(query)).all()
    log.debug("nrvq.api.audit.top_blocked", count=len(rows), code="NRVQ-API-7022")
    return [{"tool_name": row.tool_name, "count": row.count} for row in rows]


@router.get("/audit/volume")
async def audit_volume(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Tool call volume bucketed by hour."""
    namespace = read_namespace(user, namespace)
    since = _since_for_range(range)
    query = select(AuditLogEntry).where(AuditLogEntry.timestamp_utc >= since).order_by(AuditLogEntry.timestamp_utc)
    if namespace:
        query = query.where(AuditLogEntry.namespace == namespace)
    records = (await session.execute(query)).scalars().all()
    buckets: dict[str, dict[str, int | str]] = {}
    for record in records:
        hour_key = record.timestamp_utc.strftime("%Y-%m-%d %H:00")
        if hour_key not in buckets:
            buckets[hour_key] = {"time": hour_key, "allow": 0, "block": 0, "escalate": 0, "audit": 0}
        buckets[hour_key][record.decision] = int(buckets[hour_key].get(record.decision, 0)) + 1
    log.debug("nrvq.api.audit.volume", buckets=len(buckets), code="NRVQ-API-7023")
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
    """Audit row as an export record, including masked_params when captured (F-19)."""
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

    F-19: signed=true (NDJSON only) emits a tamper-evident, hash-chained stream — each record carries a
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
