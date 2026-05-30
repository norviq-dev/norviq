# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Audit query routes."""

from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import desc, func, select

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()


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
        "trust_score": row.trust_score,
        "latency_ms": row.latency_ms,
        "timestamp": row.timestamp_utc.isoformat(),
    }


@router.get("/audit/records")
async def list_audit_records(
    namespace: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    tool_name: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List audit records with pagination and filters."""
    since = _since_for_range(range)
    session = await get_session()
    try:
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
            query = query.where(AuditLogEntry.tool_name == tool_name)
        rows = (await session.execute(query)).scalars().all()
    finally:
        await session.close()
    log.debug("nrvq.api.audit.listed", count=len(rows), code="NRVQ-API-7020")
    return [_to_dict(row) for row in rows]


@router.get("/audit/records/{record_id}")
async def get_audit_record(record_id: str) -> dict:
    """Get a single audit record by id."""
    try:
        parsed_id = UUID(record_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Record not found") from exc
    session = await get_session()
    try:
        row = await session.scalar(select(AuditLogEntry).where(AuditLogEntry.id == parsed_id))
    finally:
        await session.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Record not found")
    payload = _to_dict(row)
    payload["payload"] = row.payload
    return payload


@router.get("/audit/stats")
async def audit_stats(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
) -> dict:
    """Return aggregate audit stats."""
    since = _since_for_range(range)
    session = await get_session()
    try:
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
    finally:
        await session.close()
    rate = round((blocked / total) * 100, 2) if total else 0.0
    log.debug("nrvq.api.audit.stats", total=total, blocked=blocked, code="NRVQ-API-7021")
    return {"total": total, "blocked": blocked, "allowed": total - blocked, "block_rate_pct": rate, "top_tools": top_tools}


@router.get("/audit/top-blocked")
async def top_blocked_tools(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
    limit: int = Query(default=5, ge=1, le=100),
) -> list[dict]:
    """Top blocked tool names by count."""
    since = _since_for_range(range)
    session = await get_session()
    try:
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
    finally:
        await session.close()
    log.debug("nrvq.api.audit.top_blocked", count=len(rows), code="NRVQ-API-7022")
    return [{"tool_name": row.tool_name, "count": row.count} for row in rows]


@router.get("/audit/volume")
async def audit_volume(
    namespace: str | None = Query(default=None),
    range: Literal["1h", "6h", "24h", "7d", "30d"] = Query(default="24h"),
) -> list[dict]:
    """Tool call volume bucketed by hour."""
    since = _since_for_range(range)
    session = await get_session()
    try:
        query = select(AuditLogEntry).where(AuditLogEntry.timestamp_utc >= since).order_by(AuditLogEntry.timestamp_utc)
        if namespace:
            query = query.where(AuditLogEntry.namespace == namespace)
        records = (await session.execute(query)).scalars().all()
    finally:
        await session.close()
    buckets: dict[str, dict[str, int | str]] = {}
    for record in records:
        hour_key = record.timestamp_utc.strftime("%Y-%m-%d %H:00")
        if hour_key not in buckets:
            buckets[hour_key] = {"time": hour_key, "allow": 0, "block": 0, "escalate": 0, "audit": 0}
        buckets[hour_key][record.decision] = int(buckets[hour_key].get(record.decision, 0)) + 1
    log.debug("nrvq.api.audit.volume", buckets=len(buckets), code="NRVQ-API-7023")
    return list(buckets.values())
