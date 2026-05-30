# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Audit query routes."""

from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import desc, func, select

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()


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
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List audit records with pagination and filters."""
    session = await get_session()
    try:
        query = select(AuditLogEntry).order_by(desc(AuditLogEntry.timestamp_utc)).limit(limit).offset(offset)
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
async def audit_stats(namespace: str | None = Query(default=None)) -> dict:
    """Return aggregate audit stats."""
    session = await get_session()
    try:
        base = select(func.count(AuditLogEntry.id))
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
        top_tools = [{"tool_name": name, "count": count} for name, count in (await session.execute(tools_stmt)).all()]
    finally:
        await session.close()
    rate = round((blocked / total) * 100, 2) if total else 0.0
    log.debug("nrvq.api.audit.stats", total=total, blocked=blocked, code="NRVQ-API-7021")
    return {"total": total, "blocked": blocked, "allowed": total - blocked, "block_rate_pct": rate, "top_tools": top_tools}
