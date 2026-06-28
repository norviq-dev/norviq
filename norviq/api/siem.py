# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Outbound SIEM audit forwarder (opt-in). Pushes new audit rows to a configured endpoint.

Off by default (`settings.siem_enabled`). The authenticated pull endpoint
`GET /api/v1/audit/export` is the always-on path; this is the push complement. The syslog format
is a documented stub — `ndjson` is the implemented wire format.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import structlog
from sqlalchemy import select

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.routers.audit import _to_dict
from norviq.config import settings

log = structlog.get_logger()

_BATCH = 500


class AuditForwarder:
    """Periodically POSTs new audit rows to a SIEM endpoint as NDJSON (cursor by timestamp)."""

    def __init__(self, session_factory=get_session, client: httpx.AsyncClient | None = None) -> None:
        """Store collaborators; session_factory yields an AsyncSession (overridable in tests)."""
        self._session_factory = session_factory
        self._client = client
        self._owns_client = client is None
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._cursor_ts = None

    async def start(self) -> None:
        """Launch the background poll loop when enabled and configured (else a no-op)."""
        if not settings.siem_enabled:
            return
        if not settings.siem_webhook_url:
            log.warning("nrvq.siem.not_configured", reason="missing_webhook_url", code="NRVQ-SIEM-14002")
            return
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info("nrvq.siem.started", url=settings.siem_webhook_url, code="NRVQ-SIEM-14000")

    async def _run(self) -> None:
        """Poll-and-forward until stopped, tolerating transient endpoint failures."""
        while not self._stop.is_set():
            try:
                await self.forward_once()
            except Exception as exc:  # pragma: no cover - network/DB transient
                log.error("nrvq.siem.forward_failed", error=str(exc), code="NRVQ-SIEM-14001")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.siem_poll_interval_s)
            except asyncio.TimeoutError:
                pass

    async def forward_once(self) -> int:
        """Fetch audit rows newer than the cursor, POST them, advance the cursor. Returns count."""
        rows = await self._fetch_new()
        if not rows:
            return 0
        payload = "".join(json.dumps(_to_dict(row), separators=(",", ":")) + "\n" for row in rows)
        response = await self._client.post(
            settings.siem_webhook_url, content=payload, headers={"content-type": "application/x-ndjson"}
        )
        response.raise_for_status()
        self._cursor_ts = rows[-1].timestamp_utc
        log.info("nrvq.siem.forwarded", count=len(rows), code="NRVQ-SIEM-14000")
        return len(rows)

    async def _fetch_new(self) -> list[AuditLogEntry]:
        """Read the next batch of audit rows after the cursor, ordered oldest-first."""
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            query = (
                select(AuditLogEntry)
                .order_by(AuditLogEntry.timestamp_utc, AuditLogEntry.id)
                .limit(_BATCH)
            )
            if self._cursor_ts is not None:
                query = query.where(AuditLogEntry.timestamp_utc > self._cursor_ts)
            return list((await session.execute(query)).scalars().all())
        finally:
            await self._aclose(provider)

    @staticmethod
    async def _aclose(provider: AsyncIterator) -> None:
        """Close the async-generator session provider if it supports it."""
        if hasattr(provider, "aclose"):
            await provider.aclose()

    async def stop(self) -> None:
        """Signal the loop to stop, await it, and close an owned HTTP client."""
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
