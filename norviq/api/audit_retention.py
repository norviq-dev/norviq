# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HIGH-2a: periodic audit_log retention pruning.

``settings.audit_retention_days`` was defined but never enforced — audit_log is append-only (every
gated tool call writes a row) with no pruning job, so it grows unbounded, which is itself an
availability risk (unbounded table/index growth degrades writes and disk usage over time). This mirrors
the ``AuditForwarder`` (siem.py) / ``FleetPolicyPuller`` lifespan pattern: a class with ``start()``/
``stop()`` that owns its own background poll loop, wired into ``main.py``'s lifespan and cancelled on
shutdown.

SAFETY: this only ever deletes rows in ``audit_log`` (an append-only EVIDENCE table) older than the
retention cutoff — it never touches ``policies``/``policy_versions`` or anything the evaluator reads, so
pruning can never change enforcement.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import structlog

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.config import settings

log = structlog.get_logger()


class AuditRetentionPruner:
    """Periodically deletes audit_log rows older than ``settings.audit_retention_days``."""

    def __init__(self, session_factory=get_session) -> None:
        """Store the session factory (overridable in tests); session_factory yields an AsyncSession."""
        self._session_factory = session_factory
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        """Launch the background prune loop (no-op if retention is disabled: audit_retention_days <= 0)."""
        if settings.audit_retention_days <= 0:
            log.info("nrvq.audit.retention_disabled", code="NRVQ-AUD-6011")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "nrvq.audit.retention_started",
            retention_days=settings.audit_retention_days,
            interval_s=settings.audit_retention_prune_interval_s,
            code="NRVQ-AUD-6009",
        )

    async def _run(self) -> None:
        """Prune-and-sleep until stopped, tolerating transient DB failures (best-effort, never crashes)."""
        while not self._stop.is_set():
            try:
                await self.prune_once()
            except Exception as exc:  # noqa: BLE001 - best-effort; a DB hiccup must not kill the loop
                log.error("nrvq.audit.retention_prune_failed", error=str(exc), code="NRVQ-AUD-6012")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.audit_retention_prune_interval_s)
            except asyncio.TimeoutError:
                pass

    async def prune_once(self) -> int:
        """Delete audit_log rows older than the retention cutoff. Returns the number of rows deleted."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            result = await session.execute(
                AuditLogEntry.__table__.delete().where(AuditLogEntry.timestamp_utc < cutoff)
            )
            await session.commit()
            n = int(result.rowcount or 0)
            if n:
                log.info("nrvq.audit.retention_pruned", count=n, cutoff=cutoff.isoformat(), code="NRVQ-AUD-6010")
            return n
        except Exception:
            await session.rollback()
            raise
        finally:
            await provider.aclose()

    async def stop(self) -> None:
        """Cancel the background loop (graceful shutdown)."""
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - shutdown best-effort
                pass
            self._task = None
