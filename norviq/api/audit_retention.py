# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unified background data-retention pruner (extends the original audit_log pruner).

One hourly loop (``audit_retention_prune_interval_s``) sweeps every retention-managed table; each
table has its own knob and a ``<=0`` value disables that table's pruning (keep forever):

* ``audit_log``                 — rows older than ``audit_retention_days`` (default 30)
* ``mitre_coverage_snapshots``  — rows older than ``coverage_snapshot_retention_days`` (default 30)
* ``intent_drafts``             — expired drafts (``expires_at``-driven; pruned here regardless of
                                  whether the Catalog list was ever loaded, so a namespace nobody
                                  views does not keep its expired rows indefinitely)
* ``agent_registry``            — identities unseen for ``agent_registry_retention_days`` (default 90)
* ``asset_graph``               — keep the newest ``graph_snapshot_keep_per_namespace`` (default 10)
                                  snapshots per namespace; rows referenced by ``attack_paths`` are
                                  ALWAYS kept (the FK has no cascade — deleting one would break the
                                  paths' provenance), readers only ever use the newest row.

SAFETY: none of these tables is read by the evaluator's enforcement path — ``policies`` /
``policy_versions`` (and anything else enforcement reads) are deliberately NOT retention-managed
here, so pruning can never change a decision. Mirrors the ``AuditForwarder`` / ``FleetPolicyPuller``
lifespan pattern: ``start()``/``stop()`` owning a background loop, cancelled on shutdown. One pruner
runs per API replica; every statement is idempotent so concurrent sweeps are harmless.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import text

from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.retention import gc_expired_drafts
from norviq.config import settings

log = structlog.get_logger()


class RetentionPruner:
    """Periodically applies every table's retention window (see module docstring)."""

    def __init__(self, session_factory=get_session) -> None:
        """Store the session factory (overridable in tests); session_factory yields an AsyncSession."""
        self._session_factory = session_factory
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        """Launch the background prune loop. Always starts: drafts GC is expires_at-driven (no disable
        knob), and each dated window checks its own <=0 switch per sweep."""
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "nrvq.retention.started",
            audit_days=settings.audit_retention_days,
            coverage_days=settings.coverage_snapshot_retention_days,
            registry_days=settings.agent_registry_retention_days,
            graph_keep=settings.graph_snapshot_keep_per_namespace,
            interval_s=settings.audit_retention_prune_interval_s,
            code="NRVQ-AUD-6009",
        )

    async def _run(self) -> None:
        """Prune-and-sleep until stopped, tolerating transient DB failures (best-effort, never crashes)."""
        while not self._stop.is_set():
            try:
                await self.prune_once()
            except Exception as exc:  # noqa: BLE001 - best-effort; a DB hiccup must not kill the loop
                log.error("nrvq.retention.prune_failed", error=str(exc), code="NRVQ-AUD-6012")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.audit_retention_prune_interval_s)
            except asyncio.TimeoutError:
                pass

    async def prune_once(self) -> dict[str, int]:
        """Run one sweep across every retention-managed table. Each table is pruned in its own
        best-effort step (a failure in one never blocks the others). Returns per-table delete counts."""
        counts = {
            "audit_log": await self._step(self._prune_audit),
            "coverage_snapshots": await self._step(self._prune_coverage_snapshots),
            "intent_drafts": await self._step(self._prune_drafts),
            "agent_registry": await self._step(self._prune_agent_registry),
            "asset_graph": await self._step(self._prune_asset_graph),
        }
        if any(counts.values()):
            log.info("nrvq.retention.pruned", **counts, code="NRVQ-AUD-6010")
        return counts

    async def _step(self, fn) -> int:
        """Run one table's prune with its own session + error isolation (best-effort per table)."""
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            n = await fn(session)
            await session.commit()
            return int(n or 0)
        except Exception as exc:  # noqa: BLE001 - isolate: one table's failure must not stop the sweep
            await session.rollback()
            log.warning("nrvq.retention.step_failed", step=fn.__name__, error=str(exc), code="NRVQ-AUD-6013")
            return 0
        finally:
            await provider.aclose()

    async def _prune_audit(self, session) -> int:
        """audit_log rows older than audit_retention_days (<=0 disables)."""
        if settings.audit_retention_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)
        result = await session.execute(
            AuditLogEntry.__table__.delete().where(AuditLogEntry.timestamp_utc < cutoff)
        )
        return result.rowcount or 0

    async def _prune_coverage_snapshots(self, session) -> int:
        """mitre_coverage_snapshots trend points older than the window (<=0 disables). ONLY kind='snapshot'
        (the coverage-trend series) is pruned — kind='export' rows are evidence-pack export provenance
        markers (the "last exported" indicator) and are audit evidence, so retention NEVER touches them."""
        days = int(getattr(settings, "coverage_snapshot_retention_days", 0))
        if days <= 0:
            return 0
        result = await session.execute(
            text(
                "DELETE FROM mitre_coverage_snapshots "
                "WHERE timestamp_utc < :cutoff AND kind = 'snapshot'"
            ),
            {"cutoff": datetime.now(timezone.utc) - timedelta(days=days)},
        )
        return result.rowcount or 0

    async def _prune_drafts(self, session) -> int:
        """Expired intent drafts, globally — the background counterpart of the Catalog's lazy GC (which
        only ever ran for namespaces someone actually listed). Non-enforcing by construction."""
        return await gc_expired_drafts(session, None)

    async def _prune_agent_registry(self, session) -> int:
        """agent_registry identities unseen for agent_registry_retention_days (<=0 disables). Removes
        decommissioned/churned agents that would otherwise be listed forever and surface as phantom
        'awaiting' nodes on the asset graph."""
        days = int(getattr(settings, "agent_registry_retention_days", 0))
        if days <= 0:
            return 0
        result = await session.execute(
            text("DELETE FROM agent_registry WHERE last_seen < :cutoff"),
            {"cutoff": datetime.now(timezone.utc) - timedelta(days=days)},
        )
        return result.rowcount or 0

    async def _prune_asset_graph(self, session) -> int:
        """asset_graph snapshots beyond the newest N per namespace (<=0 disables). Every reader uses only
        the newest row per namespace (DISTINCT ON / LIMIT 1), so older rows are dead weight that grows
        one row per evaluated tool call. Rows referenced by attack_paths are ALWAYS kept — the FK has no
        ON DELETE and the paths' provenance stays inspectable."""
        keep = int(getattr(settings, "graph_snapshot_keep_per_namespace", 0))
        if keep <= 0:
            return 0
        result = await session.execute(
            text(
                "DELETE FROM asset_graph WHERE id IN ("
                "  SELECT id FROM ("
                "    SELECT id, row_number() OVER ("
                "      PARTITION BY namespace ORDER BY built_at DESC"
                "    ) AS rn FROM asset_graph"
                "  ) ranked WHERE ranked.rn > :keep"
                ") AND id NOT IN (SELECT DISTINCT graph_id FROM attack_paths)"
            ),
            {"keep": keep},
        )
        return result.rowcount or 0

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


# Back-compat alias for the audit-only pruner name.
AuditRetentionPruner = RetentionPruner
