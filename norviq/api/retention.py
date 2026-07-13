# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Part B — draft retention/GC helpers (keeps the intent_drafts store + the Policy Catalog UI bounded).

SAFETY INVARIANT: everything here operates ONLY on the dedicated ``intent_drafts`` table, which the evaluator
NEVER reads (``_collect_candidates`` only queries ``policies``). So expiring/evicting/dismissing a draft can never
change enforcement — retention is fully decoupled from the enforcing policy set. Version-history pruning (which
DOES touch ``policy_versions``) lives in the loader and is guarded to never drop the current-enforcing version.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.synthetic import is_synthetic_identity
from norviq.config import settings

log = structlog.get_logger()


def draft_expiry(agent_class: str, now: datetime | None = None) -> datetime:
    """When a new draft for ``agent_class`` should auto-expire: fast for test/e2e (synthetic) classes, the normal
    window otherwise. Both windows are Helm/env-configurable (draft_ttl_days / draft_ttl_test_hours)."""
    base = now or datetime.now(timezone.utc)
    if is_synthetic_identity(agent_class):
        return base + timedelta(hours=int(settings.draft_ttl_test_hours))
    return base + timedelta(days=int(settings.draft_ttl_days))


async def gc_expired_drafts(session: AsyncSession, namespace: str | None = None) -> int:
    """Delete expired drafts (best-effort; returns how many). These are NON-ENFORCING by construction, so this is
    always safe. Scoped to a namespace when given."""
    sql = "DELETE FROM intent_drafts WHERE expires_at IS NOT NULL AND expires_at < :now"
    params: dict = {"now": datetime.now(timezone.utc)}
    if namespace and namespace.lower() != "all":
        sql += " AND namespace = :ns"
        params["ns"] = namespace
    try:
        result = await session.execute(text(sql), params)
        await session.commit()
        n = int(result.rowcount or 0)
        if n:
            log.info("nrvq.api.retention.drafts_expired", count=n, namespace=namespace, code="NRVQ-API-7110")
        return n
    except Exception as exc:  # noqa: BLE001 — GC is best-effort; never fail the caller
        log.warning("nrvq.api.retention.gc_failed", error=str(exc), code="NRVQ-API-7111")
        return 0


async def enforce_draft_cap(session: AsyncSession, namespace: str) -> int:
    """Hard ceiling of ``draft_cap_per_namespace`` real drafts per namespace — evict the OLDEST beyond the cap so
    the store can never grow unbounded even if a TTL is misconfigured. Non-enforcing rows only. Returns evicted."""
    cap = int(settings.draft_cap_per_namespace)
    try:
        # keep the newest `cap`; delete the rest for this namespace (by created_at, oldest first)
        result = await session.execute(
            text(
                "DELETE FROM intent_drafts WHERE id IN ("
                "  SELECT id FROM intent_drafts WHERE namespace = :ns "
                "  ORDER BY created_at DESC OFFSET :cap"
                ")"
            ),
            {"ns": namespace, "cap": cap},
        )
        await session.commit()
        n = int(result.rowcount or 0)
        if n:
            log.info("nrvq.api.retention.drafts_capped", count=n, namespace=namespace, cap=cap, code="NRVQ-API-7112")
        return n
    except Exception as exc:  # noqa: BLE001
        log.warning("nrvq.api.retention.cap_failed", error=str(exc), code="NRVQ-API-7113")
        return 0
