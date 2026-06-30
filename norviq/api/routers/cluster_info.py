# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Cluster-info route (F046) — the console's LIVE source for this deployment's identity + namespaces.

Replaces the console's hardcoded CLUSTERS / NS_BY_CLUSTER. The cluster id/name come from config; the
namespace list is the REAL set observed across policies, agents, and audit — never a fabricated list.
When a fleet hub is configured the console lists clusters from /fleet/clusters instead; this endpoint
backs the single-cluster (fleet-off) path and the namespace selector in both.
"""

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user
from norviq.api.db.models import AgentRegistryEntry, AuditLogEntry, Policy
from norviq.api.db.session import get_session
from norviq.config import settings

log = structlog.get_logger()
router = APIRouter()

# The platform's canonical default namespace — returned only when nothing has been observed yet (a fresh
# install with no policies/agents/audit). This is the real default the system writes to, not fabricated data.
_DEFAULT_NS = "default"


@router.get("/cluster-info")
async def cluster_info(
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return this deployment's cluster id/name + the real namespaces observed in its data."""
    cluster_id = settings.fleet_cluster_id or "local"
    cluster_name = settings.fleet_cluster_name or cluster_id

    observed: set[str] = set()
    for model in (Policy, AuditLogEntry, AgentRegistryEntry):
        result = await session.execute(select(model.namespace).distinct())
        observed.update(ns for ns in result.scalars().all() if ns)
    # "all" is the reserved wildcard sentinel (the console's "All namespaces" option + the query-wildcard the
    # audit/stats routes treat as "no namespace filter"). A fleet-wide policy seeded into namespace "all" must
    # NOT surface as a selectable tenant namespace — it collides with that sentinel and renders a duplicate
    # "All namespaces" entry in the selector. Drop it from the observed tenant list.
    observed.discard("all")

    # Non-admin tokens see only their own namespace claim — consistent with scoped audit/agent/policy reads.
    role = str(user.get("role", "")).lower()
    claim_ns = str(user.get("namespace", "") or "")
    if role != "admin" and claim_ns:
        namespaces = [claim_ns]
    else:
        namespaces = sorted(observed) if observed else [_DEFAULT_NS]

    log.info(
        "nrvq.api.cluster_info.served",
        cluster=cluster_id,
        namespaces=len(namespaces),
        code="NRVQ-API-7080",
    )
    return {"cluster_id": cluster_id, "cluster_name": cluster_name, "namespaces": namespaces}
