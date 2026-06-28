# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Deployment (workload) discovery routes — derived from observed agent identities."""

import structlog
from fastapi import APIRouter, Depends, Query, Request

from norviq.api.auth import get_current_user

log = structlog.get_logger()
router = APIRouter()


def _ns_and_class_from_spiffe(spiffe_id: str) -> tuple[str | None, str | None]:
    """Pull (namespace, agent_class) from spiffe://.../ns/{ns}/sa/{agent_class}."""
    parts = spiffe_id.split("/")
    namespace = agent_class = None
    if "ns" in parts:
        idx = parts.index("ns")
        if idx + 1 < len(parts):
            namespace = parts[idx + 1]
    if "sa" in parts:
        idx = parts.index("sa")
        if idx + 1 < len(parts):
            agent_class = parts[idx + 1]
    return namespace, agent_class


@router.get("/deployments")
async def list_deployments(
    request: Request,
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """List workloads (name/namespace/agent_class) derived from observed agent identities.

    There is no K8s API behind the dev API, so we synthesize one workload per distinct
    agent_class seen in trust keys for the namespace. The UI keeps a static fallback for
    empty results, so an empty list is a valid (non-error) response.
    """
    _ = user
    cache = request.app.state.cache
    seen: set[str] = set()
    rows: list[dict] = []
    async for key in cache._client().scan_iter("trust:*"):
        spiffe_id = str(key).replace("trust:", "", 1)
        ns, agent_class = _ns_and_class_from_spiffe(spiffe_id)
        if ns != namespace or not agent_class or agent_class in seen:
            continue
        seen.add(agent_class)
        rows.append({"name": agent_class, "namespace": namespace, "agent_class": agent_class})
    log.debug("nrvq.api.deployments.listed", count=len(rows), namespace=namespace, code="NRVQ-API-7020")
    return rows
