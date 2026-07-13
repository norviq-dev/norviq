# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Trigger endpoint for attack graph computation."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_target_cluster
from norviq.api.db.session import get_session
from norviq.engine.attack_graph import AttackGraphEngine

log = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["attack-graph"])


@router.post("/attack-paths/compute")
async def trigger_attack_graph_computation(
    request: Request,
    namespace: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
):
    """Trigger attack graph recomputation for one or all namespaces."""
    require_admin(user)
    try:
        engine = AttackGraphEngine(request.app.state.evaluator)
        if namespace:
            count = await engine.compute_paths_for_namespace(session, namespace)
            log.info(
                "nrvq.attack_graph.computed",
                namespace=namespace,
                count=count,
                code="NRVQ-API-7060",
            )
            return {"namespace": namespace, "computed": count}
        counts = await engine.compute_all_namespaces(session)
        log.info(
            "nrvq.attack_graph.computed_all",
            namespaces=list(counts.keys()),
            total=sum(counts.values()),
            code="NRVQ-API-7060",
        )
        return {"computed_by_namespace": counts, "total": sum(counts.values())}
    except Exception as exc:
        log.error(
            "nrvq.attack_graph.compute_failed",
            error=str(exc),
            code="NRVQ-API-7060-ERR",
        )
        raise HTTPException(status_code=500, detail=f"Compute failed: {exc}") from exc
