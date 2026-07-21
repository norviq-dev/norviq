# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Graph analysis API routes."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Request

from typing import Callable

from norviq.api.auth import get_current_user, scoped_namespace
from norviq.engine.graph.analyzer import GraphAnalyzer
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.attack_graph import AttackGraphEngine
from norviq.engine.graph.store import compute_graph_version

router = APIRouter(prefix="/graph", tags=["graph"])


async def _graph_from_request(request: Request, namespace: str) -> AssetGraphBuilder:
    """Resolve graph snapshot for requested namespace."""
    store = getattr(request.app.state, "graph_store", None)
    if store is not None:
        loaded = await store.load(namespace)
        if loaded is not None:
            return loaded
    evaluator = getattr(request.app.state, "evaluator", None)
    if evaluator is None or not hasattr(evaluator, "get_graph"):
        raise HTTPException(status_code=503, detail="Graph engine is unavailable")
    return evaluator.get_graph(namespace)


async def _cached_analysis(
    request: Request, namespace: str, analysis_type: str, params: str, compute: Callable[[AssetGraphBuilder], object]
) -> object:
    """Serve a graph analysis from the per-(namespace, graph-version) cache, computing on miss.
    The graph snapshot is loaded once; the expensive analysis is memoized and auto-invalidated on graph change."""
    graph = await _graph_from_request(request, namespace)
    cache = getattr(request.app.state, "cache", None)
    if cache is None or not hasattr(cache, "get_analysis"):
        return compute(graph)
    version = compute_graph_version(graph)
    hit = await cache.get_analysis(namespace, version, analysis_type, params)
    if hit is not None:
        return hit
    result = compute(graph)
    await cache.set_analysis(namespace, version, analysis_type, result, params)
    return result


@router.get("/")
async def get_graph(request: Request, namespace: str = "default", user: dict = Depends(get_current_user)) -> dict[str, object]:
    """Get asset graph snapshot for one namespace."""
    namespace = scoped_namespace(user, namespace) or "default"
    graph = await _graph_from_request(request, namespace)
    return graph.to_dict()


@router.get("/summary")
async def get_summary(request: Request, namespace: str = "default", user: dict = Depends(get_current_user)) -> dict[str, object]:
    """Return topology and trust summary metrics."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(request, namespace, "summary", "", lambda g: AttackGraphEngine(g.graph).get_summary())


@router.get("/blast-radius/{agent_id:path}")
async def get_blast_radius(request: Request, agent_id: str, namespace: str = "default", user: dict = Depends(get_current_user)) -> dict[str, object]:
    """Compute blast radius for compromised agent."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(
        request, namespace, "blast", agent_id, lambda g: asdict(AttackGraphEngine(g.graph).compute_blast_radius(agent_id))
    )


@router.get("/attack-paths")
async def get_attack_paths(request: Request, source: str, target: str, namespace: str = "default", user: dict = Depends(get_current_user)) -> list[dict[str, object]]:
    """Return attack paths between source and target."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(
        request, namespace, "paths", f"{source}->{target}",
        lambda g: [asdict(path) for path in AttackGraphEngine(g.graph).find_attack_paths(source, target)],
    )


@router.get("/critical-paths")
async def get_critical_paths(request: Request, namespace: str = "default", user: dict = Depends(get_current_user)) -> list[dict[str, object]]:
    """Find paths crossing low trust boundaries."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(
        request, namespace, "critical", "",
        lambda g: [asdict(path) for path in AttackGraphEngine(g.graph).find_critical_paths()],
    )


@router.get("/chokepoints")
async def get_chokepoints(request: Request, namespace: str = "default", user: dict = Depends(get_current_user)) -> list[dict[str, object]]:
    """Find tool chokepoints in graph."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(request, namespace, "chokepoints", "", lambda g: AttackGraphEngine(g.graph).find_chokepoints())


@router.get("/analysis")
async def get_full_analysis(request: Request, namespace: str = "default", user: dict = Depends(get_current_user)) -> dict[str, object]:
    """Run complete graph analysis report."""
    namespace = scoped_namespace(user, namespace) or "default"
    return await _cached_analysis(request, namespace, "full", "", lambda g: GraphAnalyzer(g).full_analysis())
