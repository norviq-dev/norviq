# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Graph analysis API routes."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from norviq.engine.graph.analyzer import GraphAnalyzer
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.attack_graph import AttackGraphEngine

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


@router.get("/")
async def get_graph(request: Request, namespace: str = "default") -> dict[str, object]:
    """Get asset graph snapshot for one namespace."""
    graph = await _graph_from_request(request, namespace)
    return graph.to_dict()


@router.get("/summary")
async def get_summary(request: Request, namespace: str = "default") -> dict[str, object]:
    """Return topology and trust summary metrics."""
    graph = await _graph_from_request(request, namespace)
    return AttackGraphEngine(graph.graph).get_summary()


@router.get("/blast-radius/{agent_id:path}")
async def get_blast_radius(request: Request, agent_id: str, namespace: str = "default") -> dict[str, object]:
    """Compute blast radius for compromised agent."""
    graph = await _graph_from_request(request, namespace)
    return asdict(AttackGraphEngine(graph.graph).compute_blast_radius(agent_id))


@router.get("/attack-paths")
async def get_attack_paths(request: Request, source: str, target: str, namespace: str = "default") -> list[dict[str, object]]:
    """Return attack paths between source and target."""
    graph = await _graph_from_request(request, namespace)
    paths = AttackGraphEngine(graph.graph).find_attack_paths(source, target)
    return [asdict(path) for path in paths]


@router.get("/critical-paths")
async def get_critical_paths(request: Request, namespace: str = "default") -> list[dict[str, object]]:
    """Find paths crossing low trust boundaries."""
    graph = await _graph_from_request(request, namespace)
    paths = AttackGraphEngine(graph.graph).find_critical_paths()
    return [asdict(path) for path in paths]


@router.get("/chokepoints")
async def get_chokepoints(request: Request, namespace: str = "default") -> list[dict[str, object]]:
    """Find tool chokepoints in graph."""
    graph = await _graph_from_request(request, namespace)
    return AttackGraphEngine(graph.graph).find_chokepoints()


@router.get("/analysis")
async def get_full_analysis(request: Request, namespace: str = "default") -> dict[str, object]:
    """Run complete graph analysis report."""
    graph = await _graph_from_request(request, namespace)
    return GraphAnalyzer(graph).full_analysis()
