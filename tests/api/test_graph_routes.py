# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API tests for graph routes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.main import create_app
from norviq.engine.graph.asset_graph import AssetGraphBuilder


class _FakeEvaluator:
    """Evaluator stub exposing graph builder."""

    def __init__(self) -> None:
        self.graph_builder = AssetGraphBuilder()
        self.graph_builder.record_tool_call("spiffe://a", "execute_sql", "allow")

    def get_graph(self, namespace: str) -> AssetGraphBuilder:
        """Return test graph for requested namespace."""
        _ = namespace
        return self.graph_builder


def _client() -> TestClient:
    """Build test client with graph-enabled evaluator state."""
    app = create_app()
    app.state.evaluator = _FakeEvaluator()
    return TestClient(app)


def test_graph_endpoints() -> None:
    """Serve graph, summary, paths, and analysis endpoints."""
    client = _client()
    try:
        assert client.get("/api/v1/graph/").status_code == 200
        assert client.get("/api/v1/graph/summary").json()["agents"] >= 1
        blast = client.get("/api/v1/graph/blast-radius/spiffe://a").json()
        assert blast["source"] == "spiffe://a"
        assert client.get("/api/v1/graph/chokepoints").status_code == 200
        assert client.get("/api/v1/graph/analysis").status_code == 200
    finally:
        client.close()
