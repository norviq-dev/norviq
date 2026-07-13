# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API tests for graph routes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
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
    """Build test client with graph-enabled evaluator state (auth overridden to an admin)."""
    app = create_app()
    app.state.evaluator = _FakeEvaluator()
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default"}
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


def _client_as(user: dict) -> TestClient:
    app = create_app()
    app.state.evaluator = _FakeEvaluator()
    app.dependency_overrides[get_current_user] = lambda: user

    async def _session():
        # A stub session so the dependency resolves; the scope guard 403s before it is ever used on these paths.
        yield object()

    app.dependency_overrides[get_session] = _session
    return TestClient(app)


def test_attack_paths_cross_tenant_is_403() -> None:
    # EXHAUSTIVE-PERF-AUDIT / IDOR: the legacy GET /attack-paths discarded the caller (`_ = _user`) and fed the
    # raw ?namespace straight into SQL — any authenticated viewer could read another tenant's precomputed attack
    # paths. Scoping now refuses a foreign namespace with 403 BEFORE the DB is touched (fail-closed).
    client = _client_as({"role": "viewer", "namespace": "tenant-b"})
    try:
        resp = client.get("/api/v1/attack-paths?namespace=default")
        assert resp.status_code == 403
    finally:
        client.close()


def test_attack_paths_no_claim_viewer_is_403() -> None:
    # F-06 floor: a non-admin with NO namespace claim gets no tenant data at all.
    client = _client_as({"role": "viewer", "namespace": ""})
    try:
        assert client.get("/api/v1/attack-paths?namespace=default").status_code == 403
    finally:
        client.close()
