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
    # No-claim floor: a non-admin with NO namespace claim gets no tenant data at all.
    client = _client_as({"role": "viewer", "namespace": ""})
    try:
        assert client.get("/api/v1/attack-paths?namespace=default").status_code == 403
    finally:
        client.close()


# --- error responses must not echo the exception text (CWE-209) ------------------------------------


def _client_with_failing_db(boom: Exception) -> TestClient:
    """Client whose DB session yields OK but raises on query, so the failure happens INSIDE the route
    body and actually reaches its `except Exception` handler. (A dependency that raises on yield is
    caught by FastAPI itself and returns a generic 500 without ever entering the route — a test built
    that way passes against the vulnerable code too, i.e. proves nothing.)"""
    app = create_app()
    app.state.evaluator = _FakeEvaluator()
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default"}

    class _ExplodingSession:
        async def execute(self, *a, **kw):
            raise boom

        async def close(self):
            return None

    async def _session():
        yield _ExplodingSession()

    app.dependency_overrides[get_session] = _session
    return TestClient(app, raise_server_exceptions=False)


def test_graph_500_does_not_leak_exception_text() -> None:
    """A driver/ORM error can carry table names, query fragments or connection details — the response
    must stay generic (the full type + message + traceback is logged server-side instead)."""
    # No quotes/backslashes: JSON-escaping must not be what makes this assertion pass.
    secret = "relation api_keys does not exist at 10.0.0.5:5432 user=norviq"
    for path in ("/api/v1/asset-graph", "/api/v1/attack-paths"):
        client = _client_with_failing_db(RuntimeError(secret))
        try:
            resp = client.get(path)
            assert resp.status_code == 500, f"{path} -> {resp.status_code}"
            body = resp.text
            assert secret not in body, f"{path} leaked the exception message"
            assert "RuntimeError" not in body, f"{path} leaked the exception type"
            assert "api_keys" not in body
        finally:
            client.close()
