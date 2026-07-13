# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F046: GET /api/v1/cluster-info returns this deployment's id/name + REAL observed namespaces.

Covers happy (distinct namespaces deduped+sorted), empty (fresh install -> ["default"]), and the
non-admin scope (a namespace-claimed token sees only its own namespace).
"""

from __future__ import annotations

from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Returns the same namespace rows for every distinct-namespace SELECT (3 models)."""

    def __init__(self, namespaces: list[str]) -> None:
        self._namespaces = namespaces

    async def execute(self, _stmt):
        rows = list(self._namespaces)
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    async def close(self) -> None:
        return None


def _client(namespaces: list[str]) -> TestClient:
    app = create_app()

    async def _override():
        yield _FakeSession(namespaces)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token(role: str = "admin", namespace: str = "") -> str:
    claims = {"sub": "u", "role": role}
    if namespace:
        claims["namespace"] = namespace
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def test_cluster_info_happy_dedupes_and_sorts() -> None:
    client = _client(["payments", "default", "default", "analytics"])
    resp = client.get("/api/v1/cluster-info", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cluster_id"]  # non-empty (config or "local")
    assert body["namespaces"] == ["analytics", "default", "payments"]


def test_cluster_info_excludes_all_wildcard() -> None:
    # "all" is the reserved "All namespaces" sentinel — a fleet-wide policy seeded into namespace "all" must
    # NOT surface as a selectable tenant namespace (it would render a duplicate "All namespaces" in the console).
    client = _client(["all", "default", "payments"])
    resp = client.get("/api/v1/cluster-info", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    assert resp.json()["namespaces"] == ["default", "payments"]


def test_cluster_info_empty_returns_default() -> None:
    client = _client([])
    resp = client.get("/api/v1/cluster-info", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    assert resp.json()["namespaces"] == ["default"]


def test_cluster_info_non_admin_scoped_to_claim() -> None:
    client = _client(["payments", "default", "team-a"])
    resp = client.get(
        "/api/v1/cluster-info",
        headers={"Authorization": f"Bearer {_token(role='viewer', namespace='team-a')}"},
    )
    assert resp.status_code == 200
    assert resp.json()["namespaces"] == ["team-a"]


def test_cluster_info_requires_auth() -> None:
    client = _client(["default"])
    assert client.get("/api/v1/cluster-info").status_code in (401, 403)
