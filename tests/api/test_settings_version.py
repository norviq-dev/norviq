# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F046: GET/PUT /api/v1/settings (effective config + persisted overrides) and GET /api/v1/version
(single source). Covers happy, override merge, RBAC (viewer PUT -> 403), validation, and auth."""

from __future__ import annotations

from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Returns a preset NamespaceSettings row (or None) for the GET select; records add/commit for PUT."""

    def __init__(self, row) -> None:
        self._row = row
        self.committed = False
        self.added: list = []

    async def execute(self, _stmt):
        row = self._row
        return SimpleNamespace(scalar_one_or_none=lambda: row)

    def add(self, obj) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        return None


def _client(row=None) -> tuple[TestClient, _FakeSession]:
    app = create_app()
    session = _FakeSession(row)

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app), session


def _token(role: str = "admin") -> str:
    return jwt.encode({"sub": "u", "role": role}, settings.api_secret_key, algorithm="HS256")


def test_settings_returns_effective_config_defaults() -> None:
    client, _ = _client(row=None)  # no persisted override -> live config defaults
    resp = client.get("/api/v1/settings?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["enforcement_mode"] == settings.enforcement_mode
    assert body["trust_threshold"] == settings.trust_threshold
    assert body["rate_limit"] == settings.evaluator_rate_limit_per_window


def test_settings_persisted_override_wins() -> None:
    row = SimpleNamespace(
        namespace="default", enforcement_mode="audit", trust_threshold=0.55, rate_limit=None
    )
    client, _ = _client(row=row)
    body = client.get("/api/v1/settings?namespace=default", headers={"Authorization": f"Bearer {_token()}"}).json()
    assert body["enforcement_mode"] == "audit"  # override
    assert body["trust_threshold"] == 0.55  # override
    assert body["rate_limit"] == settings.evaluator_rate_limit_per_window  # null falls back to config
    # violation_penalty was a dead per-ns control (never reached the engine) — it must NOT be surfaced.
    assert "violation_penalty" not in body


def test_settings_put_persists_admin_only() -> None:
    client, session = _client(row=None)
    resp = client.put(
        "/api/v1/settings?namespace=default",
        json={"enforcement_mode": "audit", "trust_threshold": 0.6},
        headers={"Authorization": f"Bearer {_token('admin')}"},
    )
    assert resp.status_code == 200
    assert session.committed and len(session.added) == 1


def test_settings_put_viewer_forbidden() -> None:
    client, _ = _client(row=None)
    resp = client.put(
        "/api/v1/settings?namespace=default",
        json={"enforcement_mode": "audit"},
        headers={"Authorization": f"Bearer {_token('viewer')}"},
    )
    assert resp.status_code == 403


def test_settings_put_validation_rejects_bad_mode() -> None:
    client, _ = _client(row=None)
    resp = client.put(
        "/api/v1/settings?namespace=default",
        json={"enforcement_mode": "destroy"},
        headers={"Authorization": f"Bearer {_token('admin')}"},
    )
    assert resp.status_code == 422


def test_version_single_source() -> None:
    client, _ = _client(row=None)
    resp = client.get("/api/v1/version", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] and body["version"] != "0.0.0+unknown"
    assert body["license"] == "Apache-2.0"


def test_settings_requires_auth() -> None:
    client, _ = _client(row=None)
    assert client.get("/api/v1/settings").status_code in (401, 403)
    assert client.get("/api/v1/version").status_code in (401, 403)
