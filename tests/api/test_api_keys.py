# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F046: /api/v1/keys issue/list/revoke (admin-only, hashed) + the api-key auth resolver.

Covers create (secret returned once, only hash stored), list (no secret), revoke, viewer 403,
and that authenticate_api_key resolves a valid key to its scoped principal but rejects revoked/bogus."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient
from jose import jwt

from norviq.api import api_keys as ak
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Tiny in-memory ApiKey store. Single-row-scoped queries are fine for these unit tests."""

    def __init__(self, rows: list) -> None:
        self.rows = rows

    async def execute(self, _stmt):
        rows = list(self.rows)
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: rows),
            scalar_one_or_none=lambda: rows[0] if rows else None,
        )

    def add(self, row) -> None:
        self.rows.append(row)

    async def commit(self) -> None:
        return None

    async def close(self) -> None:
        return None


def _client(rows: list) -> TestClient:
    app = create_app()

    async def _override():
        yield _FakeSession(rows)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token(role: str = "admin") -> str:
    return jwt.encode({"sub": "u", "role": role}, settings.api_secret_key, algorithm="HS256")


def test_create_returns_secret_once_and_stores_only_hash() -> None:
    rows: list = []
    client = _client(rows)
    resp = client.post(
        "/api/v1/keys",
        json={"name": "ci", "namespace": "default", "role": "service"},
        headers={"Authorization": f"Bearer {_token('admin')}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["key"].startswith("nrvq_") and body["role"] == "service"
    assert "key_hash" not in body  # the hash is never returned
    assert rows[0].key_hash == ak.hash_key(body["key"])  # only the hash is stored


def test_list_hides_secret_and_viewer_forbidden() -> None:
    rows: list = []
    client = _client(rows)
    client.post("/api/v1/keys", json={"name": "k"}, headers={"Authorization": f"Bearer {_token('admin')}"})
    listed = client.get("/api/v1/keys", headers={"Authorization": f"Bearer {_token('admin')}"}).json()
    assert listed and "key" not in listed[0] and "key_hash" not in listed[0]
    assert client.get("/api/v1/keys", headers={"Authorization": f"Bearer {_token('viewer')}"}).status_code == 403
    assert (
        client.post("/api/v1/keys", json={"name": "x"}, headers={"Authorization": f"Bearer {_token('viewer')}"}).status_code
        == 403
    )


def test_revoke_marks_key() -> None:
    rows: list = []
    client = _client(rows)
    created = client.post("/api/v1/keys", json={"name": "k"}, headers={"Authorization": f"Bearer {_token('admin')}"}).json()
    resp = client.delete(f"/api/v1/keys/{created['id']}", headers={"Authorization": f"Bearer {_token('admin')}"})
    assert resp.status_code == 200 and resp.json()["revoked"] is True


def test_authenticate_api_key_resolves_scoped_principal() -> None:
    full, prefix, key_hash = ak.generate_key()
    row = SimpleNamespace(
        id="1", prefix=prefix, key_hash=key_hash, name="k", namespace="team-a", role="viewer",
        revoked=False, last_used_at=None,
    )

    async def _factory():
        yield _FakeSession([row])

    principal = asyncio.run(ak.authenticate_api_key(full, session_factory=_factory))
    assert principal == {"sub": f"apikey:{prefix}", "role": "viewer", "namespace": "team-a", "name": "k"}
    assert isinstance(row.last_used_at, datetime) and row.last_used_at.tzinfo == timezone.utc


def test_authenticate_api_key_rejects_bogus_and_non_prefixed() -> None:
    async def _empty():
        yield _FakeSession([])

    assert asyncio.run(ak.authenticate_api_key("nrvq_bogus", session_factory=_empty)) is None
    assert asyncio.run(ak.authenticate_api_key("not-an-api-key", session_factory=_empty)) is None
