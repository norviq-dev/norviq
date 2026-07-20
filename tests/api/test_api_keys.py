# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""/api/v1/keys issue/list/revoke (admin-only, hashed) + the api-key auth resolver.

Covers create (secret returned once, only hash stored), list (no secret), revoke, viewer 403,
and that authenticate_api_key resolves a valid key to its scoped principal but rejects revoked/bogus."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

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
    return jwt.encode(
        {"sub": "u", "role": role, "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


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


class _FakeCache:
    """Minimal Redis-counter stub (per-key INCR with a window)."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def incr_call_count(self, key: str, window_s: int = 60) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


def test_authfail_throttle_counts_per_prefix() -> None:
    """Each failed nrvq_ auth increments a per-prefix counter (keyed on the display prefix)."""
    cache = _FakeCache()

    async def _empty():
        yield _FakeSession([])

    for _ in range(3):
        asyncio.run(ak.authenticate_api_key("nrvq_abcd1234xyz", session_factory=_empty, cache=cache))
    # one display-prefix accumulated all 3 failures
    assert list(cache.counts.values()) == [3]
    assert next(iter(cache.counts)).startswith("apikey-authfail:nrvq_")


def test_constant_time_compare_rejects_hash_mismatch() -> None:
    """Defense-in-depth — a row whose stored hash != the computed digest is rejected (compare_digest)."""
    full, prefix, _ = ak.generate_key()
    row = SimpleNamespace(id="1", prefix=prefix, key_hash="deadbeef" * 8, name="k",
                          namespace="default", role="viewer", revoked=False, last_used_at=None)

    async def _factory():
        yield _FakeSession([row])

    assert asyncio.run(ak.authenticate_api_key(full, session_factory=_factory)) is None


# --- RETENTION: API-key expiry (expires_at; NULL = never — legacy keys keep working) ---------------


def test_authenticate_rejects_expired_key() -> None:
    from datetime import timedelta

    full, prefix, key_hash = ak.generate_key()
    row = SimpleNamespace(
        id="1", prefix=prefix, key_hash=key_hash, name="k", namespace="team-a", role="viewer",
        revoked=False, last_used_at=None,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=5),
    )

    async def _factory():
        yield _FakeSession([row])

    assert asyncio.run(ak.authenticate_api_key(full, session_factory=_factory)) is None
    assert row.last_used_at is None  # rejected BEFORE the last-used stamp — expired == unauthenticated


def test_authenticate_allows_legacy_key_without_expiry() -> None:
    # Keys issued before the expires_at column existed (attribute absent entirely) must keep working.
    full, prefix, key_hash = ak.generate_key()
    row = SimpleNamespace(
        id="1", prefix=prefix, key_hash=key_hash, name="legacy", namespace="default", role="viewer",
        revoked=False, last_used_at=None,
    )

    async def _factory():
        yield _FakeSession([row])

    principal = asyncio.run(ak.authenticate_api_key(full, session_factory=_factory))
    assert principal is not None and principal["sub"] == f"apikey:{prefix}"


def test_create_key_defaults_to_configured_ttl_and_zero_means_never() -> None:
    from datetime import timedelta

    rows: list = []
    client = _client(rows)
    # Omitted expires_in_days -> server default (api_key_default_ttl_days, 90).
    body = client.post(
        "/api/v1/keys", json={"name": "d"}, headers={"Authorization": f"Bearer {_token('admin')}"}
    ).json()
    assert body["expires_at"] is not None
    got = datetime.fromisoformat(body["expires_at"])
    expected = datetime.now(timezone.utc) + timedelta(days=settings.api_key_default_ttl_days)
    assert abs((got - expected).total_seconds()) < 300
    # Explicit 0 -> never expires (an intentional service-key choice).
    body0 = client.post(
        "/api/v1/keys", json={"name": "svc", "expires_in_days": 0},
        headers={"Authorization": f"Bearer {_token('admin')}"},
    ).json()
    assert body0["expires_at"] is None
    # Explicit N -> now + N days.
    body7 = client.post(
        "/api/v1/keys", json={"name": "wk", "expires_in_days": 7},
        headers={"Authorization": f"Bearer {_token('admin')}"},
    ).json()
    got7 = datetime.fromisoformat(body7["expires_at"])
    assert abs((got7 - (datetime.now(timezone.utc) + timedelta(days=7))).total_seconds()) < 300
