# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""AUTH-01 regression: /auth/logout + server-side session invalidation.

Fail-on-bug: on the pre-fix code POST /api/v1/auth/logout was 404 and the same token kept returning
200 on /api/v1/me — these tests fail there and pass on the fix. Covers: the logout->401 flip on /me,
denylist TTL == the token's remaining lifetime, JWT-only semantics (missing/garbage/API-key creds and
double logout all 401), Redis-down behavior (logout still revokes via the in-process mirror; the
revocation CHECK fails open), decode_token (the /ws/audit path) rejecting a logged-out token, and the
mirror's prune/cap bounds.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from jose import JWTError, jwt

from norviq.api import session_revocation as sr
from norviq.api import passwords as pw
from norviq.api.auth import decode_token
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings

_DEFAULT = "norviq"


@pytest.fixture(autouse=True)
def _clean_mirror():
    """The in-process revocation mirror is module-global — isolate every test."""
    sr._mirror.clear()
    yield
    sr._mirror.clear()


class _FakeSession:
    """Single-user in-memory store (same shape as test_auth_login)."""

    def __init__(self, rows: list) -> None:
        self.rows = rows

    async def execute(self, _stmt):
        rows = list(self.rows)
        return SimpleNamespace(scalar_one_or_none=lambda: rows[0] if rows else None)

    async def commit(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _FakeRevocationCache:
    """Matches the RedisCache revocation surface; records the TTL the route computed."""

    def __init__(self) -> None:
        self.revoked: dict[str, int] = {}

    async def revoke_token(self, token_hash: str, ttl_s: int) -> None:
        self.revoked[token_hash] = ttl_s

    async def is_token_revoked(self, token_hash: str) -> bool:
        return token_hash in self.revoked


class _BrokenCache:
    """Redis down: every denylist op raises."""

    async def revoke_token(self, token_hash: str, ttl_s: int) -> None:
        raise ConnectionError("redis down")

    async def is_token_revoked(self, token_hash: str) -> bool:
        raise ConnectionError("redis down")


def _admin_row() -> SimpleNamespace:
    return SimpleNamespace(
        username="admin", password_hash=pw.hash_password(_DEFAULT), role="admin", must_change=True
    )


def _client(cache=None) -> TestClient:
    app = create_app()
    app.state.cache = cache if cache is not None else _FakeRevocationCache()

    async def _override():
        yield _FakeSession([_admin_row()])

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _mint(ttl: int = 600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": "admin", "role": "admin", "namespace": "*", "iat": now, "exp": now + ttl},
        settings.api_secret_key,
        algorithm="HS256",
    )


def _login(client: TestClient) -> str:
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": _DEFAULT})
    assert resp.status_code == 200
    return resp.json()["access_token"]


# --- the AUTH-01 fail-on-bug regression ----------------------------------------------------------


def test_logout_exists_and_invalidates_the_session() -> None:
    """Pre-fix: logout was 404 and /me stayed 200 with the same token. Both must flip."""
    client = _client()
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/me", headers=headers).status_code == 200
    out = client.post("/api/v1/auth/logout", headers=headers)
    assert out.status_code == 200  # was 404 on the old code
    assert out.json() == {"logged_out": True}
    after = client.get("/api/v1/me", headers=headers)
    assert after.status_code == 401  # was 200 on the old code — the actual security defect
    assert after.json()["detail"] == "Session has been logged out"


def test_logout_denylist_ttl_matches_remaining_token_lifetime() -> None:
    cache = _FakeRevocationCache()
    client = _client(cache)
    token = _mint(ttl=600)
    assert client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert len(cache.revoked) == 1
    ttl = next(iter(cache.revoked.values()))
    assert 595 <= ttl <= 600  # TTL = exp - now: the entry dies exactly when the token would


def test_logout_requires_a_valid_jwt() -> None:
    client = _client()
    assert client.post("/api/v1/auth/logout").status_code == 401  # no credential
    assert client.post("/api/v1/auth/logout", headers={"Authorization": "Bearer garbage"}).status_code == 401
    # An nrvq_ API key is NOT a session: key lifecycle is DELETE /keys/{id}, never logout.
    assert client.post("/api/v1/auth/logout", headers={"Authorization": "Bearer nrvq_abc123"}).status_code == 401


def test_second_logout_is_401_session_already_gone() -> None:
    client = _client()
    headers = {"Authorization": f"Bearer {_mint()}"}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 401


def test_logout_with_redis_down_still_revokes_via_mirror() -> None:
    """Q3 decision: Redis write failure -> still 200 (the mirror holds the revocation on this replica)."""
    client = _client(_BrokenCache())
    token = _login(client)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/me", headers=headers).status_code == 401  # mirror rejects despite Redis down


def test_revocation_check_fails_open_when_redis_down_and_not_in_mirror() -> None:
    """Q2 decision: a Redis blip must not 401 every caller (matches the lockout best-effort posture)."""
    client = _client(_BrokenCache())
    token = _login(client)
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200


# --- decode_token (the /ws/audit connect path) ---------------------------------------------------


async def test_decode_token_rejects_a_logged_out_token() -> None:
    cache = _FakeRevocationCache()
    token = _mint()
    assert (await decode_token(token, cache=cache))["sub"] == "admin"
    await sr.revoke(cache, token, exp=int(time.time()) + 600)
    with pytest.raises(JWTError, match="logged out"):
        await decode_token(token, cache=cache)


async def test_decode_token_consults_mirror_even_without_cache() -> None:
    token = _mint()
    await sr.revoke(None, token, exp=int(time.time()) + 600)
    with pytest.raises(JWTError, match="logged out"):
        await decode_token(token)  # positional-compatible: no cache arg at all


# --- session_revocation primitives ---------------------------------------------------------------


async def test_mirror_prunes_expired_entries() -> None:
    sr._mirror[sr.token_hash("old-token")] = int(time.time()) - 10  # entry whose token has expired
    assert await sr.is_revoked(None, "old-token") is False
    assert sr._mirror == {}  # pruned, not lingering


async def test_mirror_cap_evicts_soonest_to_expire_first() -> None:
    now = int(time.time())
    for i in range(sr._MIRROR_MAX_ENTRIES):
        sr._mirror[f"h{i}"] = now + 1000 + i
    await sr.revoke(None, "one-more", exp=now + 5000)
    assert len(sr._mirror) <= sr._MIRROR_MAX_ENTRIES
    assert sr._mirror.get(sr.token_hash("one-more"))  # the new revocation always survives eviction
    assert "h0" not in sr._mirror  # the soonest-to-expire entry was evicted


async def test_is_revoked_prefers_mirror_over_redis() -> None:
    cache = _FakeRevocationCache()
    await sr.revoke(cache, "tok", exp=int(time.time()) + 60)
    assert await sr.is_revoked(_BrokenCache(), "tok") is True  # mirror answers before Redis is consulted
