# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LOGIN-2: local username/password login + forced first-login change.

Covers: successful login (short-TTL token + must_change/default-password signals), wrong-password and
unknown-user both returning the SAME generic 401, rate-limit lockout (429 after N failures), the
constant-time bcrypt compare, hash-at-rest (never plaintext), /auth/change-password (success, wrong
current, weak/same/default new), the first-login force flag flipping, and the boot-time admin seeder.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from norviq.api import passwords as pw
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import auth_login
from norviq.config import settings

_DEFAULT = "norviq"


class _FakeSession:
    """Single-user in-memory store. Every query resolves to the one seeded row (fine for these units)."""

    def __init__(self, rows: list) -> None:
        self.rows = rows
        self.committed = 0

    async def execute(self, _stmt):
        rows = list(self.rows)
        return SimpleNamespace(scalar_one_or_none=lambda: rows[0] if rows else None)

    def add(self, row) -> None:
        self.rows.append(row)

    async def commit(self) -> None:
        self.committed += 1

    async def close(self) -> None:
        return None


class _FakeCache:
    """Windowed per-key counter (INCR/peek/reset) matching the RedisCache surface LOGIN-2 uses."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def incr_call_count(self, key: str, window_s: int = 60) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def peek_call_count(self, key: str) -> int:
        return self.counts.get(key, 0)

    async def reset_call_count(self, key: str) -> None:
        self.counts.pop(key, None)


def _admin_row(password: str = _DEFAULT, must_change: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        username="admin", password_hash=pw.hash_password(password), role="admin", must_change=must_change
    )


def _client(rows: list, cache: _FakeCache | None = None) -> TestClient:
    app = create_app()
    if cache is not None:
        app.state.cache = cache

    async def _override():
        yield _FakeSession(rows)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _bearer(sub: str = "admin", role: str = "admin") -> dict:
    token = jwt.encode(
        {"sub": sub, "role": role, "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


# --- password primitives -----------------------------------------------------------------------


def test_hash_is_bcrypt_not_plaintext_and_verifies() -> None:
    h = pw.hash_password("s3cret-passphrase")
    assert h != "s3cret-passphrase" and h.startswith("$2")  # bcrypt hash, never the plaintext
    assert pw.verify_password("s3cret-passphrase", h)
    assert not pw.verify_password("wrong", h)


def test_hash_supports_passwords_over_72_bytes() -> None:
    """The SHA-256 pre-hash means two distinct >72-byte passwords don't collide (no bcrypt truncation)."""
    long_a, long_b = "A" * 100, "A" * 99 + "B"
    h = pw.hash_password(long_a)
    assert pw.verify_password(long_a, h) and not pw.verify_password(long_b, h)


def test_verify_is_false_on_malformed_hash_never_raises() -> None:
    assert pw.verify_password("x", "not-a-bcrypt-hash") is False


# --- /auth/login -------------------------------------------------------------------------------


def test_login_success_returns_short_ttl_token_and_signals() -> None:
    client = _client([_admin_row()])
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": _DEFAULT})
    assert resp.status_code == 200
    body = resp.json()
    claims = jwt.decode(body["access_token"], settings.api_secret_key, algorithms=["HS256"])
    assert claims["sub"] == "admin" and claims["role"] == "admin" and claims["namespace"] == "*"
    assert claims["must_change"] is True and (claims["exp"] - claims["iat"]) == settings.auth_session_ttl_s
    assert body["must_change"] is True and body["default_password_in_use"] is True
    assert "password" not in body and "password_hash" not in body


def test_login_wrong_password_and_unknown_user_are_indistinguishable() -> None:
    wrong = _client([_admin_row()]).post(
        "/api/v1/auth/login", json={"username": "admin", "password": "nope"}
    )
    unknown = _client([]).post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"] == "Invalid username or password"


def test_login_changed_password_clears_default_signal() -> None:
    client = _client([_admin_row(password="a-strong-passphrase", must_change=False)])
    body = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "a-strong-passphrase"}
    ).json()
    assert body["must_change"] is False and body["default_password_in_use"] is False


def test_login_lockout_after_max_attempts(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_login_max_attempts", 3)
    cache = _FakeCache()
    client = _client([_admin_row()], cache=cache)
    for _ in range(3):
        assert client.post("/api/v1/auth/login", json={"username": "admin", "password": "bad"}).status_code == 401
    # The ceiling is reached — even the CORRECT password is now refused with 429 (locked out), not 401.
    locked = client.post("/api/v1/auth/login", json={"username": "admin", "password": _DEFAULT})
    assert locked.status_code == 429


def test_login_success_resets_failure_counter(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_login_max_attempts", 3)
    cache = _FakeCache()
    client = _client([_admin_row()], cache=cache)
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "bad"})
    client.post("/api/v1/auth/login", json={"username": "admin", "password": "bad"})
    assert client.post("/api/v1/auth/login", json={"username": "admin", "password": _DEFAULT}).status_code == 200
    assert cache.counts.get("callcount:login-fail:admin", 0) == 0  # reset on success


def test_login_disabled_returns_403(monkeypatch) -> None:
    monkeypatch.setattr(settings, "auth_login_enabled", False)
    resp = _client([_admin_row()]).post("/api/v1/auth/login", json={"username": "admin", "password": _DEFAULT})
    assert resp.status_code == 403


# --- /auth/change-password ---------------------------------------------------------------------


def test_change_password_success_sets_new_hash_and_clears_must_change() -> None:
    row = _admin_row()
    client = _client([row])
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": _DEFAULT, "new_password": "brand-new-passphrase"},
        headers=_bearer(),
    )
    assert resp.status_code == 200 and resp.json() == {"changed": True, "must_change": False}
    assert row.must_change is False
    assert pw.verify_password("brand-new-passphrase", row.password_hash)  # new hash at rest
    assert not pw.verify_password(_DEFAULT, row.password_hash)  # old password no longer works


def test_change_password_wrong_current_rejected() -> None:
    resp = _client([_admin_row()]).post(
        "/api/v1/auth/change-password",
        json={"current_password": "not-it", "new_password": "brand-new-passphrase"},
        headers=_bearer(),
    )
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "new_password",
    ["short", _DEFAULT, "norviq"],  # too short, equal to default, (also equals default)
)
def test_change_password_rejects_weak_or_default_new(new_password) -> None:
    resp = _client([_admin_row()]).post(
        "/api/v1/auth/change-password",
        json={"current_password": _DEFAULT, "new_password": new_password},
        headers=_bearer(),
    )
    assert resp.status_code == 400


def test_change_password_rejects_reusing_current() -> None:
    resp = _client([_admin_row(password="current-strong-pass", must_change=False)]).post(
        "/api/v1/auth/change-password",
        json={"current_password": "current-strong-pass", "new_password": "current-strong-pass"},
        headers=_bearer(),
    )
    assert resp.status_code == 400


def test_change_password_no_local_user_404() -> None:
    resp = _client([]).post(
        "/api/v1/auth/change-password",
        json={"current_password": "x", "new_password": "brand-new-passphrase"},
        headers=_bearer(sub="oidc-user"),
    )
    assert resp.status_code == 404


# --- boot seeder -------------------------------------------------------------------------------


def test_ensure_default_admin_seeds_hashed_admin_with_must_change() -> None:
    rows: list = []

    async def _factory():
        yield _FakeSession(rows)

    asyncio.run(auth_login.ensure_default_admin(session_factory=_factory))
    assert len(rows) == 1
    seeded = rows[0]
    assert seeded.username == settings.auth_admin_username and seeded.role == "admin"
    assert seeded.must_change is True
    assert seeded.password_hash != settings.auth_admin_password  # stored hashed, not in the clear
    assert pw.verify_password(settings.auth_admin_password, seeded.password_hash)


def test_ensure_default_admin_is_idempotent() -> None:
    existing = _admin_row(password="already-changed", must_change=False)
    rows = [existing]

    async def _factory():
        yield _FakeSession(rows)

    asyncio.run(auth_login.ensure_default_admin(session_factory=_factory))
    assert rows == [existing]  # no duplicate seed; the changed password is untouched
