# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""DEF-044 fail-on-bug: the HS256 decode must REQUIRE an `exp` claim.

Pre-fix (auth._validate_token HS256 branch), ``jwt.decode`` was called WITHOUT
``options={"require": ["exp"]}``, so PyJWT only verified ``exp`` when present and never *required* it.
A validly-signed HS256 token minted with NO ``exp`` was therefore:
  * immortal — accepted forever (never expires), and
  * logout-proof — ``/auth/logout`` falls back to a ~1s revocation TTL for a no-exp token
    (auth_login.py), so the session is replayable ~1s after logout.

The OIDC branch already passed ``options={"require": ["exp"], ...}``; this closes the same hole on the
legacy-HS256 path. Every legitimate mint sets ``exp`` (token_mint.mint_admin_token /
mint_session_token), so requiring it rejects only forged/no-exp tokens.

These tests FAIL on the pre-fix code (a no-exp token gets 200 / validates) and PASS on the fix (401 /
JWTError). A control token WITH exp still works, proving no regression.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient
from jwt import PyJWTError as JWTError

from norviq.api import passwords as pw
from norviq.api import session_revocation as sr
from norviq.api.auth import _validate_token, decode_token, get_current_user
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
    """Single-user in-memory store (same shape as test_auth_logout)."""

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
    def __init__(self) -> None:
        self.revoked: dict[str, int] = {}

    async def revoke_token(self, token_hash: str, ttl_s: int) -> None:
        self.revoked[token_hash] = ttl_s

    async def is_token_revoked(self, token_hash: str) -> bool:
        return token_hash in self.revoked


def _admin_row() -> SimpleNamespace:
    # role=admin, must_change=False so a valid token reaches protected routes without the H1 lock.
    return SimpleNamespace(
        username="admin", password_hash=pw.hash_password(_DEFAULT), role="admin", must_change=False
    )


def _client() -> TestClient:
    app = create_app()
    app.state.cache = _FakeRevocationCache()

    async def _override():
        yield _FakeSession([_admin_row()])

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _mint_no_exp() -> str:
    """A validly-signed HS256 token with NO exp claim — the DEF-044 immortal/logout-proof token."""
    return jwt.encode(
        {"sub": "admin", "role": "admin", "namespace": "*"},
        settings.api_secret_key,
        algorithm="HS256",
    )


def _mint_with_exp(ttl: int = 600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": "admin", "role": "admin", "namespace": "*", "iat": now, "exp": now + ttl},
        settings.api_secret_key,
        algorithm="HS256",
    )


# --- HTTP-level fail-on-bug (get_current_user via /api/v1/me) -------------------------------------


def test_no_exp_token_is_rejected_on_protected_route() -> None:
    """Pre-fix: a no-exp HS256 token was accepted -> 200 (immortal). Must be 401."""
    client = _client()
    headers = {"Authorization": f"Bearer {_mint_no_exp()}"}
    resp = client.get("/api/v1/me", headers=headers)
    assert resp.status_code == 401  # was 200 on the old code — the immortal-token defect
    assert resp.json()["detail"] == "Invalid token"


def test_token_with_exp_still_works_no_regression() -> None:
    """Control: a normally-minted token (with exp) must still authenticate."""
    client = _client()
    headers = {"Authorization": f"Bearer {_mint_with_exp()}"}
    assert client.get("/api/v1/me", headers=headers).status_code == 200


def test_no_exp_token_cannot_even_reach_logout() -> None:
    """Pre-fix: /auth/logout validated a no-exp token (200) then revoked it with only a ~1s TTL, so it
    was replayable ~1s later (logout defeated). Post-fix it never validates -> 401, so the ~1s
    revocation window that defeated logout is gone entirely."""
    client = _client()
    headers = {"Authorization": f"Bearer {_mint_no_exp()}"}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 401


# --- unit-level fail-on-bug (the shared validator + the websocket decode path) -------------------


async def test_validate_token_rejects_missing_exp() -> None:
    """_validate_token is the shared HS256/OIDC validator; the HS256 branch must require exp."""
    with pytest.raises(JWTError):
        await _validate_token(_mint_no_exp())
    # Control: with exp it validates and returns the claims.
    claims = await _validate_token(_mint_with_exp())
    assert claims["sub"] == "admin"


async def test_decode_token_rejects_missing_exp() -> None:
    """decode_token backs the /ws/audit query-param path — a no-exp token must not open the socket."""
    with pytest.raises(JWTError):
        await decode_token(_mint_no_exp())


async def test_get_current_user_rejects_missing_exp() -> None:
    """Direct (non-HTTP) get_current_user call: a no-exp token raises 401."""
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=_mint_no_exp())
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(creds=creds, request=None)
    assert exc_info.value.status_code == 401
