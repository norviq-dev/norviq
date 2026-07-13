# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LOGIN-2: local username/password login — the PRIMARY no-IdP path.

Replaces the CLI/paste-token quick-start as the default first-login experience. On success ``/auth/login``
returns a SHORT-TTL HS256 session token (role/namespace claims, signed with the existing api_secret_key).
Passwords are verified with a constant-time bcrypt compare against a stored hash — never in the clear, never
logged. A per-username Redis counter provides rate-limiting + lockout (backoff) after repeated failures. The
seeded default admin is forced to change its password on first login (``must_change``); ``/auth/change-password``
re-checks the current password before setting the new hash.

The CLI/token mint (``token_mint``) is retained for automation; OIDC SSO (``auth._validate_oidc``) is retained
for enterprise. These routes mount under ``/api/v1`` (proxied by the console nginx ``location /api/``); the SPA
keeps its own ``/auth/callback`` route for the OIDC redirect, which is why these are NOT bare ``/auth/*`` paths.
"""

from __future__ import annotations

import time

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import _validate_token, get_current_user, security
from norviq.api.db.models import User
from norviq.api.db.session import get_session
from norviq.api.passwords import (
    clear_failures,
    dummy_verify_async,
    hash_password_async,
    is_locked_out,
    register_failure,
    verify_password_async,
)
from norviq.api.session_revocation import is_revoked, revoke, token_hash
from norviq.api.token_mint import mint_session_token
from norviq.config import settings

log = structlog.get_logger()
router = APIRouter()

# Deliberately identical message for "no such user" and "wrong password" so a caller cannot tell which
# half failed (no username enumeration via the error body — pairs with the dummy_verify timing guard).
_INVALID_CREDS = "Invalid username or password"


class LoginRequest(BaseModel):
    """Username/password login body."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class ChangePasswordRequest(BaseModel):
    """Authenticated password change (re-checks the current password)."""

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


def _cache(request: Request):
    """The app's Redis cache (for lockout), or None when unavailable — lockout is best-effort."""
    state = getattr(getattr(request, "app", None), "state", None)
    return getattr(state, "cache", None) if state is not None else None


def _namespace_for(role: str) -> str:
    """Admin is namespace-agnostic ('*'); any other local role gets no tenant scope by default."""
    return "*" if role == "admin" else ""


@router.post("/auth/login")
async def login(
    body: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Authenticate a username/password and return a short-TTL session token.

    Fail-safe: local login can be disabled (403). Lockout is checked BEFORE the password compare so a
    locked username cannot be probed further. A missing user still burns one bcrypt verify (dummy_verify)
    to keep the timing indistinguishable from a wrong password.
    """
    if not settings.auth_login_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Local login is disabled")
    cache = _cache(request)
    username = body.username.strip()

    if await is_locked_out(cache, username, max_attempts=settings.auth_login_max_attempts):
        log.warning("nrvq.auth.login_locked", user=username, code="NRVQ-AUTH-14012")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )

    row = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
    # CRITICAL DoS fix: bcrypt is synchronous/CPU-bound — run it off the single asyncio event loop
    # (asyncio.to_thread) so a burst of concurrent logins (even bad usernames) cannot stall the replica.
    if row is None or not await verify_password_async(body.password, row.password_hash):
        if row is None:
            await dummy_verify_async(body.password)  # constant-time parity for the unknown-user path
        count = await register_failure(cache, username, window_s=settings.auth_login_window_s)
        log.warning("nrvq.auth.login_failed", user=username, attempts=count, code="NRVQ-AUTH-14012")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDS)

    await clear_failures(cache, username)
    role = str(row.role or "viewer").lower()
    namespace = _namespace_for(role)
    token = mint_session_token(
        sub=username,
        role=role,
        namespace=namespace,
        must_change=bool(row.must_change),
        ttl_seconds=settings.auth_session_ttl_s,
    )
    # "Default password in use" (drives the loud banner) is a stronger signal than must_change alone: it is
    # only true while the account still verifies against the shipped default. Computed with the same
    # constant-time compare; the plaintext default is never logged.
    default_in_use = bool(row.must_change) and await verify_password_async(
        settings.auth_default_admin_password, row.password_hash
    )
    log.info(
        "nrvq.auth.login_ok",
        user=username,
        role=role,
        must_change=bool(row.must_change),
        code="NRVQ-AUTH-14010",
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": role,
        "namespace": namespace,
        "must_change": bool(row.must_change),
        "default_password_in_use": default_in_use,
    }


@router.post("/auth/logout")
async def logout(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """AUTH-01: log out — revoke the presented session token server-side until its own expiry.

    JWT-only by design: the raw credential is validated directly (not via get_current_user) so an
    ``nrvq_`` API key gets a 401 here — key lifecycle is ``DELETE /keys/{id}``, not logout. An
    already-revoked token also 401s (the session is gone; the client has nothing left to log out).
    The denylist key is a hash of the token itself, so the token contract (no jti) is unchanged.
    """
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        claims = await _validate_token(creds.credentials)
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    cache = _cache(request)
    if await is_revoked(cache, creds.credentials):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been logged out")
    exp = int(claims.get("exp") or 0) or int(time.time()) + 1  # a JWT without exp dies immediately
    await revoke(cache, creds.credentials, exp)
    log.info(
        "nrvq.auth.logout_ok",
        user=claims.get("sub"),
        token_hash_prefix=token_hash(creds.credentials)[:12],
        code="NRVQ-AUTH-14015",
    )
    return {"logged_out": True}


def _validate_new_password(new_password: str, *, current_password: str) -> None:
    """Reject a weak/unchanged/default new password (fail-closed before we write the hash)."""
    if len(new_password) < settings.auth_min_password_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"New password must be at least {settings.auth_min_password_length} characters.",
        )
    if new_password == current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password.",
        )
    if new_password == settings.auth_default_admin_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must not be the default password.",
        )


@router.post("/auth/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Change the authenticated local user's password: re-check current, validate new, set hash, clear must_change."""
    username = str(user.get("sub") or "")
    row = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
    # Only local-login users have a password to change (OIDC/api-key principals have no row here).
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No local password for this account")
    if not await verify_password_async(body.current_password, row.password_hash):
        log.warning("nrvq.auth.change_password_denied", user=username, code="NRVQ-AUTH-14012")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    _validate_new_password(body.new_password, current_password=body.current_password)
    row.password_hash = await hash_password_async(body.new_password)
    row.must_change = False
    await session.commit()
    log.info("nrvq.auth.password_changed", user=username, code="NRVQ-AUTH-14011")
    return {"changed": True, "must_change": False}


async def ensure_default_admin(session_factory=get_session) -> None:
    """Boot-time seed: create the default admin (must_change=True) if no such user exists.

    Idempotent — a restart never overwrites a changed password. Skipped when local login is disabled.
    `session_factory` is injectable for tests; it opens its own session like the api-key resolver.
    """
    if not settings.auth_login_enabled:
        return
    provider = session_factory()
    session = await provider.__anext__()
    try:
        existing = (
            await session.execute(select(User).where(User.username == settings.auth_admin_username))
        ).scalar_one_or_none()
        if existing is not None:
            return
        session.add(
            User(
                username=settings.auth_admin_username,
                password_hash=await hash_password_async(settings.auth_admin_password),
                role="admin",
                must_change=True,
            )
        )
        await session.commit()
        log.info("nrvq.auth.default_admin_seeded", user=settings.auth_admin_username, code="NRVQ-AUTH-14013")
    finally:
        await provider.aclose()
