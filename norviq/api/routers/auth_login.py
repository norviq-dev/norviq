# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Local username/password login — the PRIMARY no-IdP path.

On success ``/auth/login``
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
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
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
from norviq.api.rate_limit import _client_ip
from norviq.api.session_revocation import is_revoked, revoke, token_hash
from norviq.api.token_mint import mint_session_token
from norviq.config import settings

log = structlog.get_logger()
router = APIRouter()

# Deliberately identical message for "no such user" and "wrong password" so a caller cannot tell which
# half failed (no username enumeration via the error body — pairs with the dummy_verify timing guard).
# How much harder a DISTRIBUTED attempt has to work to lock one account out. The per-(username, IP)
# ceiling is the real throttle; this is the backstop for an attacker spread across many addresses, and
# it is deliberately loose — a tight value would reintroduce the remote-lockout DoS it exists beside.
_USERNAME_LOCK_MULTIPLIER = 10

_INVALID_CREDS = "Invalid username or password"


class LoginRequest(BaseModel):
    """Username/password login body."""

    # Tight caps = the authoritative control (the UI maxLength is client-side and trivially bypassed).
    # 64/128 comfortably fits any real credential (NIST 800-63B: permit >=64-char passwords) while shrinking
    # the attack surface — no oversized body to log, buffer, or probe. Body-size 413 + bcrypt-sha256 prehash
    # already blunt the long-password hashing DoS; these bounds close the rest.
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    """Authenticated password change (re-checks the current password)."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


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

    # LOCK PER (USERNAME, SOURCE IP), NOT PER USERNAME (F-044).
    #
    # Keyed on the username alone, the throttle was a remote lockout of any account whose name you can
    # guess. Measured: five bad `admin` logins locked the REAL admin out for ~5 minutes — three
    # correct-password logins returned 429 before one succeeded. An availability control that an
    # unauthenticated attacker can aim at the operator is a denial-of-service primitive, and the
    # operator it locks out is precisely the person who would respond to the attack.
    #
    # Adding the source IP means an attacker's attempts exhaust their OWN bucket; the legitimate
    # operator, from a different address, is untouched. `_client_ip` is reused rather than reading
    # X-Forwarded-For here, because that header is caller-writable: keying on it would let an attacker
    # rotate the header for a fresh bucket per request and never reach the ceiling at all. It believes
    # XFF only behind a trusted proxy and otherwise uses the unforgeable TCP peer.
    #
    # A per-username counter is KEPT alongside, at a much higher ceiling, so a distributed attempt
    # spread across many addresses is still bounded — it just now costs an attacker
    # `_USERNAME_LOCK_MULTIPLIER`x more requests to deny one operator, instead of five.
    ip = _client_ip(request.scope)
    per_ip_key = f"{username}|{ip}"
    if await is_locked_out(cache, per_ip_key, max_attempts=settings.auth_login_max_attempts):
        log.warning("nrvq.auth.login_locked", user=username, source_ip=ip, scope="ip", code="NRVQ-AUTH-14012")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )
    if await is_locked_out(
        cache, username, max_attempts=settings.auth_login_max_attempts * _USERNAME_LOCK_MULTIPLIER
    ):
        log.warning("nrvq.auth.login_locked", user=username, source_ip=ip, scope="username",
                    code="NRVQ-AUTH-14012")
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
        # Both counters advance: the per-IP one is what locks this attacker out, the per-username one
        # is the distributed-attempt backstop.
        count = await register_failure(cache, per_ip_key, window_s=settings.auth_login_window_s)
        await register_failure(cache, username, window_s=settings.auth_login_window_s)
        log.warning("nrvq.auth.login_failed", user=username, attempts=count, code="NRVQ-AUTH-14012")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_INVALID_CREDS)

    await clear_failures(cache, per_ip_key)
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
    """Log out — revoke the presented session token server-side until its own expiry.

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
    # exp is guaranteed present: _validate_token now requires it (auth._validate_token, options require exp),
    # so a no-exp token 401s above and never reaches here. The +1 fallback is defensive belt-and-suspenders.
    exp = int(claims.get("exp") or 0) or int(time.time()) + 1
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
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    creds: HTTPAuthorizationCredentials = Depends(security),
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
    # REVOKE THE TOKEN THAT MADE THIS REQUEST (F-044). A password change is what a user does when they
    # believe their credentials are compromised, and it left every already-issued session — including
    # an attacker's — valid until its own `exp`. The new password locked no one out; it only stopped
    # them getting a NEW token. That is the opposite of what the action means.
    #
    # Only the presented token can be revoked here: the denylist is keyed by the hash of the raw
    # token, so sessions on other devices are not reachable without a per-user token epoch (a bigger
    # change to the token contract, noted in the commit). Revoking this one closes the case that
    # matters most — the browser the user just used, and any copy of that same token.
    #
    # Best-effort by design: a revocation-store failure must not undo a password change that is
    # already committed. `revoke` writes the in-process mirror first and logs NRVQ-AUTH-14017 on a
    # Redis failure, so an incomplete cross-replica revocation is greppable rather than invisible.
    if creds is not None:
        try:
            old_exp = int((user.get("exp") or 0)) or int(time.time()) + int(settings.auth_session_ttl_s)
            await revoke(_cache(request), creds.credentials, old_exp)
        except Exception as exc:  # noqa: BLE001 — the password IS changed; never fail the response now
            log.error(
                "nrvq.auth.change_password_revoke_failed",
                user=username,
                error=str(exc),
                code="NRVQ-AUTH-14020",
            )
    # Mint a FRESH session token with must_change cleared and return it, so the caller can swap off the
    # login-time token immediately. The must_change gate (auth._validate_token, NRVQ-AUTH-14018) reads the
    # TOKEN CLAIM, not the DB row — so without a new token the client keeps a must_change=True JWT and is
    # 403'd on every gated route despite a successful change, until a full re-login. Mirrors /auth/login.
    role = str(row.role or "viewer").lower()
    namespace = _namespace_for(role)
    token = mint_session_token(
        sub=username,
        role=role,
        namespace=namespace,
        must_change=False,
        ttl_seconds=settings.auth_session_ttl_s,
    )
    return {
        "changed": True,
        "must_change": False,
        "access_token": token,
        "token_type": "bearer",
        "role": role,
        "namespace": namespace,
    }


async def ensure_default_admin(session_factory=get_session) -> None:
    """Boot-time seed: create the default admin (must_change=True) if no such user exists.

    Idempotent across restarts AND across concurrent replicas — a restart never overwrites a changed
    password, and two pods booting at once do not collide. Skipped when local login is disabled.
    `session_factory` is injectable for tests; it opens its own session like the api-key resolver.

    The SELECT is only a fast path that avoids a bcrypt hash on every boot. It is NOT the guard: the
    chart runs `api.replicas: 2` by default, so on a fresh install both pods ran this at once, both saw
    no admin, and both inserted — one died on startup with

        duplicate key value violates unique constraint "users_username_key"
        DETAIL:  Key (username)=(admin) already exists.
        ERROR:    Application startup failed. Exiting.

    which self-heals on restart and so looked harmless, while actually making a fresh install
    nondeterministic (a crash backoff can outlast `helm install --wait --atomic` and roll it back).
    ON CONFLICT DO NOTHING makes the write itself the guard. DO NOTHING, never DO UPDATE: the loser must
    not overwrite the winner's row, and on a later boot it must not clobber a password the operator has
    since changed.
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
        result = await session.execute(
            pg_insert(User.__table__)
            .values(
                username=settings.auth_admin_username,
                password_hash=await hash_password_async(settings.auth_admin_password),
                role="admin",
                must_change=True,
            )
            .on_conflict_do_nothing(index_elements=[User.__table__.c.username])
        )
        await session.commit()
        if result.rowcount:
            log.info("nrvq.auth.default_admin_seeded", user=settings.auth_admin_username, code="NRVQ-AUTH-14013")
        else:
            # Another replica won the race. Not an error — the admin exists, which is the desired state.
            log.info(
                "nrvq.auth.default_admin_seed_conflict", user=settings.auth_admin_username,
                code="NRVQ-AUTH-14014",
            )
    finally:
        await provider.aclose()
