# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LOGIN-2: password hashing + brute-force lockout for the local username/password login.

Standalone (no auth/db imports) so the router and the boot-time seeder can both use it without a
circular import. Hashing is **bcrypt with a SHA-256 pre-hash** (the Django ``bcrypt_sha256`` pattern):
the SHA-256 digest is base64-encoded before bcrypt so an arbitrary-length password is supported
without silently hitting bcrypt's 72-byte truncation (which would let two different long passwords
collide). ``bcrypt.checkpw`` is a constant-time compare. Passlib is intentionally NOT used — its
CryptContext is broken against bcrypt 5.x. Plaintext passwords and hashes never touch the logs.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib

import bcrypt
import structlog

log = structlog.get_logger()


def _prehash(raw: str) -> bytes:
    """SHA-256 pre-hash (base64) so bcrypt never truncates a >72-byte password."""
    return base64.b64encode(hashlib.sha256(raw.encode("utf-8")).digest())


def hash_password(raw: str) -> str:
    """Return a bcrypt-sha256 hash of ``raw`` (per-hash random salt)."""
    return bcrypt.hashpw(_prehash(raw), bcrypt.gensalt()).decode("ascii")


def verify_password(raw: str, hashed: str) -> bool:
    """Constant-time verify ``raw`` against a stored hash. False (never raises) on any malformed input."""
    try:
        return bcrypt.checkpw(_prehash(raw), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


# A fixed decoy hash so a login for a NON-EXISTENT user still burns one bcrypt verify — this closes the
# timing side channel that would otherwise let an attacker enumerate valid usernames (present user →
# real verify; absent user → instant return). Computed once at import.
_DECOY_HASH = hash_password("nrvq-user-enumeration-timing-guard")


def dummy_verify(raw: str) -> None:
    """Run a throwaway verify (constant-time parity for the unknown-user path). Result is discarded."""
    verify_password(raw, _DECOY_HASH)


# --- async wrappers (CRITICAL DoS fix) -------------------------------------------------------------
#
# bcrypt is synchronous, CPU-bound, and deliberately slow (~100ms+). uvicorn runs this API single-process
# (no --workers), so a handful of concurrent unauthenticated POST /auth/login calls — even ones with a
# BAD username, since dummy_verify still burns a full bcrypt round — serialize on the one asyncio event
# loop and stall every other in-flight request on the replica. `asyncio.to_thread` moves the bcrypt call
# onto a worker thread so the loop stays free; the sync functions above are kept as-is for any non-async
# caller (the admin_reset / token_mint CLIs, and unit tests that assert on hashing directly).


async def hash_password_async(raw: str) -> str:
    """Off-event-loop ``hash_password`` — use on the request path."""
    return await asyncio.to_thread(hash_password, raw)


async def verify_password_async(raw: str, hashed: str) -> bool:
    """Off-event-loop ``verify_password`` — use on the request path. Same constant-time guarantee."""
    return await asyncio.to_thread(verify_password, raw, hashed)


async def dummy_verify_async(raw: str) -> None:
    """Off-event-loop ``dummy_verify`` — use on the request path (preserves the anti-enumeration timing)."""
    await asyncio.to_thread(dummy_verify, raw)


# --- brute-force lockout (best-effort; Redis-backed, never blocks auth if the cache is down) ---

_LOCK_PREFIX = "login-fail"


def _lock_key(username: str) -> str:
    return f"{_LOCK_PREFIX}:{username}"


async def is_locked_out(cache, username: str, *, max_attempts: int) -> bool:
    """True when the username has already hit the failed-attempt ceiling in the current window."""
    if cache is None:
        return False
    try:
        return int(await cache.peek_call_count(_lock_key(username))) >= max_attempts
    except Exception:  # pragma: no cover - lockout is defense-in-depth, never breaks login
        return False


async def register_failure(cache, username: str, *, window_s: int) -> int:
    """Count one failed attempt for the username within the window. Returns the running count (0 if no cache)."""
    if cache is None:
        return 0
    try:
        return int(await cache.incr_call_count(_lock_key(username), window_s=window_s))
    except Exception:  # pragma: no cover
        return 0


async def clear_failures(cache, username: str) -> None:
    """Reset the failed-attempt counter (called on a successful login)."""
    if cache is None:
        return
    try:
        await cache.reset_call_count(_lock_key(username))
    except Exception:  # pragma: no cover
        pass
