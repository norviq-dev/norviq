# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""AUTH-01: server-side session revocation (logout) for stateless JWTs.

Sessions are stateless HS256/OIDC JWTs with no ``jti``, so logout is implemented as a denylist keyed
by the SHA-256 of the RAW presented token (unique per token via the signature; covers login-, CLI- and
webhook-minted tokens without changing the token contract). Entries carry TTL = the token's remaining
lifetime, so the denylist can never outgrow the set of still-live tokens.

Two layers, checked on every JWT validation (``auth.get_current_user`` / ``auth.decode_token``):
- an in-process mirror (always written, always checked) — keeps revocation correct on a single-replica
  deployment even while Redis is restarting, and lets unit tests run without Redis;
- Redis (``RedisCache.revoke_token`` / ``is_token_revoked``) — the authoritative cross-replica store.

Redis failures are BEST-EFFORT by design (same deliberate posture as the login lockout counter): a
read failure fails OPEN with a warning rather than turning a Redis blip into a full auth outage
(``/readyz`` already drains the pod on Redis-down, bounding the window); a write failure at logout
still returns success — the mirror has already revoked on the only replica that exists — but logs at
ERROR with its own code (NRVQ-AUTH-14017) so incomplete cross-replica revocation is grep-able.

The raw token is never logged; only a short hash prefix (a full hash would let a log reader probe
whether a specific stolen token is revoked).
"""

from __future__ import annotations

import hashlib
import time

import structlog

log = structlog.get_logger()

# In-process mirror {token_hash: exp_epoch}. Bounded: expired entries are pruned on every write and
# check, and the cap evicts oldest-expiring entries first so it can never become a memory sink.
_mirror: dict[str, int] = {}
_MIRROR_MAX_ENTRIES = 10_000
_LOG_PREFIX_LEN = 12


def token_hash(raw_token: str) -> str:
    """SHA-256 hex of the raw presented credential — the denylist key."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _prune_mirror(now: int) -> None:
    """Drop expired entries; under cap pressure also evict the soonest-to-expire live entries."""
    expired = [h for h, exp in _mirror.items() if exp <= now]
    for h in expired:
        _mirror.pop(h, None)
    overflow = len(_mirror) - _MIRROR_MAX_ENTRIES
    if overflow > 0:
        for h in sorted(_mirror, key=_mirror.get)[:overflow]:  # type: ignore[arg-type]
            _mirror.pop(h, None)


async def revoke(cache, raw_token: str, exp: int) -> None:
    """Revoke a token until its own ``exp``: mirror always, Redis best-effort (ERROR on failure)."""
    now = int(time.time())
    ttl = max(1, int(exp) - now)
    h = token_hash(raw_token)
    _mirror[h] = now + ttl
    _prune_mirror(now)
    if cache is None:
        return
    try:
        await cache.revoke_token(h, ttl)
    except Exception as exc:  # noqa: BLE001 — revocation must never 500 a logout; mirror already holds it
        log.error(
            "nrvq.auth.revocation_store_degraded",
            op="revoke",
            token_hash_prefix=h[:_LOG_PREFIX_LEN],
            error=str(exc),
            code="NRVQ-AUTH-14017",
        )


async def is_revoked(cache, raw_token: str) -> bool:
    """True if the token was logged out. Mirror first (free), then Redis (fail-OPEN with a warning)."""
    now = int(time.time())
    _prune_mirror(now)
    h = token_hash(raw_token)
    if _mirror.get(h, 0) > now:
        return True
    if cache is None:
        return False
    try:
        return bool(await cache.is_token_revoked(h))
    except Exception as exc:  # noqa: BLE001 — deliberate fail-open: a Redis blip must not 401 every caller
        log.warning(
            "nrvq.auth.revocation_store_degraded",
            op="check",
            token_hash_prefix=h[:_LOG_PREFIX_LEN],
            error=str(exc),
            code="NRVQ-AUTH-14017",
        )
        return False
