# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Server-side session revocation (logout) for stateless JWTs.

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

# How long the revocation store may be unreachable before `is_revoked` stops guessing and starts
# refusing. Long enough to cover a Redis restart or failover — the blip this fail-open exists for, and
# the one /readyz already drains the pod for — and far shorter than the lifetime of a session token,
# so a sustained outage cannot leave revocation quietly disabled for hours. Module-level rather than
# per-process state so the two callers share one clock.
_REVOCATION_GRACE_S = 30.0
_degraded_since: float | None = None


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
        revoked = bool(await cache.is_token_revoked(h))
    except Exception as exc:  # noqa: BLE001 — degradation is BOUNDED below, not unconditional
        # BOUNDED FAIL-OPEN (F-044). This used to fail open unconditionally, which meant a logged-out
        # token kept working for as long as Redis was unreachable — indefinitely, and silently, since
        # the only signal was a warning line. "Log out" that does not survive a dependency outage is
        # not a security control, it is a UI gesture.
        #
        # Failing CLOSED outright is the card's suggestion and is worse: it turns a Redis blip into a
        # 401 for every authenticated caller, which is a total outage of the product caused by the
        # product. Both directions are real, so neither absolute is right.
        #
        # So the fail-open is time-boxed. A blip inside the grace window keeps everyone working, which
        # is the case that actually happens (restarts, failovers, a brief partition) and the case
        # /readyz already drains for. A SUSTAINED outage is a different thing — it is indistinguishable
        # from someone holding the revocation store down precisely so a stolen token keeps working —
        # and past the window this refuses rather than guesses.
        global _degraded_since
        now_ts = time.time()
        if _degraded_since is None:
            _degraded_since = now_ts
        outage_s = now_ts - _degraded_since
        fail_closed = outage_s > _REVOCATION_GRACE_S
        log.warning(
            "nrvq.auth.revocation_store_degraded",
            op="check",
            token_hash_prefix=h[:_LOG_PREFIX_LEN],
            error=str(exc),
            outage_seconds=round(outage_s, 1),
            failing_closed=fail_closed,
            code="NRVQ-AUTH-14017",
        )
        return fail_closed
    # A successful read clears the outage clock, so the grace window measures THIS outage rather than
    # accumulating across unrelated blips.
    _degraded_since = None
    return revoked
