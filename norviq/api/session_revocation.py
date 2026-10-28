# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Server-side session revocation (logout) for stateless JWTs.

Sessions are stateless HS256/OIDC JWTs with no ``jti``, so logout is implemented as a denylist keyed
by a SHA-256 over the token's DECODED segments (unique per token via the signature; covers login-, CLI-
and webhook-minted tokens without changing the token contract).

Keyed on the decoded bytes, not the presented string, because one token has several valid spellings.
A base64url segment whose length is not a multiple of four carries spare low bits in its last
character, and PyJWT before 2.14.0 accepted every value of them. Keyed on the raw string, a logged-out
token re-spelled in its last character missed the denylist and still verified: logout was undone by
editing one character. The 2.14.0 floor in pyproject closes it at decode time; this closes it here too,
so revocation does not depend on which library version rejects what. Entries carry TTL = the token's remaining
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

import base64
import binascii
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


def _legacy_token_hash(raw_token: str) -> str:
    """The 0.2.5-and-earlier key: SHA-256 of the raw string. Still written and checked so a token revoked
    before an upgrade (or after a rollback) stays revoked; it can go once every such token has expired."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def token_hash(raw_token: str) -> str:
    """The denylist key: SHA-256 over a JWT's decoded segments, each length-prefixed so segment
    boundaries cannot be shifted. Every spelling of one token maps to one key. A credential that is not
    a three-segment base64url JWT (an API key, say) keeps the raw-string hash."""
    parts = raw_token.split(".")
    if len(parts) == 3:
        try:
            h = hashlib.sha256()
            for seg in parts:
                raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
                h.update(len(raw).to_bytes(8, "big"))
                h.update(raw)
            return h.hexdigest()
        except (binascii.Error, ValueError):
            pass
    return _legacy_token_hash(raw_token)


def _keys(raw_token: str) -> list[str]:
    """Canonical key first, then the legacy one when it differs."""
    canonical, legacy = token_hash(raw_token), _legacy_token_hash(raw_token)
    return [canonical] if canonical == legacy else [canonical, legacy]


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
    keys = _keys(raw_token)
    h = keys[0]
    for k in keys:
        _mirror[k] = now + ttl
    _prune_mirror(now)
    if cache is None:
        return
    try:
        for k in keys:
            await cache.revoke_token(k, ttl)
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
    keys = _keys(raw_token)
    h = keys[0]
    if any(_mirror.get(k, 0) > now for k in keys):
        return True
    if cache is None:
        return False
    try:
        revoked = False
        for k in keys:
            if await cache.is_token_revoked(k):
                revoked = True
                break
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
