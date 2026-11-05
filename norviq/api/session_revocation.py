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

Three layers. Two are checked on every JWT validation (``auth.get_current_user`` / ``auth.decode_token``):
- an in-process mirror (always written, always checked) — keeps revocation correct on a single-replica
  deployment even while Redis is restarting, and lets unit tests run without Redis;
- Redis (``RedisCache.revoke_token`` / ``is_token_revoked``) — the shared cache that carries a revocation
  to every other replica on its next request.
The third is never on the request path:
- Postgres (``revoked_tokens``) — the durable record. Every revocation is written there; each API
  process loads every live row into its mirror before it serves a request (``sync``, called by the
  lifespan) and pulls new rows every ``_SYNC_INTERVAL_S`` after that (``sync_forever``).

A logout writes them in that order — mirror, Redis, Postgres — and the order matters. Redis is what
tells the other replicas, so it is written before the one store that can be slow to answer. With
Postgres first, a database that did not answer (a node that died, a managed failover, a pod IP that no
longer exists) held the Redis write back for asyncpg's 60s connect timeout, and every other replica
kept accepting the logged-out token for that long: through the real engine pointed at a black-holed
address, the logout returned, and Redis was written, 60.1s after the request. Authentication never
reads Postgres, so those replicas kept serving the whole time. The Postgres write is bounded on its own
(``_PERSIST_TIMEOUT_S``), so it cannot hold up the logout response for long either.

Why the third layer exists: the first two do not survive Redis losing its data. Measured against real
API processes (uvicorn, real Postgres and Redis, the token's Redis entries deleted): a replica that had
not served the logout accepted the token again at once and was still accepting it 30s later, and once
restarted, the replica that HAD served it accepted it too — for the rest of the token's lifetime. With
this layer the restarted process refuses at once and the other replica within one sync pass (7s
measured). The chart's single-node Redis does keep an RDB on its volume, but runs with no config file,
so the stock schedule applies (``save 3600 1 300 100 60 10000``, read back from a valkey 8.1 started
the same way): a logout reaches the disk between one and sixty minutes later depending on how busy
Redis is — up to a whole session lifetime — and is lost on any unclean stop before that. A managed or
bring-your-own Redis may persist nothing at all, and 0.2.6's own upgrade swaps the server under the
data (redis 7.4 for valkey 8.1) while it rolls every API pod.

What each store being down costs. Redis failures are BEST-EFFORT by design (same deliberate posture as
the login lockout counter): a read failure fails OPEN for a bounded window and then CLOSED (F-044,
``_REVOCATION_GRACE_S``), and a write failure at logout still returns success — the mirror has
already revoked — but logs at ERROR with its own code (NRVQ-AUTH-14017) so incomplete cross-replica
revocation is grep-able. Postgres is never read on the request path, so it being down never decides a
check either way; what it costs is durability and freshness:
- at startup the full set must load or the process does not start (``main.lifespan`` retries, then
  refuses). A process that served requests with an empty mirror would accept every token logged out
  before it started, and a database the API cannot reach at boot already fails ``create_tables`` one
  step earlier;
- at logout the token is already refused here through the mirror and on every other replica through
  Redis (unless that write failed too, NRVQ-AUTH-14017) before Postgres is tried, and the caller gets
  the same 200 as ever: at once when the database refuses, at most ``_PERSIST_TIMEOUT_S`` later when it
  does not answer. The entries are queued in ``_unpersisted`` BEFORE the write is attempted and
  dropped from it only once the write has landed, so a write that fails, times out, or is cut short by
  a cancelled request is retried instead of lost. NRVQ-AUTH-14024 is logged at ERROR, with the
  exception type;
- every sync pass retries the queue (NRVQ-AUTH-14027 once it lands; until then each failing pass logs
  NRVQ-AUTH-14025 with ``unpersisted=<n>``) and writes it into Redis again, whether or not the marker
  below is set. That rewrite is what covers Postgres down and Redis wiped together: the first process
  to notice the wipe reseeds Redis from ITS mirror and sets the marker, and that mirror does not hold
  another process's unpersisted logouts, so a revoking process that relied on the reseed alone would
  find the marker set and write nothing;
- a failed pull leaves the mirror as of the last pass. Peers' newer revocations still reach this
  process through Redis, which every logout writes before it touches Postgres.
The residue: a logout made while Postgres was down, by a process that exits before the database comes
back. On a normal shutdown the lifespan makes one last bounded attempt and logs NRVQ-AUTH-14031 at
ERROR with the count if anything is still queued (a process killed outright cannot; its 14024 lines are
the record). Those revocations are still in Redis — the logout wrote them and every pass rewrote them
— and the next process to boot imports them into Postgres; they are lost only if Redis also loses its
data before that boot.

Memory. Neither the mirror nor the queue has a cap, because every way of honouring one drops a live
revocation: with a 10,000-key cap holding every replica's logouts, a token logged out among ~5,000
others was evicted at boot, at every pull and even on the process that served its logout, and after a
Redis loss every replica accepted it again although its row was in Postgres. What bounds them instead
is what bounds the table: keys of tokens that were logged out and have not expired yet (two keys per
JWT). Measured with tracemalloc: 160-180 bytes per mirror key (164 MiB at 1M keys); a queued key shares
its string and int with the mirror's and adds 20-40 bytes. So 100,000 tokens logged out within one
session lifetime (200,000 keys) cost ~35 MiB in every API process. Growing it takes a live session's
own logout or password change (behind the HTTP rate limits) or write access to Redis or Postgres, and
an entry leaves at its token's own expiry; ``revoked_tokens`` holds the same rows and is what to watch.

Redis is reconciled, not only bypassed. Every process's first pass imports the ``revoked:*`` entries
Redis holds that the store lacks — on the first 0.2.6 boot that is every revocation 0.2.5 made, which
lived nowhere else. And when Redis has lost its data — detected by a marker key with no TTL
(``RedisCache.revocation_seed_marker_present``) — the next pass writes the whole mirror back. The API's
own checks do not need that; the engine's remote-caller path and a rolled-back 0.2.5 replica read Redis
and nothing else.

The raw token is never logged; only a short hash prefix (a full hash would let a log reader probe
whether a specific stolen token is revoked).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
import time
from datetime import datetime, timedelta, timezone

import structlog

log = structlog.get_logger()

# In-process mirror {token_hash: exp_epoch}: in an API process, every live key in Postgres plus this
# process's own logouts. Expired entries are dropped by every sync pass, never on a request: a scan per
# request cost 385us at 10k entries, where the check alone is 5.6us (7.9us at 1M; the pass's prune of 1M
# takes 39ms every 10s). Nothing else is ever dropped: see "Memory" above.
_mirror: dict[str, int] = {}
_LOG_PREFIX_LEN = 12
# The last second a Python datetime can hold (9999-12-31T23:59:59Z). A token's `exp` is clamped to it
# before it is stored anywhere: the CLI mints with an unbounded --ttl, and one key that cannot become a
# `timestamptz` used to fail every batch of queued writes it sat in, on every pass. Clamped, it still
# outlives any real token.
_MAX_EXP = 253_402_300_799

# The durable layer. `_session_factory` is bound by the API lifespan (`bind_store`). What checks tokens
# without that lifespan (the sidecar's remote-caller path, the fleet hub) and the unit tests never bind
# it: they keep the two-layer behaviour above, and since no pass runs there, a write prunes instead.
_session_factory = None
# Revocations not yet confirmed in Postgres, {key: exp_epoch}: queued before each write is attempted,
# dropped once it lands (or once its token has expired), retried and rewritten into Redis by every sync
# pass. Never capped: an entry dropped from here is a logout Postgres may never get.
_unpersisted: dict[str, int] = {}
# How long a logout waits for its Postgres write. By then the token is already refused everywhere
# (mirror and Redis are written first), so this bounds only the response time; a write that misses it
# stays queued for the next pass. Measured on the local Postgres: 17ms with a fresh connection, 2.5ms
# pooled. The engine itself bounds only statements (command_timeout); a connect to an address that
# drops packets waits asyncpg's default of 60s, so without this the logout would wait that long.
_PERSIST_TIMEOUT_S = 2.0
# The bound on one sync pass's Postgres half (pull, then queued writes), and on writing what a pass
# imported from Redis. A pass is background work, but its Redis half (the queue rewrite, the reconcile)
# runs after it and must not wait 60s. An incremental pull took 4.8ms with 1M live rows in the table.
_SYNC_STORE_TIMEOUT_S = 5.0
# The same bound for a process's first pass, which loads the WHOLE live table (and, on the first 0.2.6
# boot, writes every 0.2.5 entry it imports from Redis). Startup retries it, then refuses (main.py).
# Measured on the local Postgres: 1M live rows loaded in 3.4s (0.33s at 100k), so this leaves room for
# several million.
_LOAD_TIMEOUT_S = 30.0
# How stale a replica's mirror may get. Only matters when Redis has ALSO lost the entry — otherwise a
# peer's revocation reaches this process through Redis on the next request — so it is sized against the
# 30s grace already accepted for an unreachable Redis: a third of it. Cost: one indexed SELECT per
# process per pass, 0.8/s across the chart's default eight processes (4 workers x 2 replicas).
_SYNC_INTERVAL_S = 10.0
# Each incremental pass re-reads this much history before its watermark. `revoked_at` is the inserting
# transaction's start time, so a row can commit a moment AFTER a concurrent pass has read past its
# timestamp; a logout's insert is one statement, so a minute of overlap is orders of magnitude of slack.
_SYNC_OVERLAP_S = 60.0
# Database-clock watermark of the last successful pull; None = this process has not loaded the set yet.
_sync_watermark: datetime | None = None
# asyncpg caps one statement at 32767 bind parameters; two per row keeps a batch well under it.
_PERSIST_BATCH = 1000
_KEY_RE = re.compile(r"[0-9a-f]{64}")

# How long the revocation store may be unreachable before `is_revoked` stops guessing and starts
# refusing. Long enough to cover a Redis restart or failover — the blip this fail-open exists for, and
# the one /readyz already drains the pod for — and far shorter than the lifetime of a session token,
# so a sustained outage cannot leave revocation quietly disabled for hours. Module-level rather than
# per-process state so the two callers share one clock.
_REVOCATION_GRACE_S = 30.0
_degraded_since: float | None = None


def _legacy_token_hash(raw_token: str) -> str:
    """The 0.2.5-and-earlier key: SHA-256 of the raw string. Still written and checked so a token revoked
    under 0.2.5, or while rolled back to it, stays revoked wherever the store keeps its data across the
    upgrade: an external store, or the HA failover, which stays on Redis 7.4. Not the bundled
    single-instance store. It starts Valkey on an empty directory because Valkey cannot read 0.2.5's Redis
    7.4 dump (CHANGELOG 0.2.6), so those revocations are gone there and such tokens are accepted again
    until they expire. It can go once every token revoked under 0.2.5 has expired."""
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


def _prune(store: dict[str, int], now: int) -> None:
    """Drop expired entries, and only those: an entry whose token has expired protects nothing, because
    the JWT check refuses the token on its own `exp`. O(n), so it runs once per sync pass, not per request."""
    expired = [h for h, exp in store.items() if exp <= now]
    for h in expired:
        store.pop(h, None)


def _prune_mirror(now: int) -> None:
    _prune(_mirror, now)


def _describe(exc: BaseException) -> str:
    """An error for a log line. `str()` of a TimeoutError is empty, and that is the failure that matters."""
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _reap(task: asyncio.Future) -> None:
    if not task.cancelled():
        task.exception()  # retrieved, so asyncio does not log "exception was never retrieved"


async def _bounded(coro, seconds: float):
    """Await one store call for at most ``seconds``; past that, cancel it and raise TimeoutError AT ONCE.

    Not ``asyncio.wait_for``: that cancels and then waits for the call to unwind, and unwinding a
    connection whose peer has gone silent waits too. Measured through a TCP proxy that stops forwarding
    mid-session: ``wait_for(_persist(...), 0.5)`` raised after 2.51s, this at 0.50s. The cancelled call
    finishes unwinding in the background on its own (no task was left 4s later)."""
    task = asyncio.ensure_future(coro)
    try:
        done, _ = await asyncio.wait({task}, timeout=seconds)
    except asyncio.CancelledError:
        task.cancel()
        raise
    if not done:
        task.cancel()
        task.add_done_callback(_reap)
        raise TimeoutError(f"no answer from Postgres within {seconds:g}s")
    return task.result()


def bind_store(session_factory) -> None:
    """Make Postgres the durable record for this process. The API lifespan calls this once, then
    ``sync`` before serving; ``session_factory`` is ``db.session.get_session`` or a test double."""
    global _session_factory, _sync_watermark
    _session_factory = session_factory
    _sync_watermark = None


async def _persist(entries: dict[str, int]) -> None:
    """Insert {key: exp_epoch} rows. Raises — each caller decides what a failure costs."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from norviq.api.db.models import RevokedToken

    rows = [
        {"token_hash": k, "expires_at": datetime.fromtimestamp(min(exp, _MAX_EXP), tz=timezone.utc)}
        for k, exp in entries.items()
    ]
    provider = _session_factory()
    session = await provider.__anext__()
    try:
        for i in range(0, len(rows), _PERSIST_BATCH):
            # DO NOTHING on a repeat: the expiry is the token's own `exp`, so a second write of the same
            # key (another replica importing it from Redis, a retried queue entry) carries the same value.
            await session.execute(
                pg_insert(RevokedToken.__table__)
                .values(rows[i : i + _PERSIST_BATCH])
                .on_conflict_do_nothing(index_elements=["token_hash"])
            )
        await session.commit()
    finally:
        await provider.aclose()


async def _persist_or_queue(entries: dict[str, int], timeout: float, **context) -> None:
    """Write entries to Postgres within ``timeout``. Queued first and dequeued only once the write has
    landed, so no way out of here — an error, the timeout, a cancelled caller — leaves them unqueued."""
    _unpersisted.update(entries)
    try:
        await _bounded(_persist(entries), timeout)
    except Exception as exc:  # noqa: BLE001 — still queued; every sync pass retries it
        log.error(
            "nrvq.auth.revocation_persist_failed",
            **context,
            timeout_s=timeout,
            queued=len(_unpersisted),
            error=_describe(exc),
            detail="revoked now through the mirror and Redis; every sync pass retries the Postgres write",
            code="NRVQ-AUTH-14024",
        )
        return
    for key in entries:
        _unpersisted.pop(key, None)


async def revoke(cache, raw_token: str, exp: int) -> None:
    """Revoke a token until its own ``exp``: the mirror, then Redis, then Postgres — the two stores the
    checks read before the one that can be slow, so a database that does not answer delays nothing but
    this call's return, by at most ``_PERSIST_TIMEOUT_S``. No store failing fails the logout; see the
    module docstring for what each one costs and how it recovers."""
    now = int(time.time())
    ttl = max(1, min(int(exp), _MAX_EXP) - now)
    keys = _keys(raw_token)
    h = keys[0]
    entries = {k: now + ttl for k in keys}
    _mirror.update(entries)
    if _session_factory is None:
        _prune_mirror(now)  # no sync pass runs in this process to do it
    if cache is not None:
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
    if _session_factory is not None:
        await _persist_or_queue(entries, _PERSIST_TIMEOUT_S, token_hash_prefix=h[:_LOG_PREFIX_LEN])


async def is_revoked(cache, raw_token: str) -> bool:
    """True if the token was logged out. Mirror first (two dict lookups, whatever its size), then Redis
    (bounded fail-open, below). Postgres is never read here, and nothing here scans the mirror: it
    already holds what Postgres knows, loaded and pulled by ``sync``, which also drops expired entries."""
    now = int(time.time())
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


async def _pull() -> int:
    """Merge the store's rows into the mirror: all of them on the first pass, then only those written
    since the last pass's watermark. Raises on a store error. Returns the entries that were new here —
    not the rows read, which repeat for a minute because of the overlap."""
    global _sync_watermark
    from sqlalchemy import func, select

    from norviq.api.db.models import RevokedToken

    provider = _session_factory()
    session = await provider.__anext__()
    try:
        # One transaction, so `now()` is the same instant the row query is judged against.
        db_now = await session.scalar(select(func.now()))
        # Expiry is judged by THIS process's clock — the one that checks the JWT's own `exp`.
        stmt = select(RevokedToken.token_hash, RevokedToken.expires_at).where(
            RevokedToken.expires_at > datetime.now(timezone.utc)
        )
        if _sync_watermark is not None:
            stmt = stmt.where(RevokedToken.revoked_at > _sync_watermark)
        rows = (await session.execute(stmt)).all()
    finally:
        await provider.aclose()
    added = 0
    for key, expires_at in rows:
        exp = int(expires_at.timestamp())
        if exp > _mirror.get(key, 0):
            _mirror[key] = exp
            added += 1
    _sync_watermark = db_now - timedelta(seconds=_SYNC_OVERLAP_S)
    return added


async def _flush_unpersisted() -> None:
    """Retry the queued writes. Raises on a store error; the queue is kept for next pass."""
    now = int(time.time())
    _prune(_unpersisted, now)
    if not _unpersisted:
        return
    pending = dict(_unpersisted)
    await _persist(pending)
    for key in pending:  # only what was written: a logout may have queued more during the await
        _unpersisted.pop(key, None)
    log.info("nrvq.auth.revocations_persisted_late", entries=len(pending), code="NRVQ-AUTH-14027")


async def _store_pass() -> int:
    """A pass's Postgres half: pull, then the queued writes. Returns what the pull added."""
    added = await _pull()
    await _flush_unpersisted()
    return added


async def _rewrite_unpersisted(cache) -> None:
    """Write the queue into Redis on every pass, marker or not. Postgres has not got these, so after a
    Redis wipe no other process can put them back: the first to notice the wipe reseeds from ITS mirror
    and sets the marker, and a reseed is all the marker check below would ever trigger. Cheap — the
    queue is empty unless Postgres is failing — and it never sets the marker, because these entries
    vouch for nothing but themselves."""
    if cache is None:
        return
    now = int(time.time())
    _prune(_unpersisted, now)
    if _unpersisted:
        await cache.revoke_tokens({k: exp - now for k, exp in _unpersisted.items()})


async def _reconcile_cache(cache, *, boot: bool, timeout: float) -> int:
    """Make Redis and the store agree. Returns the entries imported from Redis into the mirror.

    Import, on a process's first pass and whenever Redis has lost its data: anything Redis holds that
    the mirror does not. On the first 0.2.6 boot that is every revocation 0.2.5 made — they lived nowhere
    else — and on any boot it is whatever a 0.2.5 pod mid-rollout, or a pod that exited with a queued
    write, put only in Redis. Persisting them is what lets them outlive the NEXT Redis loss.

    Repair, only when the marker says Redis has lost its data: write the whole mirror back. Redis before
    Postgres here too: the repair goes out before the imports' bounded write is attempted.
    """
    if cache is None:
        return 0
    intact = await cache.revocation_seed_marker_present()
    if intact and not boot:
        return 0
    now = int(time.time())
    held = await cache.scan_revoked_tokens()
    # Only what this module could have written: every key is a SHA-256 hexdigest. Anything else under
    # `revoked:` would fail the 64-character column, and it would fail as part of a batch — taking the
    # real revocations queued beside it down with it on every retry. And only keys the mirror does not
    # already hold live: one key is one token with one `exp`. Comparing expiries instead re-imported keys
    # Postgres already had: Redis rounds the remaining TTL to the nearest second, and a key set at a
    # fractional second can read back one second past its token's `exp`.
    imported = {k: now + ttl for k, ttl in held.items() if _KEY_RE.fullmatch(k) and _mirror.get(k, 0) <= now}
    _mirror.update(imported)
    if imported:
        _unpersisted.update(imported)  # before the reseed below can raise: queued, they are retried every pass
    if not intact:
        live = {k: exp - now for k, exp in _mirror.items() if exp > now}
        await cache.reseed_revoked_tokens(live)
        log.warning(
            "nrvq.auth.revocation_cache_reseeded",
            entries=len(live),
            imported=len(imported),
            detail="Redis had lost its data (or this is the first 0.2.6 boot); the denylist was rebuilt from Postgres",
            code="NRVQ-AUTH-14028",
        )
    if imported:
        await _persist_or_queue(imported, timeout, source="redis_import")
    return len(imported)


async def sync(cache) -> int:
    """One reconciliation pass: drop expired entries, pull the store into the mirror and retry queued
    writes (together bounded by ``_SYNC_STORE_TIMEOUT_S``, or ``_LOAD_TIMEOUT_S`` until the first pull
    has succeeded), then rewrite the queue into Redis and reconcile Redis.

    The lifespan calls it once before the process serves anything — then a raise means "do not start",
    and it retries and refuses (main.py). ``sync_forever`` calls it after that. Returns the keys the pass
    added to the mirror: on the first pass every live key in Postgres plus any imported from Redis,
    afterwards the keys that were new to this process (a peer's logouts, imports after a Redis loss).

    The Redis half runs even when the store failed or did not answer, from the mirror and queue as they
    stand, and the store error is raised after it: Postgres down AND Redis wiped is the case where the
    other replicas have no other way to learn about a revocation this process made. Nothing touches
    Redis before the first successful pull, because the marker a repair sets vouches for a complete
    denylist, and an empty mirror is not one.
    """
    if _session_factory is None:
        raise RuntimeError("session_revocation.sync before bind_store")
    boot = _sync_watermark is None
    timeout = _LOAD_TIMEOUT_S if boot else _SYNC_STORE_TIMEOUT_S
    _prune_mirror(int(time.time()))  # here, whatever the stores do, rather than on every request
    store_error: Exception | None = None
    added = 0
    try:
        added = await _bounded(_store_pass(), timeout)
    except Exception as exc:  # noqa: BLE001 — re-raised below, after Redis has had its turn
        store_error = exc
    if _sync_watermark is not None:
        try:
            await _rewrite_unpersisted(cache)
            added += await _reconcile_cache(cache, boot=boot, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — a Redis outage is is_revoked's to judge (F-044), not ours
            log.warning(
                "nrvq.auth.revocation_sync_failed", op="reconcile_cache", error=_describe(exc), code="NRVQ-AUTH-14025"
            )
    if store_error is not None:
        raise store_error
    return added


async def sync_forever(cache) -> None:
    """The background half: one ``sync`` pass every ``_SYNC_INTERVAL_S`` until cancelled at shutdown."""
    while True:
        await asyncio.sleep(_SYNC_INTERVAL_S)
        try:
            added = await sync(cache)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — the mirror stands as of the last pass; Redis still carries peers'
            log.warning(
                "nrvq.auth.revocation_sync_failed",
                op="store",
                error=_describe(exc),
                unpersisted=len(_unpersisted),
                code="NRVQ-AUTH-14025",
            )
            continue
        if added:
            log.info("nrvq.auth.revocations_synced", entries=added, mirror=len(_mirror), code="NRVQ-AUTH-14026")


async def close() -> None:
    """Shutdown, after ``sync_forever`` is cancelled: one last bounded try at the queue. Whatever is still
    queued afterwards is reported, because this process was the only one retrying it; it stays in Redis,
    and the next process to boot imports it into Postgres."""
    if _session_factory is None or not _unpersisted:
        return
    try:
        await _bounded(_flush_unpersisted(), _SYNC_STORE_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 — reported below; shutdown goes on
        log.error(
            "nrvq.auth.revocations_unpersisted_at_shutdown",
            entries=len(_unpersisted),
            error=_describe(exc),
            detail="these logouts are in Redis but not Postgres; the next API process to boot imports them",
            code="NRVQ-AUTH-14031",
        )
