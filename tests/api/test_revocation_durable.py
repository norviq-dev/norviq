# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A logged-out token must stay logged out after Redis loses its data and the API rolls.

Revocations lived in Redis and in each API process's memory, nothing else. Emptying Redis and resetting
the process state the way a restart does brought a logged-out token back: /me answered 401 after logout
and 200 afterwards. Postgres (``revoked_tokens``) is the durable record now; each process loads it
before serving and pulls it every ``_SYNC_INTERVAL_S``, and Redis is rebuilt from it when it has lost
its data. A logout writes the mirror and Redis before Postgres, so a database that does not answer
cannot delay the other replicas' refusal.

These run against the real Postgres (NRVQ_PG_URL, as CI provides). Redis is a dict so that "Redis lost
everything" can be exactly that without flushing a shared instance; RedisCache's own half of the
contract (marker, scan, reseed) is tested against real Redis in tests/engine/test_cache.py. A replica is
a set of module globals, so a second one is simulated by swapping them (``_Process``).
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import jwt
import pytest
import structlog
from sqlalchemy import text

from norviq.api import session_revocation as sr
from norviq.api.db.session import close_db, create_tables, get_session, init_db
from norviq.config import settings

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class _Redis:
    """The RedisCache revocation surface over a dict. ``wipe()`` is a Redis that came back empty."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.marker = False

    def wipe(self) -> None:
        self.store.clear()
        self.marker = False

    async def revoke_token(self, h: str, ttl: int) -> None:
        self.store[h] = ttl

    async def is_token_revoked(self, h: str) -> bool:
        return h in self.store

    async def revocation_seed_marker_present(self) -> bool:
        return self.marker

    async def scan_revoked_tokens(self) -> dict[str, int]:
        return dict(self.store)

    async def revoke_tokens(self, entries: dict[str, int]) -> None:
        self.store.update(entries)  # and NOT the marker: these entries vouch for nothing else

    async def reseed_revoked_tokens(self, entries: dict[str, int]) -> None:
        self.store.update(entries)
        self.marker = True


class _Process:
    """One API process's revocation state. Entering it swaps the module globals in; leaving swaps back."""

    def __init__(self) -> None:
        self.mirror: dict[str, int] = {}
        self.unpersisted: dict[str, int] = {}
        self.watermark = None
        self.degraded = None

    def __enter__(self) -> "_Process":
        self._saved = (sr._mirror, sr._unpersisted, sr._sync_watermark, sr._degraded_since)
        sr._mirror, sr._unpersisted = self.mirror, self.unpersisted
        sr._sync_watermark, sr._degraded_since = self.watermark, self.degraded
        return self

    def __exit__(self, *_exc) -> None:
        self.watermark, self.degraded = sr._sync_watermark, sr._degraded_since
        sr._mirror, sr._unpersisted, sr._sync_watermark, sr._degraded_since = self._saved


class _Flaky:
    """A session factory whose database can be taken down and brought back.

    Down, it refuses at once (a stopped Postgres) or, with ``hangs``, never answers: a node that died,
    a managed database failing over, a pod IP that no longer exists. The real engine bounds statements
    but not the connect, which waits asyncpg's own 60s (measured: a logout through the real engine
    pointed at a black-holed address returned after 60.1s when Postgres was written first). ``entered``
    is set once a caller is stuck in it.

    A hung call takes ``UNWIND_S`` to give up once cancelled, the way a connection to a peer that went
    silent does (2.5s measured through a proxy that stopped forwarding mid-session). So a bound that
    waits for the cancelled call to unwind (asyncio.wait_for) overruns here as it would in production,
    instead of passing because a test double unwinds instantly."""

    UNWIND_S = 2.5

    def __init__(self) -> None:
        self.down = False
        self.hangs = False
        self.calls = 0
        self.entered = asyncio.Event()

    def __call__(self):
        self.calls += 1
        return self._gen()

    async def _gen(self):
        if self.down:
            self.entered.set()
            if self.hangs:
                try:
                    await asyncio.Event().wait()
                finally:
                    await asyncio.sleep(self.UNWIND_S)
            raise ConnectionRefusedError("postgres is down")
        async for session in get_session():
            yield session


async def _within(coro, seconds: float = 5.0):
    """Await ``coro``, or fail the test if it is still waiting after ``seconds``. A plain wait_for would
    raise TimeoutError, which is also what a bounded store call raises, and the two must not be confused."""
    task = asyncio.ensure_future(coro)
    done, _ = await asyncio.wait({task}, timeout=seconds)
    if not done:
        task.cancel()
        pytest.fail(f"still waiting on the store after {seconds}s")
    return task.result()


@asynccontextmanager
async def _session():
    gen = get_session()
    session = await gen.__anext__()
    try:
        yield session
    finally:
        await gen.aclose()


@pytest.fixture
async def db():
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set for PostgreSQL integration tests")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()  # the lifespan's own path: this is what creates revoked_tokens on an upgrade
    written: list[str] = []
    saved = (sr._session_factory, sr._sync_watermark)
    try:
        yield written
    finally:
        sr._session_factory, sr._sync_watermark = saved
        sr._mirror.clear()
        sr._unpersisted.clear()
        sr._degraded_since = None
        async with _session() as session:
            await session.execute(text("DELETE FROM revoked_tokens WHERE token_hash = ANY(:k)"), {"k": written})
            await session.commit()
        await close_db()
        settings.pg_url = old_url


def _token(ttl: int = 3600) -> str:
    now = int(time.time())
    claims = {"sub": f"user-{uuid.uuid4().hex[:8]}", "role": "admin", "namespace": "*", "iat": now, "exp": now + ttl}
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _track(written: list[str], tok: str) -> str:
    written.extend(sr._keys(tok))
    return tok


async def _boot(redis: _Redis, factory=get_session) -> _Process:
    """What a fresh API process does before it serves: bind the store, load it (main.lifespan)."""
    proc = _Process()
    with proc:
        sr.bind_store(factory)
        await sr.sync(redis)
    return proc


async def _stored(keys: list[str]) -> set[str]:
    async with _session() as session:
        rows = await session.execute(
            text("SELECT token_hash FROM revoked_tokens WHERE token_hash = ANY(:k)"), {"k": keys}
        )
        return {r[0] for r in rows}


# --- the reproduction -----------------------------------------------------------------------------


class _NoUsers:
    async def execute(self, _stmt):
        return SimpleNamespace(scalar_one_or_none=lambda: None)


def _client(redis: _Redis) -> httpx.AsyncClient:
    """The real app on the test's own event loop (TestClient would run it on another, and the pooled
    asyncpg connections the logout writes through belong to this one). No lifespan: `_boot` is it."""
    from norviq.api.main import create_app

    app = create_app()
    app.state.cache = redis

    async def _override():
        yield _NoUsers()

    app.dependency_overrides[get_session] = _override
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api")


async def test_a_logged_out_token_stays_out_after_redis_loss_and_an_api_roll(db) -> None:
    """The defect end to end: logout, Redis comes back empty, the API rolls, the token is presented."""
    redis = _Redis()
    tok = _track(db, _token())
    headers = {"Authorization": f"Bearer {tok}"}
    with await _boot(redis):
        async with _client(redis) as client:
            assert (await client.get("/api/v1/me", headers=headers)).status_code == 200
            assert (await client.post("/api/v1/auth/logout", headers=headers)).status_code == 200
            assert (await client.get("/api/v1/me", headers=headers)).status_code == 401

    redis.wipe()  # the Redis pod came back without its data
    rolled = await _boot(redis)  # and every API process restarted with nothing in memory
    with rolled:
        async with _client(redis) as client:
            after = await client.get("/api/v1/me", headers=headers)
    assert after.status_code == 401, "a logged-out token verified again after a Redis loss and an API roll"
    assert after.json()["detail"] == "Session has been logged out"


# --- across replicas --------------------------------------------------------------------------------


async def test_a_running_replica_learns_a_peers_revocation_once_redis_has_lost_it(db) -> None:
    redis = _Redis()
    a, b = await _boot(redis), await _boot(redis)
    tok = _track(db, _token())
    with a:
        await sr.revoke(redis, tok, int(time.time()) + 3600)
    with b:
        assert await sr.is_revoked(redis, tok)  # through Redis, the normal path
    redis.wipe()
    with b:
        # The window this layer bounds: B never saw the logout itself and Redis no longer has it...
        assert not await sr.is_revoked(redis, tok)
        await sr.sync(redis)  # ...until B's next pass, at most _SYNC_INTERVAL_S later
        assert await sr.is_revoked(redis, tok)
    # B's pass also put Redis back, so a reader with no mirror of its own sees it again.
    assert sr.token_hash(tok) in redis.store


def test_the_security_model_states_the_bounds_the_code_has() -> None:
    """docs/security-model.md tells operators how long a logout waits on Postgres and how often a
    missed write is retried. Both numbers are checked against the constants, so the page cannot
    quietly drift from the code."""
    from pathlib import Path

    words = {2.0: "two", 10.0: "ten"}
    text = " ".join((Path(__file__).resolve().parents[2] / "docs/security-model.md").read_text().split())
    assert f"waits at most {words[sr._PERSIST_TIMEOUT_S]} seconds" in text
    assert f"retried every {words[sr._SYNC_INTERVAL_S]} seconds" in text


async def test_the_sync_interval_stays_inside_the_redis_grace_window() -> None:
    """The replica-staleness window is only acceptable while it is shorter than the outage window F-044
    already accepts for an unreachable Redis."""
    assert sr._SYNC_INTERVAL_S < sr._REVOCATION_GRACE_S


# --- the 0.2.5 key and the re-spelled token -------------------------------------------------------


def _respelled(tok: str) -> str:
    head, payload, sig = tok.split(".")
    base = _ALPHA.index(sig[-1]) & ~0b11
    return f"{head}.{payload}.{sig[:-1]}{_ALPHA[base + ((_ALPHA.index(sig[-1]) - base + 1) % 4)]}"


async def test_both_keys_are_persisted_and_survive_a_redis_loss(db) -> None:
    redis = _Redis()
    tok = _track(db, _token())
    with await _boot(redis):
        await sr.revoke(redis, tok, int(time.time()) + 3600)
    legacy = hashlib.sha256(tok.encode()).hexdigest()
    assert await _stored(sr._keys(tok)) == {sr.token_hash(tok), legacy}

    redis.wipe()
    with await _boot(redis):
        assert await sr.is_revoked(redis, tok)
        assert await sr.is_revoked(redis, _respelled(tok)), "a re-spelled token came back after the loss"
    # A rolled-back 0.2.5 replica reads only `revoked:<sha256(raw)>` from Redis: the repair restores it.
    assert legacy in redis.store


async def test_a_revocation_0_2_5_made_is_imported_on_the_first_0_2_6_boot(db) -> None:
    """0.2.5 kept revocations in Redis only, under the raw-string key. The upgrade must not drop them at
    the next Redis loss — the upgrade itself replaces the Redis server."""
    redis = _Redis()
    tok = _track(db, _token())
    legacy = hashlib.sha256(tok.encode()).hexdigest()
    redis.store[legacy] = 1800  # written by a 0.2.5 logout; no marker, because 0.2.5 never set one
    await _boot(redis)
    assert await _stored([legacy]) == {legacy}
    assert redis.marker

    redis.wipe()
    with await _boot(redis):
        assert await sr.is_revoked(redis, tok)


async def test_a_revocation_only_redis_holds_is_persisted_by_the_next_boot(db) -> None:
    """A 0.2.5 pod still serving mid-rollout, or a 0.2.6 pod that died with a queued write, leaves a
    revocation in Redis alone while the marker says Redis is intact. The next process to boot keeps it."""
    redis = _Redis()
    await _boot(redis)
    assert redis.marker
    tok = _track(db, _token())
    legacy = hashlib.sha256(tok.encode()).hexdigest()
    redis.store[legacy] = 1800
    await _boot(redis)
    assert await _stored([legacy]) == {legacy}


async def test_a_malformed_redis_entry_is_not_imported_and_blocks_nothing(db) -> None:
    """Every key this module writes is a SHA-256 hexdigest. Anything else under `revoked:` would fail
    the 64-character column as part of a batch — and keep failing, taking real revocations with it."""
    redis = _Redis()
    tok = _track(db, _token())
    legacy = hashlib.sha256(tok.encode()).hexdigest()
    junk = "x" * 80
    redis.store.update({legacy: 1800, junk: 1800})
    with await _boot(redis):
        assert junk not in sr._mirror
        assert sr._unpersisted == {}
    assert await _stored([legacy]) == {legacy}


async def test_the_whole_cycle_against_real_redis(db) -> None:
    """The dict above stands in for Redis; this runs one loss-and-roll through RedisCache itself. The loss
    is this test's keys and the marker, not a FLUSHALL — the instance is shared."""
    from norviq.engine.cache import REVOCATION_SEED_MARKER, RedisCache

    url = os.getenv("NRVQ_REDIS_URL")
    if not url:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    cache = RedisCache(url=url)
    await cache.connect()
    tok = _track(db, _token())
    try:
        with await _boot(cache):
            await sr.revoke(cache, tok, int(time.time()) + 3600)
        await cache._client().delete(*[f"revoked:{k}" for k in sr._keys(tok)], REVOCATION_SEED_MARKER)
        assert not await cache.is_token_revoked(sr.token_hash(tok))
        with await _boot(cache):
            assert await sr.is_revoked(cache, tok)
        for key in sr._keys(tok):  # and Redis has it back, with a TTL no longer than the token's
            assert 0 < await cache._client().ttl(f"revoked:{key}") <= 3600
        assert await cache.revocation_seed_marker_present()
    finally:
        await cache._client().delete(*[f"revoked:{k}" for k in sr._keys(tok)])
        await cache.close()


# --- what each store being down costs ------------------------------------------------------------


async def test_a_logout_while_postgres_is_down_revokes_now_and_persists_later(db) -> None:
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    tok = _track(db, _token())
    flaky.down = True
    with proc:
        with structlog.testing.capture_logs() as logs:
            await sr.revoke(redis, tok, int(time.time()) + 3600)
        assert await sr.is_revoked(redis, tok)  # revoked right now, here and through Redis
        assert set(sr._unpersisted) == set(sr._keys(tok))
    failed = [e for e in logs if e["event"] == "nrvq.auth.revocation_persist_failed"]
    assert failed and failed[0]["log_level"] == "error" and failed[0]["code"] == "NRVQ-AUTH-14024"
    assert await _stored(sr._keys(tok)) == set()

    flaky.down = False
    with proc:
        await sr.sync(redis)  # the next pass lands the queued write
        assert sr._unpersisted == {}
    assert await _stored(sr._keys(tok)) == set(sr._keys(tok))
    redis.wipe()
    with await _boot(redis):
        assert await sr.is_revoked(redis, tok)


async def test_a_store_that_does_not_answer_never_holds_back_the_logout_from_redis(db, monkeypatch) -> None:
    """Postgres partitioned rather than stopped. Redis is what carries a logout to the other replicas,
    and authentication never reads Postgres, so they keep serving through the partition: the Redis write
    must not queue behind a database that does not answer. Measured with Postgres written first and the
    store hanging 3s: a peer asked 0.5s into the logout accepted the token, and the logout took 3.7s;
    through the real engine and a black-holed address, 60.1s."""
    monkeypatch.setattr(sr, "_PERSIST_TIMEOUT_S", 0.2, raising=False)  # raising=False: the control runs it too
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    tok = _track(db, _token())
    flaky.down = flaky.hangs = True
    with proc:
        started = time.monotonic()
        with structlog.testing.capture_logs() as logs:
            logout = asyncio.ensure_future(sr.revoke(redis, tok, int(time.time()) + 3600))
            try:
                await _within(flaky.entered.wait())  # the logout is now waiting on Postgres...
                with _Process():  # ...while a replica that never saw it is asked about the token
                    assert await sr.is_revoked(redis, tok), (
                        "a peer accepted the token while the logout waited on Postgres"
                    )
                await _within(logout)
            finally:
                logout.cancel()
        # The logout itself is bounded too, and what it could not write stays queued for the next pass.
        assert time.monotonic() - started < 2.0
        assert set(sr._unpersisted) == set(sr._keys(tok))
    failed = [e for e in logs if e["event"] == "nrvq.auth.revocation_persist_failed"]
    assert failed and failed[0]["log_level"] == "error" and failed[0]["code"] == "NRVQ-AUTH-14024"
    assert failed[0]["error"].startswith("TimeoutError"), failed[0]["error"]  # not the empty str(TimeoutError())


async def test_logout_answers_200_while_postgres_does_not_answer(db, monkeypatch) -> None:
    """What the user sees during the partition: the ordinary logout response, a bounded time later, and
    the token refused from then on — here, and on a replica that never served the logout."""
    monkeypatch.setattr(sr, "_PERSIST_TIMEOUT_S", 0.2, raising=False)
    redis = _Redis()
    flaky = _Flaky()
    tok = _track(db, _token())
    headers = {"Authorization": f"Bearer {tok}"}
    with await _boot(redis, flaky):
        flaky.down = flaky.hangs = True
        async with _client(redis) as client:
            started = time.monotonic()
            out = await _within(client.post("/api/v1/auth/logout", headers=headers))
            took = time.monotonic() - started
            assert (out.status_code, out.json()) == (200, {"logged_out": True})
            assert took < 2.0, f"logout took {took:.2f}s with Postgres not answering"
            assert (await client.get("/api/v1/me", headers=headers)).status_code == 401
    with _Process():
        async with _client(redis) as client:
            assert (await client.get("/api/v1/me", headers=headers)).status_code == 401


async def test_a_logout_cut_short_mid_write_stays_queued(db) -> None:
    """A caller that goes away while the Postgres write is in flight (the request cancelled) must not
    take the durable half of the logout with it: it is queued before the write is tried."""
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    tok = _track(db, _token())
    flaky.down = flaky.hangs = True
    with proc:
        logout = asyncio.ensure_future(sr.revoke(redis, tok, int(time.time()) + 3600))
        await _within(flaky.entered.wait())
        logout.cancel()
        with pytest.raises(asyncio.CancelledError):
            await logout
        assert set(sr._unpersisted) == set(sr._keys(tok)), "a cancelled logout's Postgres write was dropped"
        flaky.down = flaky.hangs = False
        await sr.sync(redis)  # and the next pass lands it
        assert sr._unpersisted == {}
    assert await _stored(sr._keys(tok)) == set(sr._keys(tok))


async def test_a_bounded_store_call_does_not_wait_for_the_cancelled_call_to_unwind() -> None:
    """asyncio.wait_for cancels and then waits for the call to unwind, and unwinding a connection whose
    peer went silent waits too (through a proxy that stopped forwarding mid-session, wait_for with a
    0.5s bound raised after 2.51s). The bound has to hold regardless."""

    async def stubborn():
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(3)  # the unwinding that itself waits on the network

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await sr._bounded(stubborn(), 0.1)
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize("first", ["revoker", "peer"])
@pytest.mark.parametrize("failure", ["refuses", "hangs"])
async def test_postgres_down_and_redis_wiped_together_peers_still_learn_of_the_logout(
    db, monkeypatch, failure, first
) -> None:
    """The case where Redis repair is not optional: the database never saw the revocation, Redis lost it,
    and only the revoking process still knows. Its pass must put it back for the others — whichever
    process notices the wipe first. The first to notice reseeds Redis from ITS mirror and sets the
    marker, so a revoking process that relied on the repair alone found the marker set and wrote
    nothing; with eight processes on one cycle it goes first about one time in eight. And a store that
    hangs instead of refusing must not hold the Redis half of the pass back either."""
    if failure == "hangs":
        monkeypatch.setattr(sr, "_PERSIST_TIMEOUT_S", 0.2, raising=False)
        monkeypatch.setattr(sr, "_SYNC_STORE_TIMEOUT_S", 0.2, raising=False)
    redis = _Redis()
    flaky = _Flaky()
    a = await _boot(redis, flaky)
    earlier = _track(db, _token())
    with a:
        await sr.revoke(redis, earlier, int(time.time()) + 3600)  # persisted: the store is still up
    b = await _boot(redis, flaky)
    tok = _track(db, _token())
    flaky.down, flaky.hangs = True, failure == "hangs"
    with a:
        await _within(sr.revoke(redis, tok, int(time.time()) + 3600))
    redis.wipe()
    store_error = TimeoutError if failure == "hangs" else ConnectionRefusedError
    for proc in (a, b) if first == "revoker" else (b, a):
        with proc:
            with pytest.raises(store_error):
                await _within(sr.sync(redis))  # the store error still surfaces, after the Redis half ran
        if proc is a:
            assert sr.token_hash(tok) in redis.store, "the revoking process's pass did not put its logout back"
    with b:
        assert await sr.is_revoked(redis, tok), "a peer accepted a token the revoking process knows is revoked"
    # Writing the queue does not set the marker, so the repair of everything else still happened.
    assert sr.token_hash(earlier) in redis.store and redis.marker


@pytest.mark.parametrize("failure", ["refuses", "hangs"])
async def test_a_process_that_cannot_load_the_store_does_not_start(db, monkeypatch, failure) -> None:
    """Startup posture: no successful load, no serving (main.lifespan retries, then refuses). Each attempt
    is bounded, so a database that does not answer is retried rather than waited on for 60s. And no Redis
    repair either — the marker vouches for a complete denylist, and an empty mirror is not one."""
    monkeypatch.setattr(sr, "_LOAD_TIMEOUT_S", 0.2, raising=False)
    redis = _Redis()
    flaky = _Flaky()
    flaky.down, flaky.hangs = True, failure == "hangs"
    with _Process():
        sr.bind_store(flaky)
        with pytest.raises(TimeoutError if failure == "hangs" else ConnectionRefusedError):
            await _within(sr.sync(redis))
        assert sr._sync_watermark is None
    assert not redis.marker


def test_the_lifespan_loads_the_store_before_serving_and_never_swallows_a_failure() -> None:
    """Wiring guard: the load sits before `yield` and goes through the retry-then-raise helper, not
    through one of the advisory warms that log and carry on."""
    from norviq.api import main

    src = inspect.getsource(main.lifespan)
    assert "session_revocation.bind_store(get_session)" in src
    load = src.index("lambda: session_revocation.sync(app.state.cache)")
    assert src.rindex("_connect_with_backoff(", 0, load) > src.index("app.state.cache.connect")
    assert load < src.index("yield")
    assert "session_revocation.sync_forever(app.state.cache)" in src
    # Shutdown reports what never reached Postgres, and needs the database to try once more.
    assert src.index("yield") < src.index("await session_revocation.close()") < src.index("await close_db()")


async def test_shutdown_lands_the_queue_or_says_what_it_could_not(db, monkeypatch) -> None:
    """A process that exits with logouts Postgres never got is the one place they can quietly lose
    their durability. Shutdown tries once more and, failing that, reports the count at ERROR."""
    monkeypatch.setattr(sr, "_SYNC_STORE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(sr, "_PERSIST_TIMEOUT_S", 0.2)
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    tok = _track(db, _token())
    flaky.down = flaky.hangs = True
    with proc:
        await sr.revoke(redis, tok, int(time.time()) + 3600)
        with structlog.testing.capture_logs() as logs:
            await _within(sr.close())
        assert set(sr._unpersisted) == set(sr._keys(tok))
    left = [e for e in logs if e["event"] == "nrvq.auth.revocations_unpersisted_at_shutdown"]
    assert left and left[0]["log_level"] == "error" and left[0]["code"] == "NRVQ-AUTH-14031"
    assert left[0]["entries"] == len(sr._keys(tok))

    flaky.down = flaky.hangs = False
    with proc:
        with structlog.testing.capture_logs() as logs:
            await sr.close()
        assert sr._unpersisted == {}
    assert [e["code"] for e in logs] == ["NRVQ-AUTH-14027"]
    assert await _stored(sr._keys(tok)) == set(sr._keys(tok))


# --- nothing live is ever dropped to a cap -------------------------------------------------------


async def test_no_revocation_is_lost_to_a_cap_when_redis_loses_its_data(db) -> None:
    """Every replica's logouts share each process's memory, so a cap there drops real revocations. With
    the mirror capped at 10,000 keys, a token logged out among 10,050 later-expiring revocations was
    evicted at boot, at every pull, and from the process that served its logout; after a Redis loss every
    replica accepted it again although its row was in Postgres. Measured with real uvicorn processes and
    a private Redis: the serving process and a fresh one both answered /me with 200."""
    prefix, n = uuid.uuid4().hex[:8], 10_050
    # Written ten minutes ago, past the pull's one-minute overlap, so a pass that dropped one of them
    # would not simply read it back.
    async with _session() as session:
        await session.execute(
            text(
                "INSERT INTO revoked_tokens (token_hash, expires_at, revoked_at) "
                "SELECT :p || lpad(to_hex(i), 56, '0'), now() + interval '55 minutes', now() - interval '10 minutes' "
                "FROM generate_series(1, CAST(:n AS int)) AS i"
            ),
            {"p": prefix, "n": n},
        )
        await session.commit()
    try:
        redis = _Redis()
        a = await _boot(redis)
        victim = _track(db, _token(ttl=300))  # expires before every one of the others
        with a:
            await sr.revoke(redis, victim, int(time.time()) + 300)
        async with _session() as session:
            await session.execute(
                text("UPDATE revoked_tokens SET revoked_at = now() - interval '10 minutes' WHERE token_hash = ANY(:k)"),
                {"k": sr._keys(victim)},
            )
            await session.commit()
        with a:
            await sr.sync(redis)  # one pass, as every 10s
        redis.wipe()
        with a:
            assert await sr.is_revoked(redis, victim), "the process that served the logout no longer refuses it"
        with await _boot(redis):
            assert await sr.is_revoked(redis, victim), "a process that loaded Postgres does not refuse it"
            assert len(sr._mirror) >= n + len(sr._keys(victim))
    finally:
        async with _session() as session:
            await session.execute(text("DELETE FROM revoked_tokens WHERE token_hash LIKE :p"), {"p": f"{prefix}%"})
            await session.commit()


async def test_the_retry_queue_never_drops_a_logout_postgres_has_not_got(db) -> None:
    """A long Postgres outage queues every logout. With the queue capped like the mirror, the
    soonest-expiring logout was evicted from both after 5,000 more (10,000 keys): Postgres never got it,
    and after a Redis loss the process that served it accepted the token."""
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    now = int(time.time())
    victim = _track(db, _token(ttl=300))
    flaky.down = True
    with proc:
        await sr.revoke(redis, victim, now + 300)
        for _ in range(5_000):
            await sr.revoke(redis, _track(db, _token()), now + 3600)
        assert set(sr._keys(victim)) <= set(sr._unpersisted), "a logout Postgres never got left the queue"
        redis.wipe()
        assert await sr.is_revoked(redis, victim), "the process that served the logout no longer refuses it"
        flaky.down = False
        await sr.sync(redis)  # the database is back: one pass lands all of it
        assert sr._unpersisted == {}
    assert await _stored(sr._keys(victim)) == set(sr._keys(victim))


async def test_a_token_that_outlives_datetime_is_clamped_and_blocks_no_other_write(db) -> None:
    """The CLI mints with an unbounded --ttl. A key whose exp is past 9999-12-31 cannot become a
    timestamptz: its write raised ValueError, and because queued writes go as one batch, every other
    queued logout stayed out of Postgres with it, pass after pass."""
    redis = _Redis()
    flaky = _Flaky()
    proc = await _boot(redis, flaky)
    now = int(time.time())
    normal = _track(db, _token())
    claims = {"sub": "cli-admin", "role": "admin", "namespace": "*", "iat": now, "exp": 10**12}
    forever = _track(db, jwt.encode(claims, settings.api_secret_key, algorithm="HS256"))
    with proc:
        flaky.down = True
        await sr.revoke(redis, normal, now + 3600)  # queued
        flaky.down = False
        with structlog.testing.capture_logs() as logs:
            await sr.revoke(redis, forever, 10**12)
        assert not [e for e in logs if e.get("code") == "NRVQ-AUTH-14024"], logs
        await sr.sync(redis)
        assert sr._unpersisted == {}
    assert await _stored(sr._keys(normal) + sr._keys(forever)) == set(sr._keys(normal) + sr._keys(forever))
    redis.wipe()
    with await _boot(redis):
        assert await sr.is_revoked(redis, forever)


async def test_a_boot_imports_nothing_postgres_already_has(db, monkeypatch) -> None:
    """Redis rounds the remaining TTL to the nearest second, so a key can read back one second past its
    token's exp. Comparing expiries re-imported such a key (queued it, wrote it again) although Postgres
    had it; one key is one token with one exp, so only a key the mirror does not hold live is an import."""
    redis = _Redis()
    tok = _track(db, _token())
    with await _boot(redis):
        await sr.revoke(redis, tok, int(time.time()) + 3600)
    for key in sr._keys(tok):
        redis.store[key] += 1  # what a rounded TTL can read back
    sources = []
    real = sr._persist_or_queue

    async def spy(entries, *args, **kwargs):
        sources.append(kwargs.get("source"))
        return await real(entries, *args, **kwargs)

    monkeypatch.setattr(sr, "_persist_or_queue", spy)
    with await _boot(redis):
        assert await sr.is_revoked(redis, tok)
    assert "redis_import" not in sources


async def test_the_check_path_never_reads_postgres(db) -> None:
    redis = _Redis()
    counting = _Flaky()
    proc = await _boot(redis, counting)
    tok = _track(db, _token())
    with proc:
        await sr.revoke(redis, tok, int(time.time()) + 3600)
        before = counting.calls
        for _ in range(50):
            assert await sr.is_revoked(redis, tok)
            assert not await sr.is_revoked(redis, _token())
        assert counting.calls == before, "a revocation check opened a database session"


# --- the table stays bounded ----------------------------------------------------------------------


async def test_expired_rows_are_not_loaded_and_are_pruned(db) -> None:
    from norviq.api.audit_retention import RetentionPruner

    gone, live = f"{uuid.uuid4().hex}{uuid.uuid4().hex}", f"{uuid.uuid4().hex}{uuid.uuid4().hex}"
    db.extend([gone, live])
    now = datetime.now(timezone.utc)
    async with _session() as session:
        await session.execute(
            text("INSERT INTO revoked_tokens (token_hash, expires_at) VALUES (:g, :ge), (:l, :le)"),
            {"g": gone, "ge": now - timedelta(minutes=5), "l": live, "le": now + timedelta(minutes=30)},
        )
        await session.commit()
    redis = _Redis()
    with await _boot(redis) as proc:
        assert gone not in sr._mirror
        assert sr._mirror.get(live, 0) > time.time()
    # Expired entries leave the mirror in the background pass, never on a request.
    stale = sr.token_hash(_token())
    with proc:
        sr._mirror[stale] = int(time.time()) - 1
        assert not await sr.is_revoked(redis, "x.y.z")
        assert stale in sr._mirror  # the check did no work proportional to the mirror...
        await sr.sync(redis)
        assert stale not in sr._mirror  # ...the pass dropped it
    pruner = RetentionPruner()
    async with _session() as session:
        assert await pruner._prune_revoked_tokens(session) >= 1
        await session.commit()
    assert await _stored([gone, live]) == {live}
