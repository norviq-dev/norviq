# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The admin's freeze and trust cap must survive everything except an explicit, logged lift.

Reproduced on prep/0.2.6 (68a7cdb) against real Postgres and Redis before these fixes:

* ``PUT /agents/{id}/trust`` with score 0 on an identity that had no ``agent_registry`` row answered 200
  and wrote the freeze to Redis only. The durable write was ``UPDATE … WHERE spiffe_id``, which matched
  nothing, so a Redis flush or restart lifted the freeze (``warm_agent_overrides`` had no row to re-seed
  from). A failed database write was swallowed the same way.
* The retention pruner deleted registry rows unseen for 90 days, frozen ones included — a quarantined
  agent is quiet, which is what ``last_seen`` reads as decommissioned.

These run against the real Postgres (NRVQ_PG_URL) and Redis (NRVQ_REDIS_URL), as CI provides, through
the product's own routes, writers and warm path. Every identity is unique per test and removed after it.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
import structlog
from sqlalchemy import text

from norviq.api.db.session import (
    close_db,
    create_tables,
    ensure_schema_compatibility,
    get_session,
    init_db,
    upsert_agent_registry,
)
from norviq.api.main import create_app
from norviq.api.routers.agents import get_admin_db, warm_agent_overrides
from norviq.config import settings
from norviq.engine.cache import RedisCache


def _env(name: str) -> str:
    value = (os.getenv(name) or "").strip().strip("\"'")
    if not value:
        pytest.fail(f"{name} must be set for these PostgreSQL/Redis integration tests")
    return value


@pytest.fixture
async def env():
    old_url, old_rate = settings.pg_url, settings.http_rate_limit_enabled
    settings.pg_url = _env("NRVQ_PG_URL")
    # The HTTP rate limiter's fixed windows live in the shared test Redis; a re-run of this file inside one
    # window got 429s (review round 5). These tests are not about rate limiting.
    settings.http_rate_limit_enabled = False
    await init_db()
    await create_tables()
    await ensure_schema_compatibility()  # the API lifespan's upgrade path (widens agent-id columns, for one)
    cache = RedisCache(url=_env("NRVQ_REDIS_URL"))
    await cache.connect()
    app = create_app()
    app.state.cache = cache
    ids: list[str] = []
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    try:
        yield app, client, cache, ids
    finally:
        await client.aclose()
        for spiffe in ids:
            await cache._client().delete(
                *(
                    f"{p}:{spiffe}"
                    for p in (
                        "agent_frozen",
                        "agent_trust_override",
                        "agent_history",
                        "agent_profile",
                        "trust",
                        "trustcalc",
                    )
                )
            )
        async with _session() as session:
            await session.execute(text("DELETE FROM agent_registry WHERE spiffe_id = ANY(:ids)"), {"ids": ids})
            await session.commit()
        await cache.close()
        await close_db()
        settings.pg_url, settings.http_rate_limit_enabled = old_url, old_rate


class _session:
    async def __aenter__(self):
        self._gen = get_session()
        return await self._gen.__anext__()

    async def __aexit__(self, *_exc):
        await self._gen.aclose()


def _agent(ids: list[str], label: str) -> str:
    spiffe = f"spiffe://norviq/ns/ctl-test/sa/{label}-{uuid.uuid4().hex[:8]}"
    ids.append(spiffe)
    return spiffe


def _hdr(role: str = "admin", sub: str = "alice") -> dict[str, str]:
    token = jwt.encode(
        {"sub": sub, "role": role, "exp": int(time.time()) + 600}, settings.api_secret_key, algorithm="HS256"
    )
    return {"Authorization": f"Bearer {token}"}


async def _row(spiffe: str):
    async with _session() as session:
        return (
            (
                await session.execute(
                    text(
                        "SELECT frozen, trust_cap, namespace, agent_class, violation_count FROM agent_registry "
                        "WHERE spiffe_id = :s"
                    ),
                    {"s": spiffe},
                )
            )
            .mappings()
            .first()
        )


async def _redis_lost_everything(cache: RedisCache, spiffe: str) -> None:
    await cache._client().delete(f"agent_frozen:{spiffe}", f"agent_trust_override:{spiffe}")


# --- PUT /agents/{id}/trust is durable for an identity the registry has never seen ---------------------


async def test_freeze_on_an_unregistered_agent_survives_a_redis_flush_and_its_first_call(env) -> None:
    """FAIL-ON-BUG: before, the 200 came back with no registry row, so after the flush nothing re-froze it."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "never-called")

    resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    assert resp.status_code == 200
    row = await _row(spiffe)
    assert row is not None and row["frozen"] is True, "the freeze reached Redis only"
    assert (row["namespace"], row["agent_class"]) == ("ctl-test", spiffe.rsplit("/", 1)[1])

    await _redis_lost_everything(cache, spiffe)
    await warm_agent_overrides(cache)
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", "a restart did not put the freeze back"

    # The agent's first evaluated call goes through the evaluator's write-through upsert. Its conflict clause
    # must leave the admin's columns alone, or the first call would unfreeze it.
    async with _session() as session:
        await upsert_agent_registry(
            session,
            spiffe_id=spiffe,
            namespace="ctl-test",
            agent_class="x",
            trust_score=0.9,
            trust_category="High",
            violation=True,
        )
        await session.commit()
    row = await _row(spiffe)
    assert row["frozen"] is True and row["violation_count"] == 1


async def test_cap_on_an_unregistered_agent_is_durable_and_a_clear_does_not_invent_a_row(env) -> None:
    _, client, cache, ids = env
    capped = _agent(ids, "capped")
    assert (await client.put(f"/api/v1/agents/{capped}/trust", json={"score": 0.3}, headers=_hdr())).status_code == 200
    row = await _row(capped)
    assert row is not None and row["frozen"] is False and row["trust_cap"] == pytest.approx(0.3)
    await _redis_lost_everything(cache, capped)
    await warm_agent_overrides(cache)
    assert float(await cache._client().get(f"agent_trust_override:{capped}")) == pytest.approx(0.3)

    # Clearing an identity with no row: nothing durable to clear, and no phantom agent in the roster.
    cleared = _agent(ids, "cleared")
    assert (await client.put(f"/api/v1/agents/{cleared}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    assert await _row(cleared) is None


async def test_a_freeze_upsert_keeps_the_existing_rows_identity_and_counters(env) -> None:
    _, client, _, ids = env
    spiffe = _agent(ids, "known")
    async with _session() as session:
        await upsert_agent_registry(
            session,
            spiffe_id=spiffe,
            namespace="real-ns",
            agent_class="real-class",
            trust_score=0.5,
            trust_category="Medium",
            violation=True,
        )
        await session.commit()
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    row = await _row(spiffe)
    assert (row["frozen"], row["namespace"], row["agent_class"], row["violation_count"]) == (
        True,
        "real-ns",
        "real-class",
        1,
    )
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    row = await _row(spiffe)
    assert (row["frozen"], row["trust_cap"]) == (False, None)


class _BrokenDb:
    """The admin-write connector when Postgres cannot be reached."""

    async def connect(self):
        raise ConnectionRefusedError("database unavailable")


async def test_a_failed_durable_write_is_a_503_not_a_200(env) -> None:
    """FAIL-ON-BUG: the write sat in a try/except that logged NRVQ-API-7033 and returned 200 anyway.

    A freeze is still applied live first — Postgres being down must not stop an admin stopping an agent —
    but the caller is told it is not durable. An unfreeze is NOT applied live: a lift that the next restart
    silently undoes is worse than one that visibly failed."""
    app, client, cache, ids = env

    app.dependency_overrides[get_admin_db] = _BrokenDb
    try:
        spiffe = _agent(ids, "db-down")
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        assert resp.status_code == 503 and "NOT persisted" in resp.json()["detail"]
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"

        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
        assert resp.status_code == 503
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", "a failed unfreeze lifted the live freeze"
    finally:
        app.dependency_overrides.pop(get_admin_db, None)


async def test_retention_never_ages_out_a_frozen_or_capped_agent(env) -> None:
    """FAIL-ON-BUG: the pruner deleted every row unseen for agent_registry_retention_days, frozen included."""
    from norviq.api.audit_retention import RetentionPruner

    _, client, _, ids = env
    frozen, capped, stale = _agent(ids, "old-frozen"), _agent(ids, "old-capped"), _agent(ids, "old-plain")
    for spiffe, score in ((frozen, 0), (capped, 0.4), (stale, 0.4)):
        assert (
            await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": score}, headers=_hdr())
        ).status_code == 200
    old = datetime.now(timezone.utc) - timedelta(days=settings.agent_registry_retention_days + 5)
    async with _session() as session:
        await session.execute(
            text("UPDATE agent_registry SET frozen = false, trust_cap = NULL WHERE spiffe_id = :s"), {"s": stale}
        )
        await session.execute(
            text("UPDATE agent_registry SET last_seen = :t WHERE spiffe_id = ANY(:ids)"),
            {"t": old, "ids": [frozen, capped, stale]},
        )
        await session.commit()
        await RetentionPruner()._prune_agent_registry(session)
        await session.commit()
    assert (await _row(frozen))["frozen"] is True
    assert (await _row(capped))["trust_cap"] == pytest.approx(0.4)
    assert await _row(stale) is None, "an ordinary stale row must still age out"


# --- DELETE /agents/{id} no longer lifts a freeze or a cap as a side effect -------------------------------


async def _seed_registered(spiffe: str) -> None:
    async with _session() as session:
        await upsert_agent_registry(
            session,
            spiffe_id=spiffe,
            namespace="ctl-test",
            agent_class="x",
            trust_score=0.5,
            trust_category="Medium",
            violation=True,
        )
        await session.commit()


async def test_delete_refuses_a_frozen_agent_and_leaves_the_freeze_in_place(env) -> None:
    """FAIL-ON-BUG: DELETE removed the registry row (the durable freeze) AND deleted agent_frozen:, so the
    identity's next call ran unfrozen. Measured before the fix: 200, row None, agent_frozen: None."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "frozen")
    await _seed_registered(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    with structlog.testing.capture_logs() as logs:
        resp = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
    assert resp.status_code == 409
    assert "frozen" in resp.json()["detail"] and "score 1.0" in resp.json()["detail"]
    assert (await _row(spiffe))["frozen"] is True
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    refused = [entry for entry in logs if entry.get("code") == "NRVQ-API-7143"]
    assert refused and refused[0]["actor"] == "alice" and refused[0]["frozen"] is True


async def test_delete_refuses_a_capped_agent(env) -> None:
    _, client, cache, ids = env
    spiffe = _agent(ids, "capped")
    await _seed_registered(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())).status_code == 200
    resp = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
    assert resp.status_code == 409 and "trust cap" in resp.json()["detail"]
    assert (await _row(spiffe))["trust_cap"] == pytest.approx(0.3)
    assert await cache._client().get(f"agent_trust_override:{spiffe}") is not None


async def test_delete_refuses_a_freeze_that_exists_only_in_redis(env) -> None:
    """A freeze set before the registry carried it durably has no frozen row; the live key still counts."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "legacy-freeze")
    await _seed_registered(spiffe)
    await cache._client().set(f"agent_frozen:{spiffe}", "1")
    assert (await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())).status_code == 409
    assert await _row(spiffe) is not None and await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_delete_after_an_explicit_lift_works_and_keeps_history(env) -> None:
    """The intended path: lift (logged with its actor), then delete. History and profile survive DELETE."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "lifted")
    await _seed_registered(spiffe)
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})
    await cache._client().hset(f"agent_profile:{spiffe}", "known_tools", '["t"]')
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200

    with structlog.testing.capture_logs() as logs:
        resp = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
    assert resp.status_code == 200 and resp.json()["deleted"] is True
    assert await _row(spiffe) is None
    assert await cache._client().exists(f"agent_history:{spiffe}", f"agent_profile:{spiffe}") == 2
    line = [entry for entry in logs if entry.get("code") == "NRVQ-API-7121"][0]
    assert (line["frozen"], line["capped"], line["actor"]) == (False, False, "alice")


async def test_delete_fails_closed_when_redis_cannot_answer(env) -> None:
    app, client, _, ids = env
    spiffe = _agent(ids, "redis-down")
    await _seed_registered(spiffe)

    class _DownCache:
        def _client(self):
            raise ConnectionError("redis unreachable")

    real = app.state.cache
    app.state.cache = _DownCache()
    try:
        assert (await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())).status_code == 503
    finally:
        app.state.cache = real
    assert await _row(spiffe) is not None


# --- POST /agents/{id}/trust/reset: the one explicit, audited way to clear the behavioural record ---------


async def test_reset_clears_history_and_profile_writes_the_audit_line_and_keeps_the_freeze(env) -> None:
    _, client, cache, ids = env
    spiffe = _agent(ids, "reset")
    await _seed_registered(spiffe)
    now = time.time()
    await cache._client().zadd(
        f"agent_history:{spiffe}", {'{"decision": "block", "n": 1}': now, '{"decision": "allow", "n": 2}': now}
    )
    await cache._client().hset(f"agent_profile:{spiffe}", "known_tools", '["t"]')
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    with structlog.testing.capture_logs() as logs:
        resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr(sub="bob"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["keys_cleared"] == [f"agent_history:{spiffe}", f"agent_profile:{spiffe}"]
    assert (body["score_before"], body["violation_count"]) == (0.0, 1)
    assert (body["history_entries_cleared"], body["history_blocks_cleared"]) == (2, 1)
    assert await cache._client().exists(f"agent_history:{spiffe}", f"agent_profile:{spiffe}") == 0

    audit = [entry for entry in logs if entry.get("code") == "NRVQ-API-7145"]
    assert len(audit) == 1
    assert audit[0]["actor"] == "bob" and audit[0]["actor_role"] == "admin"
    assert audit[0]["score_before"] == 0.0 and audit[0]["keys_cleared"] == body["keys_cleared"]

    # Not a lift: the freeze is untouched in Redis and in the registry, and the cumulative count stays.
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    row = await _row(spiffe)
    assert row["frozen"] is True and row["violation_count"] == 1


async def test_reset_is_admin_only_and_404s_an_unknown_identity(env) -> None:
    _, client, cache, ids = env
    spiffe = _agent(ids, "viewer")
    await _seed_registered(spiffe)
    await cache._client().hset(f"agent_profile:{spiffe}", "known_tools", '["t"]')
    for role in ("viewer", "operator", "service"):
        resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr(role=role))
        assert resp.status_code == 403, role
    assert await cache._client().exists(f"agent_profile:{spiffe}") == 1
    unknown = _agent(ids, "unknown")
    assert (await client.post(f"/api/v1/agents/{unknown}/trust/reset", headers=_hdr())).status_code == 404


async def test_reset_fails_closed_when_redis_cannot_answer(env) -> None:
    app, client, _, ids = env
    spiffe = _agent(ids, "reset-down")
    await _seed_registered(spiffe)

    class _DownCache:
        async def get_trust(self, _spiffe):
            raise ConnectionError("redis unreachable")

    real = app.state.cache
    app.state.cache = _DownCache()
    try:
        resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    finally:
        app.state.cache = real
    assert resp.status_code == 503


async def test_the_trust_update_log_line_names_the_admin_who_made_it(env) -> None:
    """FAIL-ON-BUG: NRVQ-API-7031 is the record of a freeze being set or lifted, and it had no actor."""
    _, client, _, ids = env
    spiffe = _agent(ids, "who")
    with structlog.testing.capture_logs() as logs:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr(sub="carol"))
    assert resp.status_code == 200
    line = [entry for entry in logs if entry.get("code") == "NRVQ-API-7031"][0]
    assert (line["actor"], line["actor_role"], line["frozen"]) == ("carol", "admin", True)


# --- Admin trust writes for one agent are serialized (per-agent advisory lock) -----------------------------
#
# Found by independent review of the first version of these fixes: each route was correct alone, but two
# admin writes for the same agent could interleave so that Postgres and Redis disagreed with both callers
# told 200. These pause one request at a fixed point, run the other, and check the end state.


class _Proxy:
    """The real cache, with hooks. Everything not overridden goes to the real object."""

    def __init__(self, real) -> None:
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)


async def test_a_freeze_crossing_a_clear_leaves_postgres_and_redis_agreeing(env) -> None:
    """FAIL-ON-BUG (review B1). The clear is paused just before its Redis write. Unserialized, the freeze ran
    to completion meanwhile (row frozen, agent_frozen set, 200), then the clear's write deleted agent_frozen:
    the registry said frozen and the agent ran unfrozen until the next API restart. The agent has no row, so
    no row lock exists to serialize them; only the per-agent lock does."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "b1")
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseClear(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, *, frozen, cap, display=None):
            if not frozen and cap is None and not hit.is_set():
                hit.set()
                await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(
                spiffe_id, token, frozen=frozen, cap=cap, display=display
            )

    app.state.cache = _PauseClear(cache)
    try:
        clear = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        freeze = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr()))
        await asyncio.sleep(0.3)
        freeze_waited = not freeze.done()
        gate.set()
        responses = await asyncio.wait_for(asyncio.gather(clear, freeze), 10)
    finally:
        app.state.cache = cache
    assert [r.status_code for r in responses] == [200, 200]
    row = await _row(spiffe)
    live = await cache._client().get(f"agent_frozen:{spiffe}")
    assert (row is not None and row["frozen"], live) == (True, "1"), f"registry {row and dict(row)} vs live {live}"
    assert freeze_waited, "the freeze did not wait for the clear holding the agent's lock"


async def test_a_delete_crossing_a_freeze_never_loses_the_freeze(env) -> None:
    """FAIL-ON-BUG (review B2). DELETE is paused after it read the row and the live keys. Unserialized, a
    freeze committed onto that row meanwhile, then DELETE removed it by primary key and logged 7121
    frozen=false: the durable freeze was gone. Now the freeze waits for DELETE's lock (and DELETE's own
    delete is conditional on the row carrying no control), so whichever order wins, the freeze survives."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "b2")
    await _seed_registered(spiffe)
    gate, hit = asyncio.Event(), asyncio.Event()
    real_client = cache._client()

    class _PausedClient(_Proxy):
        async def get(self, key):
            value = await self._real.get(key)
            if key.startswith("agent_trust_override:") and not hit.is_set():
                hit.set()
                await gate.wait()
            return value

    class _PauseDeleteCheck(_Proxy):
        def _client(self):
            return _PausedClient(real_client)

    app.state.cache = _PauseDeleteCheck(cache)
    try:
        delete = asyncio.create_task(client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        app.state.cache = cache
        freeze = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr()))
        await asyncio.sleep(0.3)
        gate.set()
        d, f = await asyncio.wait_for(asyncio.gather(delete, freeze), 10)
    finally:
        app.state.cache = cache
    assert f.status_code == 200 and d.status_code in (200, 409)
    row = await _row(spiffe)
    assert row is not None and row["frozen"] is True, "the freeze was deleted with the row"
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_freeze_to_cap_never_leaves_an_agent_with_neither(env) -> None:
    """FAIL-ON-BUG (review N1). The cap was written as DEL agent_frozen: then SET agent_trust_override:; a
    Redis error between the two left the agent with no control at all. Here every plain SET to an override
    key fails: the change now goes in one MULTI, so it either lands whole or not at all."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n1")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    real_client = cache._client()

    class _SetFails(_Proxy):
        async def set(self, key, *a, **k):
            if key.startswith("agent_trust_override:"):
                raise ConnectionError("redis dropped")
            return await self._real.set(key, *a, **k)

    class _Cache(_Proxy):
        def _client(self):
            return _SetFails(real_client)

        async def set_trust_override(self, spiffe_id, score):
            raise ConnectionError("redis dropped")

    app.state.cache = _Cache(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
    except Exception:  # noqa: BLE001 - before the fix this surfaced as an unhandled error
        resp = None
    finally:
        app.state.cache = cache
    frozen = await cache._client().get(f"agent_frozen:{spiffe}")
    cap = await cache._client().get(f"agent_trust_override:{spiffe}")
    assert frozen is not None or cap is not None, "the agent was left neither frozen nor capped"
    row = await _row(spiffe)
    if resp is not None and resp.status_code == 200:
        assert (frozen, float(cap), row["trust_cap"]) == (None, 0.3, pytest.approx(0.3))


async def test_with_the_store_down_a_tightening_is_persisted_and_a_loosening_is_not_applied(env) -> None:
    """FAIL-ON-BUG (review N2). With Redis down a freeze was an unhandled 500 and nothing reached Postgres.
    A tightening (freeze, or a cap where there was none) is durable now and the 503 says it is not live yet;
    warm_agent_overrides applies it at the next start. A loosening (freeze to cap) changes nothing."""
    app, client, cache, ids = env
    spiffe, capped, lifted = _agent(ids, "n2"), _agent(ids, "n2cap"), _agent(ids, "n2lift")
    for agent in (spiffe, capped, lifted):
        await _seed_registered(agent)
    assert (await client.put(f"/api/v1/agents/{lifted}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    class _Down(_Proxy):
        def _client(self):
            raise ConnectionError("redis down")

        async def claim_admin_trust_owner(self, *a, **k):
            raise ConnectionError("redis down")

        async def apply_admin_trust_control_if_owner(self, *a, **k):
            raise ConnectionError("redis down")

    app.state.cache = _Down(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        cap_resp = await client.put(f"/api/v1/agents/{capped}/trust", json={"score": 0.3}, headers=_hdr())
        lift_resp = await client.put(f"/api/v1/agents/{lifted}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and "Persisted but NOT confirmed live" in resp.json()["detail"]
    assert (await _row(spiffe))["frozen"] is True
    assert cap_resp.status_code == 503 and (await _row(capped))["trust_cap"] == pytest.approx(0.3)
    await warm_agent_overrides(cache)
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    assert lift_resp.status_code == 503 and "not applied" in lift_resp.json()["detail"]
    assert (await _row(lifted))["frozen"] is True, "a loosening the store could not take was left durable"


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "%20",
        "not-a-spiffe-id",
        "spiffe://",
        "spiffe://%20%20",
        "x" * 20 + "spiffe://a",
        "spiffe://norviq/ns/a/sa/" + "x" * 600,
    ],
)
async def test_admin_trust_routes_refuse_an_id_the_product_does_not_accept(env, bad) -> None:
    """FAIL-ON-BUG (review N3). The upsert wrote a frozen registry row for any string, '*' and ' '
    included. PUT, reset and DELETE refuse exactly what the evaluator and POST /keys refuse — no
    "spiffe://" prefix, more than 512 characters — plus an id empty after the prefix (422), and write
    nothing. Counted for these exact ids, so rows another run left in a shared database cannot fail it."""
    from urllib.parse import unquote

    _, client, _, _ = env
    written = unquote(bad)
    resp = await client.put(f"/api/v1/agents/{bad}/trust", json={"score": 0}, headers=_hdr())
    assert resp.status_code == 422, resp.text
    assert (await client.post(f"/api/v1/agents/{bad}/trust/reset", headers=_hdr())).status_code == 422
    assert (await client.delete(f"/api/v1/agents/{bad}", headers=_hdr())).status_code == 422
    assert await _row(written) is None


@pytest.mark.parametrize(
    "label",
    [
        "spiffe://acme-agent-{u}",
        "spiffe://Acme.com/agent-{u}",
        "spiffe://norviq/ns/ctl-test/sa/agent:v2-{u}",
        "spiffe://norviq/ns/ctl-test/sa/agent@prod-{u}",
        "spiffe://norviq/ns/ctl-test/sa/my agent-{u}",
        "spiffe://norviq/ns/ctl-test/sa/b*-{u}",
        "spiffe://norviq/ns/ctl-test/sa/b?[0]-{u}",
    ],
)
async def test_an_id_the_product_mints_and_enforces_can_be_frozen_lifted_and_deleted(env, label) -> None:
    """Review rounds 2 and 3 (N10): POST /keys mints any spiffe_id up to 512 characters and the evaluator
    enforces any "spiffe://" id, whitespace and glob characters included. An earlier rule 422'd those, so
    such an agent's kill switch was lost. The id only names keys used with GET/SET/DEL/EVAL, never a SCAN
    pattern, so these are inert."""
    from urllib.parse import quote

    _, client, cache, ids = env
    spiffe = label.format(u=uuid.uuid4().hex[:8])
    ids.append(spiffe)
    path = quote(spiffe, safe="/:@")
    assert (await client.put(f"/api/v1/agents/{path}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    assert (await _row(spiffe))["frozen"] is True and await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    assert (await client.put(f"/api/v1/agents/{path}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    assert await cache._client().get(f"agent_frozen:{spiffe}") is None
    assert (await client.delete(f"/api/v1/agents/{path}", headers=_hdr())).status_code == 200


async def test_reset_counts_every_history_entry_it_deletes(env) -> None:
    """FAIL-ON-BUG (review N4). The counts came from get_history — the 1-hour window, read before the DEL —
    while the DEL removed the whole key, so an entry outside the window (or recorded between read and DEL)
    was wiped without being counted. They are read in the same MULTI as the DEL now."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "n4")
    await _seed_registered(spiffe)
    await cache._client().zadd(
        f"agent_history:{spiffe}",
        {'{"decision": "block", "n": 1}': time.time() - 7200, '{"decision": "allow", "n": 2}': time.time()},
    )
    resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    assert resp.status_code == 200
    assert (resp.json()["history_entries_cleared"], resp.json()["history_blocks_cleared"]) == (2, 1)


async def test_reset_never_touches_a_cap_and_is_all_or_nothing(env) -> None:
    """Review N5: the cap key survives a reset; a reset whose MULTI fails clears nothing; the cluster guard
    refuses a reset aimed at another cluster before anything is cleared."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n5")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())).status_code == 200
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})
    await cache._client().hset(f"agent_profile:{spiffe}", "known_tools", '["t"]')

    other_cluster = {**_hdr(), "X-Nrvq-Target-Cluster": "cluster-b"}
    assert (await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=other_cluster)).status_code == 409
    assert await cache._client().exists(f"agent_history:{spiffe}", f"agent_profile:{spiffe}") == 2

    real_client = cache._client()

    class _FailingPipe:
        def __init__(self, pipe):
            self._pipe = pipe

        def __getattr__(self, name):
            return getattr(self._pipe, name)

        async def execute(self):
            raise ConnectionError("redis dropped mid-MULTI")

    class _PipeCtx:
        def __init__(self, ctx):
            self._ctx = ctx

        async def __aenter__(self):
            return _FailingPipe(await self._ctx.__aenter__())

        async def __aexit__(self, *exc):
            return await self._ctx.__aexit__(*exc)

    class _Client(_Proxy):
        def pipeline(self, *a, **k):
            return _PipeCtx(self._real.pipeline(*a, **k))

    class _Cache(_Proxy):
        def _client(self):
            return _Client(real_client)

    app.state.cache = _Cache(cache)
    try:
        assert (await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())).status_code == 503
    finally:
        app.state.cache = cache
    assert await cache._client().exists(f"agent_history:{spiffe}", f"agent_profile:{spiffe}") == 2

    assert (await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())).status_code == 200
    assert await cache._client().exists(f"agent_history:{spiffe}", f"agent_profile:{spiffe}") == 0
    assert float(await cache._client().get(f"agent_trust_override:{spiffe}")) == pytest.approx(0.3)


async def test_a_cap_is_not_applied_live_when_its_durable_write_fails(env) -> None:
    """Review N5: a cap (which can lift a freeze) reaches Redis only after its registry write succeeded."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n5cap")

    app.dependency_overrides[get_admin_db] = _BrokenDb
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503
    assert await cache._client().get(f"agent_trust_override:{spiffe}") is None


async def test_delete_refuses_a_cap_that_exists_only_in_redis(env) -> None:
    """Review N5: the live cap key counts, as the live freeze key does."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "n5redis")
    await _seed_registered(spiffe)
    await cache._client().set(f"agent_trust_override:{spiffe}", "0.3")
    resp = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
    assert resp.status_code == 409 and "trust cap" in resp.json()["detail"]
    assert await _row(spiffe) is not None


async def test_a_boot_warm_never_writes_back_a_cap_or_freeze_an_admin_changed_meanwhile(env) -> None:
    """FAIL-ON-BUG (raised in review of the boot-warm retry). A starting pod's warm reads every frozen or
    capped row, then writes each to the store. Between the two another replica tightened one cap and lifted
    one freeze; the warm then wrote the stale snapshot back: the looser cap, and a freeze nobody holds.
    Now each agent is re-read under its admin lock just before its SET."""
    _, client, cache, ids = env
    capped, frozen = _agent(ids, "warm-cap"), _agent(ids, "warm-frozen")
    assert (await client.put(f"/api/v1/agents/{capped}/trust", json={"score": 0.5}, headers=_hdr())).status_code == 200
    assert (await client.put(f"/api/v1/agents/{frozen}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseAfterSnapshot(_Proxy):
        async def execute(self, stmt, *a, **k):
            result = await self._real.execute(stmt, *a, **k)
            if "frozen = true OR trust_cap IS NOT NULL" in str(stmt) and not hit.is_set():
                hit.set()
                await gate.wait()
            return result

    async def _factory():
        gen = get_session()
        try:
            yield _PauseAfterSnapshot(await gen.__anext__())
        finally:
            await gen.aclose()

    warm = asyncio.create_task(warm_agent_overrides(cache, _factory))
    await asyncio.wait_for(hit.wait(), 5)
    assert (await client.put(f"/api/v1/agents/{capped}/trust", json={"score": 0.2}, headers=_hdr())).status_code == 200
    assert (await client.put(f"/api/v1/agents/{frozen}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    gate.set()
    await asyncio.wait_for(warm, 10)
    assert float(await cache._client().get(f"agent_trust_override:{capped}")) == pytest.approx(0.2)
    assert await cache._client().get(f"agent_frozen:{frozen}") is None, "the warm re-froze a lifted freeze"


# --- Round-2 review: the commit-failure path, lock contention, a hung store, and pinning each guard -----------


class _HeldLock:
    """Another admin write holding one agent's lock: its own transaction, open until the block ends."""

    def __init__(self, spiffe: str) -> None:
        self._spiffe = spiffe

    async def __aenter__(self):
        self._gen = get_session()
        self.session = await self._gen.__anext__()
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"agent_trust:{self._spiffe}"}
        )
        return self.session

    async def __aexit__(self, *_exc):
        await self.session.rollback()
        await self._gen.aclose()


@pytest.fixture
def short_waits(monkeypatch):
    import norviq.api.routers.agents as agents_mod

    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 300)
    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 0.3)
    return agents_mod


async def test_every_admin_route_waits_for_the_agents_lock_and_only_a_freeze_goes_live(env, short_waits) -> None:
    """Pins the lock in PUT, DELETE and the reset (round 2, N7/N11; round 4, N14). While another admin write
    holds the agent, a cap, a DELETE and a reset answer 503 'in progress' and change nothing. A freeze is the
    kill switch: it steals the fence and is applied live (503 'freeze applied live, NOT persisted'), so the
    holder's later fenced write cannot lift it."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "held")
    await _seed_registered(spiffe)
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})
    async with _HeldLock(spiffe):
        cap = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
        delete = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
        reset = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
        assert await cache._client().get(f"agent_trust_override:{spiffe}") is None, "a contended cap went live"
        freeze = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    for resp in (cap, delete, reset):
        assert resp.status_code == 503 and "in progress" in resp.json()["detail"], resp.text
    assert freeze.status_code == 503 and freeze.json()["detail"].startswith("Freeze applied live but NOT persisted")
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    row = await _row(spiffe)
    assert row is not None and row["frozen"] is False
    assert await cache._client().exists(f"agent_history:{spiffe}") == 1


async def test_a_freeze_steals_the_fence_from_a_stranded_loosening(env, short_waits, monkeypatch) -> None:
    """Round 4, N14: a clear holds the agent (committed, paused before its store write) past the lock timeout.
    A freeze arrives, cannot get the lock, steals the fence and goes live. When the clear resumes, its fenced
    write is a no-op: the store ends frozen."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "steal")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseLoosening(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, *, frozen, cap, display=None):
            if not frozen and not hit.is_set():
                hit.set()
                await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(
                spiffe_id, token, frozen=frozen, cap=cap, display=display
            )

    import norviq.api.routers.agents as agents_mod

    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 30)  # the paused clear must not be cut off meanwhile
    app.state.cache = _PauseLoosening(cache)
    try:
        clear = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        freeze = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        gate.set()
        clear_resp = await asyncio.wait_for(clear, 10)
    finally:
        app.state.cache = cache
    assert freeze.status_code == 503 and freeze.json()["detail"].startswith("Freeze applied live")
    assert clear_resp.status_code == 503
    assert await _live(cache, spiffe) == (True, None), "the stranded clear lifted a live freeze"


async def test_a_hung_store_is_cut_off_and_does_not_hold_the_lock(env, short_waits) -> None:
    """Round 2, N8: a store that hangs (not refuses) kept the lock and a DB connection ~20 s per request.
    Every store call under the lock is bounded; a cap against a hung store is a prompt 503 and the agent's
    lock is free again straight after."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "hung")

    class _Hung(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            await asyncio.Event().wait()

    app.state.cache = _Hung(cache)
    try:
        started = time.monotonic()
        resp = await asyncio.wait_for(
            client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr()), 15
        )
        elapsed = time.monotonic() - started
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and elapsed < 3, (resp.status_code, elapsed)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())).status_code == 200


async def test_a_reset_whose_lock_release_fails_still_reports_and_audits_what_it_cleared(env) -> None:
    """Round 2, N9: the reset writes nothing to Postgres; ending its hold on the agent only releases the
    lock. A failure there used to answer 503 'nothing was cleared' with no 7145, after the history was
    deleted. Here pg_advisory_unlock itself fails: the connection is invalidated and the answer stands."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n9")
    await _seed_registered(spiffe)
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})

    _admin_db(app, unlock_fails=True)
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 200 and resp.json()["history_entries_cleared"] == 1
    assert [entry["code"] for entry in logs if entry.get("code") in ("NRVQ-API-7145", "NRVQ-API-7146")] == [
        "NRVQ-API-7145"
    ]


async def test_the_conditional_delete_alone_keeps_a_freeze_that_committed_after_the_check(env, monkeypatch) -> None:
    """Pins DELETE's `WHERE frozen = false AND trust_cap IS NULL` on its own (round 2, N11): with the lock
    disabled, a freeze committed between DELETE's check and its delete must make the delete a 409."""
    import norviq.api.routers.agents as agents_mod

    @asynccontextmanager
    async def _no_lock(db, _spiffe_id):
        conn = await db.connect()
        try:
            yield conn
        finally:
            await conn.rollback()
            await conn.close()

    monkeypatch.setattr(agents_mod, "_agent_lock", _no_lock)
    await test_a_delete_crossing_a_freeze_never_loses_the_freeze(env)


class _Spy(_Proxy):
    """Records every pipeline the code opens: its transaction flag and how many times it executed."""

    def __init__(self, real, seen: list) -> None:
        super().__init__(real)
        self._seen = seen

    def pipeline(self, *a, **k):
        record = {"transaction": k.get("transaction", a[0] if a else True), "executes": 0}
        self._seen.append(record)
        ctx = self._real.pipeline(*a, **k)

        class _Ctx:
            async def __aenter__(_self):
                pipe = await ctx.__aenter__()

                class _P(_Proxy):
                    async def execute(_p, *ea, **ek):
                        record["executes"] += 1
                        return await pipe.execute(*ea, **ek)

                return _P(pipe)

            async def __aexit__(_self, *exc):
                return await ctx.__aexit__(*exc)

        return _Ctx()


async def test_the_control_write_is_one_script_and_the_reset_one_multi(env) -> None:
    """Pins the atomicity claims (round 2, N11): the fenced freeze/cap write is ONE script call (owner check
    and every key in one atomic step), and the reset's read-and-delete is ONE transactional pipeline executed
    once — not separate round-trips, not a plain pipeline."""
    _, _, cache, ids = env
    spiffe = _agent(ids, "multi")
    seen: list = []
    evals: list = []
    real_client = cache._client()

    class _EvalSpy(_Spy):
        async def eval(self, *a, **k):
            evals.append(a[0][:40])
            return await self._real.eval(*a, **k)

    class _Cache(_Proxy):
        def _client(self):
            return _EvalSpy(real_client, seen)

    spy = _Cache(cache)
    token = await RedisCache.claim_admin_trust_owner(spy, spiffe, None)
    assert await RedisCache.apply_admin_trust_control_if_owner(spy, spiffe, token, frozen=False, cap=0.3) == 1
    # Two scripts: the claim (owner compare-and-raise) and the write (owner check plus every key), no pipeline.
    assert len(evals) == 2 and seen == []
    assert evals[0].lstrip().startswith("local cur") and evals[1].lstrip().startswith("local owner")
    import norviq.api.routers.agents as agents_mod

    await agents_mod._reset_multi(spy, f"agent_history:{spiffe}", f"agent_profile:{spiffe}")
    assert seen == [{"transaction": True, "executes": 1}]
    await cache._client().delete(f"agent_trust_owner:{spiffe}")


# --- Boot warm: batched, locked, resumable ----------------------------------------------------------------


async def test_the_boot_warm_waits_for_an_admin_write_in_progress(env) -> None:
    """Pins the warm's lock (round 2, N11): an admin write holding an agent's lock with its row change not
    yet committed must be waited for, or the warm re-reads the old committed row and writes it after."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "warm-held")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())).status_code == 200
    async with _HeldLock(spiffe) as admin:
        await admin.execute(text("UPDATE agent_registry SET trust_cap = 0.2 WHERE spiffe_id = :s"), {"s": spiffe})
        await cache._client().set(f"agent_trust_override:{spiffe}", "0.2")
        warm = asyncio.create_task(warm_agent_overrides(cache))
        await asyncio.sleep(0.5)
        assert not warm.done(), "the warm did not wait for the agent's lock"
        await admin.commit()
    await asyncio.wait_for(warm, 30)
    assert float(await cache._client().get(f"agent_trust_override:{spiffe}")) == pytest.approx(0.2)


async def test_the_boot_warm_releases_each_batch_and_resumes_after_it(env, short_waits) -> None:
    """Round 2, R1: one transaction per agent was ~3.4 ms/agent and a retry restarted from the top, so past
    ~2.8k agents the same tail was never warmed. Batches commit as they go (an admin write on a finished
    batch's agent is not blocked) and a retry resumes from the last committed spiffe_id."""
    _, client, cache, ids = env
    first, second = sorted([_agent(ids, "batch-a"), _agent(ids, "batch-b")])
    for spiffe in (first, second):
        assert (
            await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        ).status_code == 200
        await cache._client().delete(f"agent_frozen:{spiffe}")
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseSecondBatch(_Proxy):
        async def execute(self, stmt, params=None, *a, **k):
            result = await self._real.execute(stmt, params, *a, **k)
            if "spiffe_id > :after" in str(stmt) and (params or {}).get("after") == first and not hit.is_set():
                hit.set()
                await gate.wait()
            return result

    async def _factory():
        gen = get_session()
        try:
            yield _PauseSecondBatch(await gen.__anext__())
        finally:
            await gen.aclose()

    progress = {"after": first[:-1]}
    warm = asyncio.create_task(warm_agent_overrides(cache, _factory, progress, batch_size=1))
    await asyncio.wait_for(hit.wait(), 10)
    assert progress["after"] == first and await cache._client().get(f"agent_frozen:{first}") == "1"
    # The first batch committed, so its agent's lock is free: an admin write is not held up by the warm.
    assert (await client.put(f"/api/v1/agents/{first}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    warm.cancel()  # the attempt is cut off here, as warm_with_backoff's 10 s bound does
    with pytest.raises(asyncio.CancelledError):
        await warm
    gate.set()
    await cache._client().delete(f"agent_frozen:{first}")
    await warm_agent_overrides(cache, progress=progress, batch_size=1)  # the retry
    assert await cache._client().get(f"agent_frozen:{second}") == "1"
    assert await cache._client().get(f"agent_frozen:{first}") is None, "the retry restarted from the top"


# --- Round 3: ordering by direction under one session-level lock, the owner fence, and the warm cursor --------


class _ConnProxy(_Proxy):
    """The admin-write connection, with hooks. Commit #1 takes the lock, #2 is the trust write."""

    def __init__(self, real, hooks: dict) -> None:
        super().__init__(real)
        self._hooks = hooks

    async def execute(self, stmt, *a, **k):
        if self._hooks.get("unlock_fails") and "pg_advisory_unlock" in str(stmt):
            raise ConnectionError("connection lost during unlock")
        if self._hooks.get("hang_after_lock") and self._hooks["commits"] >= 1:
            await asyncio.Event().wait()  # Postgres stopped answering once the lock was granted
        return await self._real.execute(stmt, *a, **k)

    async def rollback(self):
        if self._hooks.get("hang_after_lock") and self._hooks["commits"] >= 1:
            await asyncio.Event().wait()
        return await self._real.rollback()

    async def commit(self):
        self._hooks["commits"] += 1
        if self._hooks["commits"] == self._hooks.get("fail_commit_n"):
            if self._hooks.get("landed"):
                await self._real.commit()
            else:
                await self._real.rollback()
            raise ConnectionError("connection lost during COMMIT")
        return await self._real.commit()


def _admin_db(app, **hooks) -> dict:
    import norviq.api.routers.agents as agents_mod

    hooks.setdefault("commits", 0)

    class _Db:
        async def connect(self):
            return _ConnProxy(await agents_mod._EngineConnector().connect(), hooks)

    app.dependency_overrides[get_admin_db] = _Db
    return hooks


async def _live(cache, spiffe: str) -> tuple[bool, float | None]:
    frozen = await cache._client().get(f"agent_frozen:{spiffe}")
    cap = await cache._client().get(f"agent_trust_override:{spiffe}")
    return bool(frozen), (float(cap) if cap is not None else None)


async def _durable(spiffe: str) -> tuple[bool, float | None]:
    row = await _row(spiffe)
    return (False, None) if row is None else (bool(row["frozen"]), row["trust_cap"])


@pytest.mark.parametrize(
    "prior,new,tightening",
    [
        ((False, None), (True, None), True),  # freeze added
        ((True, None), (True, None), True),  # re-freeze
        ((False, 0.5), (True, None), True),  # cap -> freeze
        ((False, None), (False, 0.3), True),  # cap added
        ((False, 0.5), (False, 0.3), True),  # cap lowered
        ((False, 0.5), (False, 0.5), True),  # unchanged
        ((False, None), (False, None), True),  # clear of nothing
        ((True, None), (False, 0.3), False),  # freeze -> cap
        ((True, None), (False, None), False),  # freeze lifted
        ((False, 0.3), (False, 0.5), False),  # cap raised
        ((False, 0.3), (False, None), False),  # cap removed
    ],
)
def test_each_trust_change_is_classified_by_direction(prior, new, tightening) -> None:
    from norviq.api.routers.agents import _is_tightening

    assert _is_tightening(prior, new) is tightening


async def test_a_tightening_whose_commit_fails_is_live_and_says_it_may_not_be_persisted(env) -> None:
    """Review round 3: tightening writes go to the store first, so a failed commit leaves the store stricter
    than the registry — never looser — and the 503 says exactly that. No reconcile."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "t-fail")
    await _seed_registered(spiffe)
    _admin_db(app, fail_commit_n=2)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Applied live, but it may NOT be persisted")
    assert await _live(cache, spiffe) == (False, 0.3) and await _durable(spiffe) == (False, None)


async def test_a_tightening_whose_commit_ack_is_lost_is_live_persisted_and_answered_truthfully(env) -> None:
    app, client, cache, ids = env
    spiffe = _agent(ids, "t-ack")
    await _seed_registered(spiffe)
    _admin_db(app, fail_commit_n=2, landed=True)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and "may NOT be persisted" in resp.json()["detail"]
    assert await _live(cache, spiffe) == (True, None) == await _durable(spiffe)


async def test_a_loosening_whose_commit_fails_leaves_the_store_stricter_and_says_not_applied(env) -> None:
    """Review round 3: a loosening reaches the store only after its commit succeeded."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "l-fail")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    _admin_db(app, fail_commit_n=2)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Trust change not confirmed")
    assert "store was not touched" in resp.json()["detail"]
    assert await _live(cache, spiffe) == (True, None) == await _durable(spiffe)


async def test_a_loosening_whose_commit_ack_is_lost_keeps_the_store_stricter_until_retried(env) -> None:
    """Review round 3, (3): the registry took the clear but the client never heard. The store keeps the
    freeze (stricter than the registry, never looser), the 503 says so, and a retry converges."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "l-ack")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    _admin_db(app, fail_commit_n=2, landed=True)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and "store was not touched" in resp.json()["detail"]
    assert await _durable(spiffe) == (False, None) and await _live(cache, spiffe) == (True, None)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    assert await _live(cache, spiffe) == (False, None)


async def test_a_loosening_the_store_does_not_take_after_its_commit_says_persisted_and_stricter(env) -> None:
    app, client, cache, ids = env
    spiffe = _agent(ids, "l-store")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    class _FencedWriteFails(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            raise ConnectionError("redis gone")

    app.state.cache = _FencedWriteFails(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Persisted, but the store did not confirm")
    assert "Retry, or restart the API" in resp.json()["detail"]
    assert await _durable(spiffe) == (False, pytest.approx(0.4)) and await _live(cache, spiffe) == (True, None)


async def _terminate_lock_holder(spiffe: str) -> None:
    async with _session() as session:
        await session.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                "AND objid::bigint = (hashtext(:k)::bigint & 4294967295) AND pid <> pg_backend_pid()"
            ),
            {"k": f"agent_trust:{spiffe}"},
        )


async def test_a_loosening_that_lost_its_lock_after_committing_cannot_land_over_a_newer_freeze(env) -> None:
    """Review round 3: the owner fence. A clear commits, then its connection drops (the lock goes with it)
    before its store write. A freeze from another replica takes the agent and completes with 200. The
    clear's late store write must not land: it is fenced on agent_trust_owner:<id>, which the freeze
    re-claimed. Without the fence the store ends unfrozen while the registry says frozen."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "fence")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseFencedWrite(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            hit.set()
            await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(*a, **k)

    app.state.cache = _PauseFencedWrite(cache)
    try:
        clear = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        await _terminate_lock_holder(spiffe)
        app.state.cache = cache
        freeze = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        gate.set()
        clear_resp = await asyncio.wait_for(clear, 10)
    finally:
        app.state.cache = cache
    assert freeze.status_code == 200 and clear_resp.status_code == 503
    assert await _durable(spiffe) == (True, None)
    assert await _live(cache, spiffe) == (True, None), "a late loosening landed over a newer freeze"


async def test_a_connection_whose_unlock_fails_is_never_returned_to_the_pool_holding_the_lock(env) -> None:
    """Review round 3: the lock is session-level, so a pooled connection that still held it would block that
    agent's next admin write for as long as the connection lives. If pg_advisory_unlock does not answer
    true, the connection is invalidated and Postgres drops the lock with the backend."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "unlock")
    _admin_db(app, unlock_fails=True)
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 200
    assert [e["code"] for e in logs if e.get("code") == "NRVQ-API-7150"] == ["NRVQ-API-7150"]
    held = None
    for _ in range(20):  # the backend ends asynchronously after the connection is invalidated
        async with _session() as session:
            held = (
                await session.execute(
                    text(
                        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                        "AND objid::bigint = (hashtext(:k)::bigint & 4294967295)"
                    ),
                    {"k": f"agent_trust:{spiffe}"},
                )
            ).scalar()
        if not held:
            break
        await asyncio.sleep(0.1)
    assert held == 0, "a connection went back to the pool still holding the agent's lock"
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200


async def test_the_startup_warm_resumes_after_a_failed_batch_in_spiffe_id_order(env, monkeypatch) -> None:
    """Review rounds 2-4: the attempts of warm_agent_overrides_at_startup share one cursor. A batch that fails
    is retried from the last committed batch; agents already written are not written again; and batches go in
    spiffe_id order even when the rows are stored out of order (an unordered LIMIT plus a cursor skips agents).
    Scoped to its own ids: the cursor starts just before them and nothing else sorts after them."""
    import norviq.api.routers.agents as agents_mod
    from norviq.api.routers.agents import warm_agent_overrides_at_startup

    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-warm-{uuid.uuid4().hex[:8]}"
    agents = [f"{prefix}/{n}" for n in "abc"]
    ids.extend(agents)
    async with _session() as session:
        for spiffe in reversed(agents):  # stored c, b, a
            await session.execute(
                text(
                    "INSERT INTO agent_registry (id, spiffe_id, namespace, agent_class, trust_score, trust_category, "
                    "violation_count, last_seen, created_at, frozen) VALUES (gen_random_uuid(), :s, 'w', 'w', 0, "
                    "'Frozen', 0, now(), now(), true)"
                ),
                {"s": spiffe},
            )
        await session.commit()
    monkeypatch.setattr(agents_mod, "_WARM_BATCH", 1)
    real_warm = agents_mod.warm_agent_overrides

    async def _scoped(cache_, factory, progress=None, batch_size=None):
        progress.setdefault("after", prefix)
        return await real_warm(cache_, _factory, progress, batch_size)

    monkeypatch.setattr(agents_mod, "warm_agent_overrides", _scoped)

    class _NoIndexOrder(_Proxy):
        """Correctness must not hang on the planner happening to walk the spiffe_id index: without one, the
        rows come back in storage order (c, b, a), and only ORDER BY keeps the cursor from skipping."""

        async def execute(self, stmt, *a, **k):
            if "spiffe_id > :after" in str(stmt):
                await self._real.execute(text("SET LOCAL enable_indexscan = off"))
                await self._real.execute(text("SET LOCAL enable_bitmapscan = off"))
                await self._real.execute(text("SET LOCAL enable_indexonlyscan = off"))
            return await self._real.execute(stmt, *a, **k)

    async def _factory():
        gen = get_session()
        try:
            yield _NoIndexOrder(await gen.__anext__())
        finally:
            await gen.aclose()

    writes: dict[str, int] = {}
    failed: list[str] = []

    class _Cache(_Proxy):
        async def warm_admin_trust_controls(self, token, entries):
            if any(e[0] == agents[1] for e in entries) and not failed:
                failed.append("once")
                raise ConnectionError("store dropped mid-warm")
            for spiffe_id, _f, _c in entries:
                writes[spiffe_id] = writes.get(spiffe_id, 0) + 1
            return await self._real.warm_admin_trust_controls(token, entries)

    seeded = await asyncio.wait_for(warm_agent_overrides_at_startup(_Cache(cache)), 30)
    assert failed == ["once"]
    assert seeded == 3, seeded
    for spiffe in agents:
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", spiffe
    assert writes == {agents[0]: 1, agents[1]: 1, agents[2]: 1}, writes


async def test_a_warm_write_that_lands_after_an_admin_change_is_a_no_op(env) -> None:
    """Review round 4, C1 (warm_late_write.py): a warm attempt cut off by its bound may still land its writes
    later. They are fenced: once an admin write has re-claimed the agent, the warm's write does nothing."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "warm-late")
    warm_token = "warm-" + uuid.uuid4().hex
    async with cache._client().pipeline(transaction=False) as pipe:  # the warm claimed it ...
        await pipe.set(f"agent_trust_owner:{spiffe}", warm_token, px=30_000)
        await pipe.execute()
    # ... then an admin lifted the freeze the warm read (a clear claims the agent and writes)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())).status_code == 200
    # the warm's late write lands now
    keys = [f"agent_trust_owner:{spiffe}", f"agent_frozen:{spiffe}", f"agent_trust_override:{spiffe}"]
    assert await cache._client().eval(RedisCache._FENCED_WARM_LUA, 3, *keys, warm_token, "1", "") == 0
    assert await cache._client().get(f"agent_frozen:{spiffe}") is None


async def test_a_late_tightening_write_cannot_land_over_a_newer_freeze(env, short_waits) -> None:
    """Review round 4, C1: A's store write is cut off by the 2 s bound but is already on the wire; A commits,
    answers 'persisted, NOT live' and releases the lock; B freezes (200); A's write then lands. Unfenced it
    deleted the freeze and set A's cap. Fenced, B's claim makes it a no-op."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "late-tight")
    held: dict = {}
    real = cache

    class _SlowFenced(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, **k):
            held.setdefault("call", (spiffe_id, token, k))
            await asyncio.Event().wait()  # cut off by _store's bound; replayed below as the late landing

    app.state.cache = _SlowFenced(real)
    try:
        a = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())
    finally:
        app.state.cache = real
    assert a.status_code == 503 and a.json()["detail"].startswith("Persisted but NOT confirmed live")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    spiffe_id, token, k = held["call"]
    assert await real.apply_admin_trust_control_if_owner(spiffe_id, token, **k) == RedisCache.FENCE_LOST
    assert await _live(cache, spiffe) == (True, None) == await _durable(spiffe)


# --- Round 4 -------------------------------------------------------------------------------------------------


async def _advisory_held(spiffe: str) -> int:
    held = 0
    for _ in range(30):  # an invalidated backend ends asynchronously
        async with _session() as session:
            held = (
                await session.execute(
                    text(
                        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                        "AND objid::bigint = (hashtext(:k)::bigint & 4294967295)"
                    ),
                    {"k": f"agent_trust:{spiffe}"},
                )
            ).scalar()
        if not held:
            return 0
        await asyncio.sleep(0.1)
    return held


async def test_a_lock_granted_before_its_commit_failed_never_reaches_the_pool(env) -> None:
    """Round 4, N13: pg_advisory_lock was granted, then the COMMIT that ends the acquire failed. The lock may
    be held, so the connection is invalidated rather than closed into the pool. The freeze still goes live
    through the stolen fence and says it is not persisted."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n13")
    _admin_db(app, fail_commit_n=1, landed=True)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Freeze applied live but NOT persisted")
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    assert await _advisory_held(spiffe) == 0, "a connection that may hold the agent's lock went back to the pool"


async def test_a_loosening_whose_fence_vanished_is_rewritten_once_and_never_claimed_stricter(env) -> None:
    """Round 4, N15 / round 5: the owner key disappeared (a flush) between the claim and the write, taking the
    freeze with it. A vanished fence (unlike a lost one) is retried once under a fresh claim, which converges the
    store on the committed state; if the store keeps losing it, the answer may not claim it is still stricter."""
    app, client, cache, ids = env
    for label, flushes, expected in (("n15-once", 1, 200), ("n15-always", 99, 503)):
        spiffe = _agent(ids, label)
        assert (
            await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        ).status_code == 200
        left = {"n": flushes}

        class _Flushed(_Proxy):
            async def apply_admin_trust_control_if_owner(self, spiffe_id, token, **k):
                if left["n"]:
                    left["n"] -= 1
                    await self._real._client().delete(f"agent_trust_owner:{spiffe_id}", f"agent_frozen:{spiffe_id}")
                return await self._real.apply_admin_trust_control_if_owner(spiffe_id, token, **k)

        app.state.cache = _Flushed(cache)
        try:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
        finally:
            app.state.cache = cache
        assert resp.status_code == expected, (label, resp.text)
        if expected == 200:
            assert await _live(cache, spiffe) == (False, None) == await _durable(spiffe)
        else:
            assert resp.json()["detail"].startswith("Persisted, but the store did not confirm")


async def test_a_delete_whose_commit_ack_is_lost_says_it_may_have_been_deleted(env) -> None:
    """Round 4, N16."""
    app, client, _, ids = env
    spiffe = _agent(ids, "n16")
    await _seed_registered(spiffe)
    _admin_db(app, fail_commit_n=2, landed=True)
    try:
        resp = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and "may have been deleted" in resp.json()["detail"]
    assert await _row(spiffe) is None


async def test_a_burst_on_one_agent_with_a_hung_store_does_not_exhaust_the_pool(env, short_waits, monkeypatch) -> None:
    """Round 4, N17: 25 writes to one agent while its store write hangs. Each used to wait on pg_advisory_lock
    holding a pooled connection, which exhausted the pool (10 + 5) for every other request. Now one per process
    holds a connection; the rest wait in-process and answer 503 'in progress' without one."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "n17")
    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 3.0)
    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 3000)  # the default: waiters outlast the pool

    class _Hung(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            await asyncio.Event().wait()

    app.state.cache = _Hung(cache)
    try:
        burst = [
            asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr()))
            for _ in range(25)
        ]
        await asyncio.sleep(0.5)
        started = time.monotonic()
        async with _session() as session:
            assert (await session.execute(text("SELECT 1"))).scalar() == 1
        unrelated = time.monotonic() - started
        responses = await asyncio.wait_for(asyncio.gather(*burst), 30)
    finally:
        app.state.cache = cache
    assert unrelated < 1.0, f"an unrelated query waited {unrelated:.1f}s for a pooled connection"
    assert {r.status_code for r in responses} == {503}


async def test_an_exhausted_pool_gets_its_own_answer(env) -> None:
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    app, client, _, ids = env
    spiffe = _agent(ids, "pool")

    class _NoConnections:
        async def connect(self):
            raise PoolTimeout("QueuePool limit of size 10 overflow 5 reached")

    app.dependency_overrides[get_admin_db] = _NoConnections
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and "connection pool is exhausted" in resp.json()["detail"]


@pytest.mark.parametrize("command_timeout,expected_ms", [(5, 3000), (30, 3000), (4, 2000), (3, 1000), (2, 200)])
def test_the_lock_timeout_stays_below_the_command_timeout(monkeypatch, command_timeout, expected_ms) -> None:
    from norviq.api.routers.agents import _lock_timeout_ms

    monkeypatch.setattr(settings, "db_command_timeout", command_timeout)
    assert _lock_timeout_ms() == expected_ms


async def test_an_id_of_exactly_512_characters_is_accepted_and_513_is_not(env) -> None:
    """512 characters is the bound everywhere: the width of the registry column (review round 7)."""
    _, client, _, ids = env
    longest = "spiffe://" + "a" * 503
    ids.append(longest)
    assert len(longest) == 512
    assert (await client.put(f"/api/v1/agents/{longest}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    assert (await _row(longest))["frozen"] is True
    assert (await client.put(f"/api/v1/agents/{longest}b/trust", json={"score": 0}, headers=_hdr())).status_code == 422


async def test_a_tightening_with_the_store_down_and_its_commit_unconfirmed_says_it_may_be_persisted(env) -> None:
    """Round 4, C2: the store failed and the commit failed or lost its ack — the code cannot tell which, so the
    answer must not claim 'not applied'."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "c2")

    class _StoreDown(_Proxy):
        async def claim_admin_trust_owner(self, *a, **k):
            raise ConnectionError("redis down")

    app.state.cache = _StoreDown(cache)
    _admin_db(app, fail_commit_n=2, landed=True)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.state.cache = cache
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Not confirmed: the change may be persisted")
    assert await _durable(spiffe) == (True, None)


async def test_the_fenced_write_keeps_the_displayed_score_and_the_owner_key_on_a_ttl(env) -> None:
    _, client, cache, ids = env
    spiffe = _agent(ids, "ttl")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())).status_code == 200
    assert 0 < await cache._client().ttl(f"trust:{spiffe}") <= settings.redis_ttl_trust_s * 2
    from norviq.api.routers.agents import _owner_ttl_ms

    assert 30_000 <= _owner_ttl_ms()
    assert 0 < await cache._client().pttl(f"agent_trust_owner:{spiffe}") <= _owner_ttl_ms()


@pytest.fixture
def separate_replicas(monkeypatch):
    """Requests in this process stand for different API replicas: no in-process gate, only Postgres' lock."""
    import norviq.api.routers.agents as agents_mod

    @asynccontextmanager
    async def _no_gate(_spiffe_id):
        yield

    monkeypatch.setattr(agents_mod, "_local_gate", _no_gate)


async def test_across_replicas_a_freeze_crossing_a_clear_still_agrees(env, separate_replicas) -> None:
    """The in-process gate serializes one replica's requests by itself; across replicas only the Postgres
    lock does, and it must be held across the store write (session-level, not released at the acquire)."""
    await test_a_freeze_crossing_a_clear_leaves_postgres_and_redis_agreeing(env)


async def test_across_replicas_a_delete_crossing_a_freeze_never_loses_it(env, separate_replicas) -> None:
    await test_a_delete_crossing_a_freeze_never_loses_the_freeze(env)


# --- Round 5 -------------------------------------------------------------------------------------------------


class _LateClaimClient(_Proxy):
    """The store link of a warm, where a dead writer's late claim (a SET cut off on the wire) lands right after
    the warm's own claim pipeline, `rounds` times."""

    def __init__(self, real, spiffe: str, rounds: int) -> None:
        super().__init__(real)
        self._spiffe, self._rounds = spiffe, rounds

    def pipeline(self, *a, **k):
        outer, ctx = self, self._real.pipeline(*a, **k)

        class _Ctx:
            async def __aenter__(_self):
                pipe = await ctx.__aenter__()
                claims: list[str] = []

                class _P(_Proxy):
                    async def eval(_p, script, numkeys, *args):
                        if script.lstrip().startswith("local cur"):  # the claim script, not the fenced add
                            claims.extend(args[:numkeys])
                        return await pipe.eval(script, numkeys, *args)

                    async def execute(_p, *ea, **ek):
                        result = await pipe.execute(*ea, **ek)
                        if outer._rounds and f"agent_trust_owner:{outer._spiffe}" in claims:
                            outer._rounds -= 1
                            await outer._real.set(f"agent_trust_owner:{outer._spiffe}", "dead-writer", px=30_000)
                        return result

                return _P(pipe)

            async def __aexit__(_self, *exc):
                return await ctx.__aexit__(*exc)

        return _Ctx()


class _LossyWarmCache(_Proxy):
    """The real cache, with the warm's store link replaced (the method runs against this object's _client)."""

    def __init__(self, real, spiffe: str, rounds: int) -> None:
        super().__init__(real)
        self._link = _LateClaimClient(real._client(), spiffe, rounds)

    def _client(self):
        return self._link

    async def warm_admin_trust_controls(self, *a, **k):
        return await RedisCache.warm_admin_trust_controls(self, *a, **k)


async def _seed_frozen_rows(agents: list[str]) -> None:
    async with _session() as session:
        for spiffe in agents:
            await session.execute(
                text(
                    "INSERT INTO agent_registry (id, spiffe_id, namespace, agent_class, trust_score, trust_category, "
                    "violation_count, last_seen, created_at, frozen) VALUES (gen_random_uuid(), :s, 'w', 'w', 0, "
                    "'Frozen', 0, now(), now(), true)"
                ),
                {"s": spiffe},
            )
        await session.commit()


async def test_the_warm_reclaims_after_a_dead_writers_late_claim(env) -> None:
    """FAIL-ON-BUG (review round 5, D1). A late claim landed between the warm's claim and its fenced add; the
    warm read FENCE_LOST as 'an admin took over', counted the agent handled and moved on, so a freeze answered
    'applied at the next API start' stayed un-enforced after that start. The warm holds the agents' locks, so
    no live writer owns them: it re-claims and re-adds."""
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-late-claim-{uuid.uuid4().hex[:8]}"
    spiffe = f"{prefix}/a"
    ids.append(spiffe)
    await _seed_frozen_rows([spiffe])
    lossy = _LossyWarmCache(cache, spiffe, rounds=1)
    progress = {"after": prefix}
    seeded = await warm_agent_overrides(lossy, progress=progress)
    assert lossy._link._rounds == 0, "the late claim was never injected"
    assert seeded == 1 and await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_a_warm_agent_that_cannot_take_its_fence_is_skipped_named_and_retried(env) -> None:
    """Round 5, D1 / round 6, F1: if re-claiming does not help either, the agent is not counted and not silently
    passed over: the rest of the table is written, the agent is retried at the end of the attempt, and if it
    still does not take its control the attempt fails naming it (NRVQ-API-7160), so warm_with_backoff retries."""
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-late-claim-{uuid.uuid4().hex[:8]}"
    stuck, fine = f"{prefix}/a", f"{prefix}/b"
    ids.extend([stuck, fine])
    await _seed_frozen_rows([stuck, fine])
    progress = {"after": prefix}
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(RuntimeError, match=stuck):
            await warm_agent_overrides(_LossyWarmCache(cache, stuck, rounds=99), progress=progress)
    assert progress["skipped"] == {stuck} and progress["seeded"] == 1
    assert await cache._client().get(f"agent_frozen:{fine}") == "1"
    # Named before the retry (so it is in the log even if the attempt is then cut off) and again when it stays.
    assert [(e["phase"], e["spiffe_ids"]) for e in logs if e.get("code") == "NRVQ-API-7160"] == [
        ("retrying", [stuck]),
        ("unwritten", [stuck]),
    ]
    # The next attempt (same progress) retries only the skipped agent, and now it lands.
    assert await warm_agent_overrides(cache, progress=progress) == 2
    assert await cache._client().get(f"agent_frozen:{stuck}") == "1" and progress["skipped"] == set()


async def test_one_stuck_agent_lock_does_not_stop_the_warm_for_the_rest(env, short_waits) -> None:
    """Review round 6, F1: a backend holding one agent's lock (an API node that vanished mid-transaction) made
    every batch from that agent's on fail, on every attempt: 0 of 3000 freezes restored after a store flush.
    The warm try-locks, skips the held agent, writes everything else, and names the held one."""
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-stuck-{uuid.uuid4().hex[:8]}"
    agents = [f"{prefix}/{n}" for n in "abcde"]
    ids.extend(agents)
    await _seed_frozen_rows(agents)
    progress = {"after": prefix}
    async with _HeldLock(agents[1]):
        with pytest.raises(RuntimeError, match=agents[1]):
            await asyncio.wait_for(warm_agent_overrides(cache, progress=progress, batch_size=2), 20)
    for spiffe in agents:
        expected = None if spiffe == agents[1] else "1"
        assert await cache._client().get(f"agent_frozen:{spiffe}") == expected, spiffe
    assert await warm_agent_overrides(cache, progress=progress) == 5
    assert await cache._client().get(f"agent_frozen:{agents[1]}") == "1"


async def test_a_loosening_after_a_not_live_tightening_does_not_claim_the_store_is_stricter(env) -> None:
    """FAIL-ON-BUG (review round 5, D2). A freeze the store could not take (503 'NOT live') left the store
    older and looser than the registry; a following loosening whose store write also failed answered 'the
    store still enforces the previous, stricter state', which was false (the agent was unpoliced)."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "d2")

    class _StoreFails(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            raise ConnectionError("redis dropped")

    app.state.cache = _StoreFails(cache)
    try:
        first = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        second = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert first.status_code == 503 and first.json()["detail"].startswith("Persisted but NOT confirmed live")
    detail = second.json()["detail"]
    assert second.status_code == 503 and "still enforces the previous, stricter state" not in detail
    assert "holds whatever it held before this change" in detail and "older than the registry" in detail
    assert await _durable(spiffe) == (False, 0.5) and await _live(cache, spiffe) == (False, None)


async def test_a_loosening_whose_store_write_fails_once_converges_on_the_retry(env) -> None:
    """Round 5, D2: the committed state is written once more under a fresh claim before answering."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "d2retry")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    failed: list = []

    class _FailsOnce(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            if not failed:
                failed.append(1)
                raise ConnectionError("redis blip")
            return await self._real.apply_admin_trust_control_if_owner(*a, **k)

    app.state.cache = _FailsOnce(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 200 and failed == [1]
    assert await _live(cache, spiffe) == (False, 0.5) == await _durable(spiffe)


class _LoseFence(_Proxy):
    """Another claim lands between this request's claim and its fenced write."""

    async def apply_admin_trust_control_if_owner(self, spiffe_id, token, **k):
        await self._real.claim_admin_trust_owner(spiffe_id, "someone-else")
        return await self._real.apply_admin_trust_control_if_owner(spiffe_id, token, **k)


async def test_a_tightening_that_loses_its_fence_is_not_answered_as_live(env) -> None:
    """Round 5 mutation gap: FENCE_LOST is not 'live'. The store refused it, and the answer says why (round 7)."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "tlost")
    app.state.cache = _LoseFence(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.state.cache = cache
    detail = resp.json()["detail"]
    assert resp.status_code == 503 and detail.startswith("Persisted but NOT live: the store write was refused")
    assert "a newer change owns the agent" in detail and "did not answer" not in detail
    assert await _live(cache, spiffe) == (False, None)


async def test_a_loosening_whose_store_write_is_refused_says_a_newer_change_owns_the_agent(env) -> None:
    """Round 7: a FENCE_LOST after the commit is a refusal (a newer change owns the agent), not a store that did
    not answer; the answer says which, and the store keeps the newer change's state."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "llost")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    app.state.cache = _LoseFence(cache)
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.state.cache = cache
    detail = resp.json()["detail"]
    assert resp.status_code == 503 and detail.startswith("Persisted, but NOT live: the store write was refused")
    assert "a newer change owns the agent" in detail and "did not confirm" not in detail
    assert "store holds" not in detail  # round 8: not verified (the newer writer's own write may not have landed)
    failed = [e for e in logs if e.get("code") == "NRVQ-API-7147"]
    assert failed and failed[0]["error"].startswith("fence:"), failed  # round 8: it was logged with error=''
    assert await _live(cache, spiffe) == (True, None)


async def test_a_loosening_whose_claim_is_refused_applies_nothing_and_says_why(env) -> None:
    """Round 7: the loosening's claim refused (a newer owner) is 'refused', not 'the store did not answer'."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "lrefused")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    class _Refuse(_Proxy):
        async def claim_admin_trust_owner(self, spiffe_id, token, ttl_ms=None):
            return None

    app.state.cache = _Refuse(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.state.cache = cache
    detail = resp.json()["detail"]
    assert resp.status_code == 503 and detail.startswith("Trust change not applied: refused, a newer change owns")
    assert "did not answer" not in detail
    assert await _live(cache, spiffe) == (True, None)
    assert await _durable(spiffe) == (True, None)


async def test_a_steal_that_loses_its_fence_is_not_answered_as_live(env, short_waits) -> None:
    app, client, cache, ids = env
    spiffe = _agent(ids, "slost")
    await _seed_registered(spiffe)
    app.state.cache = _LoseFence(cache)
    try:
        async with _HeldLock(spiffe):
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Trust change not applied")
    assert await cache._client().get(f"agent_frozen:{spiffe}") is None


async def test_the_real_fenced_script_deletes_a_cap_on_a_clear(env) -> None:
    """Round 5 mutation gap: only the fake cache's emulation of the cap delete was tested."""
    _, _, cache, ids = env
    spiffe = _agent(ids, "lua")
    for frozen, cap in ((False, 0.3), (True, None), (False, None)):
        token = uuid.uuid4().hex
        await cache.claim_admin_trust_owner(spiffe, token)
        assert await cache.apply_admin_trust_control_if_owner(spiffe, token, frozen=frozen, cap=cap) == 1
        assert await _live(cache, spiffe) == (frozen, cap)


async def test_the_warm_cursor_follows_the_ordered_ids_not_the_batch_rows(env) -> None:
    """Round 5 mutation gap: the cursor must come from the ORDERED id list; the re-read rows (ANY(:ids)) come
    back in storage order, and a cursor taken from them re-warms or skips agents."""
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-cursor-{uuid.uuid4().hex[:8]}"
    agents = [f"{prefix}/{n}" for n in "abcd"]
    ids.extend(agents)
    await _seed_frozen_rows(list(reversed(agents)))  # stored d, c, b, a
    writes: dict[str, int] = {}

    class _Count(_Proxy):
        async def warm_admin_trust_controls(self, token, entries, *a, **k):
            for spiffe_id, _f, _c in entries:
                writes[spiffe_id] = writes.get(spiffe_id, 0) + 1
            return await self._real.warm_admin_trust_controls(token, entries, *a, **k)

    class _SeqScan(_Proxy):
        async def execute(self, stmt, *a, **k):
            if "agent_registry" in str(stmt):
                for setting in ("enable_indexscan", "enable_bitmapscan", "enable_indexonlyscan"):
                    await self._real.execute(text(f"SET LOCAL {setting} = off"))
            return await self._real.execute(stmt, *a, **k)

    async def _factory():
        gen = get_session()
        try:
            yield _SeqScan(await gen.__anext__())
        finally:
            await gen.aclose()

    assert await warm_agent_overrides(_Count(cache), _factory, {"after": prefix}, batch_size=2) == 4
    assert writes == dict.fromkeys(agents, 1), writes


async def test_admin_writes_in_one_process_never_take_more_than_half_the_pool(env, short_waits, monkeypatch) -> None:
    """Round 5: the per-agent gate does not bound writes to DIFFERENT agents; each holds a pooled connection
    through its store calls. A process-wide cap of half the pool keeps the rest for everything else."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    monkeypatch.setattr(settings, "pg_pool_size", 2)  # one admin slot
    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 3.0)
    agents_mod._slots.clear()
    first, second = _agent(ids, "slot-a"), _agent(ids, "slot-b")
    gate, hit = asyncio.Event(), asyncio.Event()

    class _Pause(_Proxy):
        async def apply_admin_trust_control_if_owner(self, *a, **k):
            if not hit.is_set():
                hit.set()
                await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(*a, **k)

    app.state.cache = _Pause(cache)
    try:
        held = asyncio.create_task(client.put(f"/api/v1/agents/{first}/trust", json={"score": 0.4}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        other = await client.put(f"/api/v1/agents/{second}/trust", json={"score": 0.4}, headers=_hdr())
        gate.set()
        assert (await asyncio.wait_for(held, 10)).status_code == 200
    finally:
        app.state.cache = cache
        agents_mod._slots.clear()
    assert other.status_code == 503 and "too many admin trust changes" in other.json()["detail"]


async def _session_settings(names) -> dict[str, str]:
    """What a connection checked out of the engine's pool reports for ``names`` (the pool hands back the
    connection the admin write used, so its settings must be the server's again)."""
    import norviq.api.routers.agents as agents_mod

    conn = await agents_mod._EngineConnector().connect()
    try:
        return {n: (await conn.execute(text(f"SHOW {n}"))).scalar() for n in names}
    finally:
        await conn.rollback()
        await conn.close()


async def test_the_admin_connection_bounds_its_idle_time_and_resets_it_before_the_pool(env) -> None:
    """Rounds 5-6: a backend whose API side vanished kept the agent's lock until TCP keepalive (hours), also
    while idle INSIDE a transaction, where idle_session_timeout does not apply. The admin connection sets
    idle_session_timeout, idle_in_transaction_session_timeout and TCP keepalives before taking the lock, and
    puts every one back to the server's value before the connection returns to the pool."""
    app, client, _, ids = env
    spiffe = _agent(ids, "idle")
    seen: list[tuple[str, object]] = []

    class _Record(_Proxy):
        async def execute(self, stmt, *a, **k):
            seen.append((str(stmt), a[0] if a else None))
            return await self._real.execute(stmt, *a, **k)

    import norviq.api.routers.agents as agents_mod

    class _Db:
        async def connect(self):
            return _Record(await agents_mod._EngineConnector().connect())

    before = await _session_settings(agents_mod._ADMIN_SESSION_SETTINGS)
    app.dependency_overrides[get_admin_db] = _Db
    try:
        assert (
            await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        ).status_code == 200
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    applied = {p["n"]: p["v"] for sql, p in seen if "set_config(:n, :v" in sql}
    assert set(applied) == set(agents_mod._ADMIN_SESSION_SETTINGS)
    assert (
        applied["idle_in_transaction_session_timeout"]
        == applied["idle_session_timeout"]
        == f"{agents_mod._owner_ttl_ms()}ms"
    )
    lock_at = next(i for i, (sql, _) in enumerate(seen) if "pg_advisory_lock" in sql)
    first_set = next(i for i, (sql, _) in enumerate(seen) if "set_config(:n, :v" in sql)
    reset_at = next(i for i, (sql, _) in enumerate(seen) if "reset_val" in sql)
    assert first_set < lock_at < reset_at
    assert await _session_settings(agents_mod._ADMIN_SESSION_SETTINGS) == before


async def test_an_id_whose_namespace_is_longer_than_the_column_can_still_be_frozen(env) -> None:
    """Round 5: the derived namespace/class went into String(255) columns, so such an id's freeze could never
    be persisted; they are truncated (display fields the evaluator's own upsert overwrites)."""
    _, client, _, ids = env
    spiffe = f"spiffe://norviq/ns/{'n' * 300}/sa/x-{uuid.uuid4().hex[:6]}"
    ids.append(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    row = await _row(spiffe)
    assert row["frozen"] is True and len(row["namespace"]) == 255


async def test_a_tightening_that_lost_its_fence_to_a_stolen_freeze_does_not_retry_over_it(
    env, short_waits, monkeypatch
) -> None:
    """Round 5: a write retries under a fresh claim only after a store error or a vanished owner key, never after
    FENCE_LOST — a newer claim may be a stolen freeze, and re-claiming would write a cap over it."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "tsteal")
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseFirst(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, *, frozen, cap, display=None):
            if not frozen and not hit.is_set():
                hit.set()
                await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(
                spiffe_id, token, frozen=frozen, cap=cap, display=display
            )

    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 30)
    app.state.cache = _PauseFirst(cache)
    try:
        capping = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        freeze = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        gate.set()
        cap_resp = await asyncio.wait_for(capping, 10)
    finally:
        app.state.cache = cache
    assert freeze.status_code == 503 and freeze.json()["detail"].startswith("Freeze applied live")
    assert cap_resp.status_code == 503 and cap_resp.json()["detail"].startswith(
        "Persisted but NOT live: the store write was refused, because a newer change owns the agent")
    assert await _live(cache, spiffe) == (True, None)


async def test_stolen_freezes_do_not_starve_the_lock_holding_writes_after_them(env, short_waits) -> None:
    """Round 7: each steal used to set the owner to current + 1, so K steals ran the owner K ahead of the
    global sequence and the next K lock-holding writes were refused. A steal now bumps a steal count beside the
    last lock holder's token: the next lock holder (a newer sequence token) wins at once."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "steals")
    await _seed_registered(spiffe)
    async with _HeldLock(spiffe) as session:
        # The agent's last lock holder took the sequence's latest token, so the next tokens are 1, 2, 3 ahead.
        last = (await session.execute(text("SELECT nextval('agent_trust_fence_seq')"))).scalar()
        await cache._client().set(f"agent_trust_owner:{spiffe}", str(last))
        for _ in range(5):
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
            assert resp.status_code == 503 and resp.json()["detail"].startswith("Freeze applied live")
    for score, state in ((0.4, (False, 0.4)), (1.0, (False, None)), (0.3, (False, 0.3))):
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": score}, headers=_hdr())
        assert resp.status_code == 200, resp.text
        assert await _live(cache, spiffe) == state


async def test_the_claim_script_orders_lock_holders_and_steals(env) -> None:
    """Round 7, the real script: a steal fences off the writer it took the fence from (its re-claim and its write
    are refused), never a newer lock holder; a late claim with an older token is still refused (monotonic)."""
    from norviq.engine.cache import RedisCache

    _, _, cache, ids = env
    spiffe = _agent(ids, "claimseq")
    assert await cache.claim_admin_trust_owner(spiffe, 10) == "10"
    stolen = await cache.claim_admin_trust_owner(spiffe, None)
    assert stolen == "10:1" and await cache.claim_admin_trust_owner(spiffe, None) == "10:2"
    assert await cache.apply_admin_trust_control_if_owner(spiffe, 10, frozen=False, cap=0.5) == RedisCache.FENCE_LOST
    assert await cache.claim_admin_trust_owner(spiffe, 10) is None      # the writer the steal fenced off
    assert await cache.claim_admin_trust_owner(spiffe, 9) is None       # a dead writer's late claim
    assert await cache.claim_admin_trust_owner(spiffe, 11) == "11"      # the next lock holder: not starved
    assert await cache.claim_admin_trust_owner(spiffe, 10) is None      # still monotonic after it
    assert await cache.claim_admin_trust_owner(spiffe, 11) == "11"      # the same holder re-claims (no steal since)
    assert await cache.apply_admin_trust_control_if_owner(spiffe, 11, frozen=False, cap=0.5) == RedisCache.FENCE_APPLIED
    await cache._client().set(f"agent_trust_owner:{spiffe}", "7")      # an older release's plain-number owner
    assert await cache.claim_admin_trust_owner(spiffe, None) == "7:1"
    assert await cache.claim_admin_trust_owner(spiffe, 8) == "8"
    await cache._client().delete(f"agent_trust_owner:{spiffe}")
    assert await cache.claim_admin_trust_owner(spiffe, None) == "0:1"   # a steal on a missing owner key
    assert await cache.claim_admin_trust_owner(spiffe, 1) == "1"


@pytest.mark.parametrize("owner", ["inf", "nan", "1e400", "0x20", " 12", "-5", "10:", "abc", "7:x", "7:1:1"])
async def test_the_claim_script_reads_a_malformed_owner_as_token_0(env, owner) -> None:
    """Review round 8: Lua's tonumber read 'inf', '1e400' and '0x20' as numbers, so such an owner refused every
    lock-holding claim until it expired. Only digits are a token; anything else is 0."""
    _, _, cache, ids = env
    spiffe = _agent(ids, "claimbad")
    await cache._client().set(f"agent_trust_owner:{spiffe}", owner)
    assert await cache.claim_admin_trust_owner(spiffe, 5) == "5"
    await cache._client().set(f"agent_trust_owner:{spiffe}", owner)
    assert await cache.claim_admin_trust_owner(spiffe, None) == "0:1"


async def test_the_claim_script_compares_large_tokens_exactly(env) -> None:
    """Review round 8: tokens past 2^53 lost precision as Lua numbers, and a steal wrote them as '1.2e+14'. They
    are compared as digit strings now (sequence values never get near; this keeps the order exact anyway)."""
    _, _, cache, ids = env
    spiffe = _agent(ids, "claimbig")
    big = "123456789012345678901"
    assert await cache.claim_admin_trust_owner(spiffe, big) == big
    assert await cache.claim_admin_trust_owner(spiffe, None) == big + ":1"
    assert await cache.claim_admin_trust_owner(spiffe, big) is None              # fenced off by the steal
    assert await cache.claim_admin_trust_owner(spiffe, "123456789012345678900") is None
    assert await cache.claim_admin_trust_owner(spiffe, "123456789012345678902") == "123456789012345678902"
    assert await cache.claim_admin_trust_owner(spiffe, "99999999999999999999") is None  # fewer digits: older


async def test_writers_queued_on_one_agent_do_not_take_slots_from_other_agents(env, short_waits, monkeypatch) -> None:
    """Round 5: the per-agent gate is entered before a process slot, so a queue behind one agent waits without
    a slot (or a connection) and a write to another agent still gets through."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    monkeypatch.setattr(settings, "pg_pool_size", 4)  # two admin slots
    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 3.0)
    # Long enough that a queued writer holding a slot (without the gate) would outlast the other agent's wait.
    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 2000)
    agents_mod._slots.clear()
    busy, other = _agent(ids, "q-busy"), _agent(ids, "q-other")
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseBusy(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, *a, **k):
            if spiffe_id == busy:
                hit.set()
                await gate.wait()
            return await self._real.apply_admin_trust_control_if_owner(spiffe_id, *a, **k)

    app.state.cache = _PauseBusy(cache)
    try:
        holder = asyncio.create_task(client.put(f"/api/v1/agents/{busy}/trust", json={"score": 0.4}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        queued = [
            asyncio.create_task(client.put(f"/api/v1/agents/{busy}/trust", json={"score": 0.4}, headers=_hdr()))
            for _ in range(3)
        ]
        await asyncio.sleep(0.5)  # the queued writers reach the gate (or, without one, a slot) first
        started = time.monotonic()
        elsewhere = await client.put(f"/api/v1/agents/{other}/trust", json={"score": 0.4}, headers=_hdr())
        waited = time.monotonic() - started
        gate.set()
        await asyncio.wait_for(asyncio.gather(holder, *queued), 15)
    finally:
        app.state.cache = cache
        agents_mod._slots.clear()
    assert elsewhere.status_code == 200, elsewhere.text
    assert waited < 1.0, f"the other agent's write waited {waited:.1f}s for a slot held by a queued writer"


# --- Round 6 -------------------------------------------------------------------------------------------------


async def test_the_warm_reclaims_for_up_to_three_rounds(env) -> None:
    """Round 6 mutation gap: a late claim landing twice is still overcome on the third round."""
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-late-claim-{uuid.uuid4().hex[:8]}"
    spiffe = f"{prefix}/a"
    ids.append(spiffe)
    await _seed_frozen_rows([spiffe])
    calls: list = []

    class _Counting(_LossyWarmCache):
        async def warm_admin_trust_controls(self, *a, **k):
            calls.append(1)
            return await super().warm_admin_trust_controls(*a, **k)

    lossy = _Counting(cache, spiffe, rounds=2)
    assert await warm_agent_overrides(lossy, progress={"after": prefix}) == 1
    assert lossy._link._rounds == 0 and await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    assert calls == [1], "the batch's own re-claim rounds did not overcome it; it fell to the skipped-agent retry"


async def test_a_writer_whose_lock_connection_died_does_not_claim_the_fence(env) -> None:
    """Round 6, non-blocking (a): the liveness check runs before the FIRST claim too. A backend killed after
    the registry read used to claim anyway; that claim could land inside another writer's change."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "deadconn")
    claims: list = []

    class _CountClaims(_Proxy):
        async def claim_admin_trust_owner(self, *a, **k):
            claims.append(a)
            return await self._real.claim_admin_trust_owner(*a, **k)

    class _DeadAfterRead(_ConnProxy):
        async def execute(self, stmt, *a, **k):
            if str(stmt) == "SELECT 1":  # the liveness probe: the session is gone
                raise ConnectionError("connection lost")
            return await super().execute(stmt, *a, **k)

    import norviq.api.routers.agents as agents_mod

    hooks = {"commits": 0}

    class _Db:
        async def connect(self):
            return _DeadAfterRead(await agents_mod._EngineConnector().connect(), hooks)

    app.dependency_overrides[get_admin_db] = _Db
    app.state.cache = _CountClaims(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.state.cache = cache
        app.dependency_overrides.pop(get_admin_db, None)
    assert claims == [], "a writer that may have lost its lock claimed the fence"
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Persisted but NOT confirmed live")


async def test_monitor_mode_does_not_let_an_unfreezable_identity_run(env) -> None:
    """Review round 6, F2: in a monitor namespace the invalid-identity block was softened to allow+audit, so an
    identity the admin routes refuse ran there, unfreezable. It stays a block in every posture."""
    from norviq.engine.evaluator import _posture_exempt_rules

    assert "invalid_spiffe_identity" in _posture_exempt_rules()


async def test_a_freeze_goes_live_quickly_when_postgres_does_not_answer_the_connect(env, monkeypatch) -> None:
    """Round 6, non-blocking (b): with Postgres partitioned the connect hung for the driver's timeout (60 s)
    before the freeze fell back to being applied live; the CLI had given up at 10 s."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "hangconn")
    monkeypatch.setattr(agents_mod, "_CONNECT_TIMEOUT_S", 0.3)

    class _Hangs:
        async def connect(self):
            await asyncio.Event().wait()

    app.dependency_overrides[get_admin_db] = _Hangs
    try:
        started = time.monotonic()
        resp = await asyncio.wait_for(
            client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr()), 15
        )
        elapsed = time.monotonic() - started
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Freeze applied live but NOT persisted")
    assert elapsed < 2.0 and await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_a_claim_from_a_writer_that_lost_its_lock_cannot_win_over_a_later_freeze(env, separate_replicas) -> None:
    """FAIL-ON-BUG (review round 6, lostlock_claim.py). H (cap 0.4) loses its lock connection while its claim
    is on the way; B, on another replica, freezes with 200; then H's claim lands. With a random token it won
    and H's cap replaced B's freeze in the store (store looser than the registry). Fence tokens now come from
    a Postgres sequence taken under the lock, so B's is larger and H's late claim is refused."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "lostlock")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())).status_code == 200
    gate, hit = asyncio.Event(), asyncio.Event()

    class _PauseFirstClaim(_Proxy):
        async def claim_admin_trust_owner(self, *a, **k):
            if not hit.is_set():
                hit.set()
                await gate.wait()
            return await self._real.claim_admin_trust_owner(*a, **k)

    app.state.cache = _PauseFirstClaim(cache)
    try:
        h = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr()))
        await asyncio.wait_for(hit.wait(), 5)
        await _terminate_lock_holder(spiffe)
        app.state.cache = cache
        b = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        app.state.cache = _PauseFirstClaim(cache)
        gate.set()
        h_resp = await asyncio.wait_for(h, 15)
    finally:
        app.state.cache = cache
    assert b.status_code == 200 and h_resp.status_code == 503
    assert await _durable(spiffe) == (True, None)
    assert await _live(cache, spiffe) == (True, None), "a writer that lost its lock replaced a later freeze"


async def test_many_held_agents_are_named_and_the_retry_stays_inside_the_attempt_bound(env, monkeypatch) -> None:
    """Review round 7 (warm_held4.py): the skipped-agent retry waited 3 s per held agent, so 4+ held agents
    overran the 10 s attempt bound — 7160 was never logged and 7035 named nobody. They are named before the
    retry, and the retry has a per-agent wait and a total budget. With 10 held agents and a 0.6 s budget the
    per-agent waits alone (10 x 0.3 s) would take 3 s, so the bound below holds only if the budget is kept."""
    import norviq.api.routers.agents as agents_mod

    monkeypatch.setattr(agents_mod, "_WARM_RETRY_BUDGET_S", 0.6)
    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-held-{uuid.uuid4().hex[:8]}"
    agents = [f"{prefix}/{n:02d}" for n in range(16)]
    ids.extend(agents)
    await _seed_frozen_rows(agents)
    held = agents[:10]
    locks = [_HeldLock(a) for a in held]
    for lock in locks:
        await lock.__aenter__()
    try:
        with structlog.testing.capture_logs() as logs:
            started = time.monotonic()
            with pytest.raises(RuntimeError):
                await asyncio.wait_for(warm_agent_overrides(cache, progress={"after": prefix}), 30)
            elapsed = time.monotonic() - started
    finally:
        for lock in locks:
            await lock.__aexit__(None, None, None)
    bound = agents_mod._lock_timeout_ms() / 1000 + 0.6 + agents_mod._WARM_RETRY_LOCK_MS / 1000 + 1.5
    assert elapsed < bound, f"the warm took {elapsed:.1f}s with {len(held)} held agents (bound {bound:.1f}s)"
    first = next(e for e in logs if e.get("code") == "NRVQ-API-7160")
    assert first["phase"] == "retrying" and first["spiffe_ids"] == held
    for spiffe in agents[10:]:
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_the_warm_runs_on_a_connection_configured_like_the_admin_lock_connection(env) -> None:
    """Review round 7: the warm's batch transaction ran on an ordinary pooled session, so a replica vanishing
    mid-warm kept up to 500 agent locks for TCP keepalive time. It now applies the admin session settings and
    puts them back before the connection is pooled."""
    import norviq.api.routers.agents as agents_mod

    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-warmconn-{uuid.uuid4().hex[:8]}"
    ids.append(f"{prefix}/a")
    await _seed_frozen_rows([f"{prefix}/a"])
    seen: dict = {}

    class _Spy(_Proxy):
        async def warm_admin_trust_controls(self, *a, **k):
            # The session's connection is checked out right now: read what it is configured with.
            conn = await agents_mod._EngineConnector().connect()
            try:
                seen["active"] = (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                            "AND pid <> pg_backend_pid() AND state = 'idle in transaction'"
                        )
                    )
                ).scalar()
            finally:
                await conn.close()
            return await self._real.warm_admin_trust_controls(*a, **k)

    before = await _session_settings(agents_mod._ADMIN_SESSION_SETTINGS)
    applied: list = []
    real_apply = agents_mod._apply_admin_session

    async def _record(conn):
        applied.append(1)
        return await real_apply(conn)

    agents_mod._apply_admin_session = _record
    try:
        assert await warm_agent_overrides(_Spy(cache), progress={"after": prefix}) == 1
    finally:
        agents_mod._apply_admin_session = real_apply
    assert applied == [1], "the warm's connection was not configured like the admin lock connection"
    # Every pooled connection (the spy's and the warm's: the pool hands them out in FIFO order) is back to the
    # server's settings.
    held = [await agents_mod._EngineConnector().connect() for _ in range(3)]
    try:
        for conn in held:
            names = agents_mod._ADMIN_SESSION_SETTINGS
            assert {n: (await conn.execute(text(f"SHOW {n}"))).scalar() for n in names} == before
    finally:
        for conn in held:
            await conn.rollback()
            await conn.close()


async def test_a_postgres_that_stops_answering_after_the_lock_does_not_hold_a_freeze_for_a_minute(env) -> None:
    """Review round 8 (pghang.py): a partition after the lock was granted made the registry read wait for the
    driver's command timeout and the release's rollback ~60 s more, so the freeze went live after ~67 s. The
    request's statements and the release are bounded now; the connection is invalidated, not pooled."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "pghang")
    # The documented bound (docs/cli.md: about db_command_timeout, 5 s), not one derived from the constants.
    bound = 6.5
    assert agents_mod._db_statement_timeout_s() + agents_mod._RELEASE_TIMEOUT_S <= 7.0
    for score, expect in ((0, "Freeze applied live but NOT persisted"), (0.4, "Trust change not applied")):
        _admin_db(app, hang_after_lock=True)
        try:
            started = time.monotonic()
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": score}, headers=_hdr())
            elapsed = time.monotonic() - started
        finally:
            app.dependency_overrides.pop(get_admin_db, None)
        assert resp.status_code == 503 and resp.json()["detail"].startswith(expect), resp.text
        assert elapsed < bound, f"answered after {elapsed:.1f}s (bound {bound:.1f}s)"
    assert await _live(cache, spiffe) == (True, None)
    assert await _advisory_held(spiffe) == 0  # the invalidated connection took its lock with it


async def test_a_loosening_whose_fence_token_fails_blames_the_registry_not_the_store(env, monkeypatch) -> None:
    """Review round 8: the fence token (a Postgres nextval) and the store claim shared one try block, so a
    database failure there was answered 'the store did not answer' and logged as 7147."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "tokfail")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    async def _no_token(conn):
        raise ConnectionError("backend terminated")

    monkeypatch.setattr(agents_mod, "_fence_token", _no_token)
    with structlog.testing.capture_logs() as logs:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    assert resp.status_code == 503 and resp.json()["detail"] == (
        "Trust change not applied: the registry could not be reached or did not answer in time. Retry.")
    codes = [(e.get("code"), e.get("stage")) for e in logs if e.get("code", "").startswith("NRVQ-API-71")
             or e.get("code") == "NRVQ-API-7033"]
    assert ("NRVQ-API-7033", "fence_token") in codes and not any(c == "NRVQ-API-7147" for c, _ in codes)
    assert await _live(cache, spiffe) == (True, None) and await _durable(spiffe) == (True, None)


async def test_the_7033_line_says_why_the_write_failed(env, monkeypatch) -> None:
    """Review round 8: 7033 logged error=<spiffe id> for an admin-slot refusal and error='' for a timeout, so
    'too many admin changes here' could not be told from 'registry unreachable'."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "why7033")
    sem = agents_mod._admin_slots()
    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 200)
    taken = 0
    while not sem.locked():
        await sem.acquire()
        taken += 1
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())
    finally:
        for _ in range(taken):
            sem.release()
    assert resp.status_code == 503
    line = next(e for e in logs if e.get("code") == "NRVQ-API-7033")
    assert line["stage"] == "admin_slots" and line["error"] == "_AdminBusy"


class _OnRetrying:
    """Wraps the router's logger: sets ``event`` when the warm logs 7160 phase=retrying (just before its retry)."""

    def __init__(self, real) -> None:
        self._real, self.event = real, asyncio.Event()

    def __getattr__(self, name):
        return getattr(self._real, name)

    def error(self, msg, **kw):
        if kw.get("code") == "NRVQ-API-7160" and kw.get("phase") == "retrying":
            self.event.set()
        return self._real.error(msg, **kw)


async def _release_on(event: asyncio.Event, lock: "_HeldLock", delay: float) -> None:
    await event.wait()
    await asyncio.sleep(delay)
    await lock.__aexit__(None, None, None)


async def test_one_agent_still_held_does_not_stop_the_retry_of_the_others(env, monkeypatch) -> None:
    """Round 8 reviewer mutation: a lock timeout on one skipped agent must move on to the next, which may be
    free by then, not end the retry for all of them."""
    import norviq.api.routers.agents as agents_mod

    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-retry-{uuid.uuid4().hex[:8]}"
    stuck, freed = f"{prefix}/a", f"{prefix}/b"  # retried in this order
    ids.extend([stuck, freed])
    await _seed_frozen_rows([stuck, freed])
    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 300)
    monkeypatch.setattr(agents_mod, "_WARM_RETRY_LOCK_MS", 1000)
    hook = _OnRetrying(agents_mod.log)
    monkeypatch.setattr(agents_mod, "log", hook)
    held_stuck, held_freed = _HeldLock(stuck), _HeldLock(freed)
    await held_stuck.__aenter__()
    await held_freed.__aenter__()
    releaser = asyncio.create_task(_release_on(hook.event, held_freed, 0.3))  # while the retry waits on `stuck`
    try:
        with pytest.raises(RuntimeError, match="1 frozen or capped"):
            await warm_agent_overrides(cache, progress={"after": prefix})
    finally:
        await releaser
        await held_stuck.__aexit__(None, None, None)
    assert await cache._client().get(f"agent_frozen:{freed}") == "1"
    assert await cache._client().get(f"agent_frozen:{stuck}") is None


async def test_the_retry_budget_starts_when_the_retry_does(env, monkeypatch) -> None:
    """Round 8 reviewer mutation: a budget counted from the start of the warm is spent by a long first pass, and
    the retry then never runs."""
    import norviq.api.routers.agents as agents_mod

    _, _, cache, ids = env
    spiffe = f"spiffe://zzzz-budget-{uuid.uuid4().hex[:8]}/a"
    ids.append(spiffe)
    await _seed_frozen_rows([spiffe])
    monkeypatch.setattr(agents_mod, "_lock_timeout_ms", lambda: 1000)  # the first pass waits 1 s on the batch lock
    monkeypatch.setattr(agents_mod, "_WARM_RETRY_BUDGET_S", 0.5)
    hook = _OnRetrying(agents_mod.log)
    monkeypatch.setattr(agents_mod, "log", hook)
    held = _HeldLock(spiffe)
    await held.__aenter__()
    releaser = asyncio.create_task(_release_on(hook.event, held, 0))
    try:
        assert await warm_agent_overrides(cache, progress={"after": spiffe[:-2]}) >= 1
    finally:
        await releaser
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"


async def test_a_warm_connection_that_cannot_be_reset_is_not_pooled(env, monkeypatch) -> None:
    """Round 8 reviewer mutation: if its settings cannot be put back, the warm's connection must be invalidated,
    or the pool hands out a connection that still carries the admin idle timeouts."""
    import norviq.api.routers.agents as agents_mod

    _, _, cache, ids = env
    prefix = f"spiffe://zzzz-noreset-{uuid.uuid4().hex[:8]}"
    ids.append(f"{prefix}/a")
    await _seed_frozen_rows([f"{prefix}/a"])
    used: list = []
    real_connect = agents_mod._EngineConnector.connect

    invalidated: list = []

    async def _recording_connect(self):
        conn = await real_connect(self)
        used.append(conn)
        return conn

    from sqlalchemy.ext.asyncio import AsyncConnection

    real_invalidate = AsyncConnection.invalidate

    async def _invalidate(self, *a, **k):
        invalidated.append(self)
        return await real_invalidate(self, *a, **k)

    monkeypatch.setattr(AsyncConnection, "invalidate", _invalidate)

    async def _reset_fails(conn):
        raise ConnectionError("reset lost")

    monkeypatch.setattr(agents_mod._EngineConnector, "connect", _recording_connect)
    monkeypatch.setattr(agents_mod, "_reset_admin_session", _reset_fails)
    assert await warm_agent_overrides(cache, progress={"after": prefix}) == 1
    assert len(used) == 1 and invalidated == used, "a connection still carrying the admin settings was pooled"


async def test_a_loosenings_retry_keeps_its_token_so_a_freeze_stolen_meanwhile_wins(env) -> None:
    """Round 8 reviewer mutation: the retry after a store error must claim with the SAME token. A new one would
    be newer than the steal and write the loosening over a freeze stolen in between."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "keeptok")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    class _ErrorThenSteal(_Proxy):
        calls = 0

        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, **k):
            type(self).calls += 1
            if type(self).calls == 1:
                stolen = await self._real.claim_admin_trust_owner(spiffe_id, None)  # a freeze steals the fence
                assert await self._real.apply_admin_trust_control_if_owner(
                    spiffe_id, stolen, frozen=True, cap=None) == 1  # ... and its write lands
                raise ConnectionError("store reset")  # while this write's answer is lost
            return await self._real.apply_admin_trust_control_if_owner(spiffe_id, token, **k)

    app.state.cache = _ErrorThenSteal(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and "a newer change owns the agent" in resp.json()["detail"]
    assert await _live(cache, spiffe) == (True, None)


async def test_an_admin_connection_refused_the_lock_and_not_reset_is_not_pooled(env, short_waits, monkeypatch) -> None:
    """Round 8 reviewer mutation: the lock was refused (contended), so nothing is held, but the connection still
    carries the admin settings; if they cannot be put back it must be invalidated, not pooled."""
    import norviq.api.routers.agents as agents_mod
    from sqlalchemy.ext.asyncio import AsyncConnection

    app, client, cache, ids = env
    spiffe = _agent(ids, "refusedreset")
    await _seed_registered(spiffe)
    invalidated: list = []
    real_invalidate = AsyncConnection.invalidate

    async def _invalidate(self, *a, **k):
        invalidated.append(self)
        return await real_invalidate(self, *a, **k)

    async def _reset_fails(conn):
        raise ConnectionError("reset lost")

    async with _HeldLock(spiffe):
        monkeypatch.setattr(AsyncConnection, "invalidate", _invalidate)
        monkeypatch.setattr(agents_mod, "_reset_admin_session", _reset_fails)
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())
        monkeypatch.undo()
    assert resp.status_code == 503 and "in progress" in resp.json()["detail"]
    assert len(invalidated) == 1, "a connection still carrying the admin settings was pooled"


class _DeadAfterRead(_ConnProxy):
    """Postgres stops answering right after the registry read: from the fence token's nextval on, every
    statement, commit and rollback waits like a partitioned connection (until cut off) and then fails."""

    async def _dead(self):
        await asyncio.sleep(30)
        raise TimeoutError("driver command_timeout")

    async def execute(self, stmt, *a, **k):
        if "nextval" in str(stmt):
            self._hooks["dead"] = True
        if self._hooks.get("dead"):
            await self._dead()
        return await self._real.execute(stmt, *a, **k)

    async def rollback(self):
        if self._hooks.get("dead"):
            await self._dead()
        return await self._real.rollback()

    async def commit(self):
        if self._hooks.get("dead"):
            await self._dead()
        return await super().commit()


def _dead_after_read_db(app, **hooks) -> dict:
    import norviq.api.routers.agents as agents_mod

    hooks.setdefault("commits", 0)

    class _Db:
        async def connect(self):
            return _DeadAfterRead(await agents_mod._EngineConnector().connect(), hooks)

    app.dependency_overrides[get_admin_db] = _Db
    return hooks


async def test_a_freeze_whose_postgres_stops_after_the_read_is_still_applied_live(env) -> None:
    """Round-8 verification (test_p_midhang_v.py): Postgres stopping after the registry read failed the fence
    token; nothing was written to the store, no steal was tried, and the answer said 'may or may not be live'
    while the freeze was NOT live. A failed fence token now takes the unreachable-registry path: the freeze
    steals the fence and is applied live, answered as 'applied live but NOT persisted'."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "midhang")
    await _seed_registered(spiffe)
    _dead_after_read_db(app)
    try:
        started = time.monotonic()
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        elapsed = time.monotonic() - started
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Freeze applied live but NOT persisted")
    assert await _live(cache, spiffe) == (True, None)
    assert elapsed < 6.5, f"answered after {elapsed:.1f}s"
    line = next(e for e in logs if e.get("code") == "NRVQ-API-7033")
    assert line["stage"] == "fence_token" and line["live"] is True, logs


async def test_a_cap_whose_postgres_stops_after_the_read_is_not_applied(env) -> None:
    """Control for the test above: a cap is not the kill switch; with no fence token nothing was written, and
    the answer says so (it used to say 'may or may not be live')."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "midhangcap")
    await _seed_registered(spiffe)
    _dead_after_read_db(app)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Trust change not applied")
    assert await _live(cache, spiffe) == (False, None) and await _durable(spiffe) == (False, None)


async def test_a_freeze_the_store_did_not_take_and_the_registry_did_not_confirm_is_stolen_live(env) -> None:
    """Round-8 verification: the other half — the store write did not land (store error) and then the registry
    write failed. A freeze must not end un-applied: it steals the fence and is applied live before answering."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "persistfail")
    await _seed_registered(spiffe)

    class _OwnWriteFails(_Proxy):
        async def apply_admin_trust_control_if_owner(self, spiffe_id, token, **k):
            if ":" not in str(token):  # the lock holder's own token; a steal's owner value is "<L>:<S>"
                raise ConnectionError("store reset")
            return await self._real.apply_admin_trust_control_if_owner(spiffe_id, token, **k)

    app.state.cache = _OwnWriteFails(cache)
    _admin_db(app, fail_commit_n=2)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        app.state.cache = cache
        app.dependency_overrides.pop(get_admin_db, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("Applied live, but it may NOT be persisted")
    assert await _live(cache, spiffe) == (True, None)


class _TableLock:
    """A migration-like ACCESS EXCLUSIVE lock on agent_registry, held for ``hold`` seconds."""

    def __init__(self, hold: float) -> None:
        self.hold = hold

    async def run(self, taken: asyncio.Event) -> None:
        async with _session() as session:
            await session.execute(text("LOCK TABLE agent_registry IN ACCESS EXCLUSIVE MODE"))
            taken.set()
            await asyncio.sleep(self.hold)
            await session.rollback()


def test_the_admin_statement_bound_follows_the_driver_timeout(monkeypatch) -> None:
    """Round-8 verification: the bound was a fixed 3 s, shorter than db_command_timeout (5 s), so an operator who
    raised the setting for a slow database was told the registry is unreachable."""
    import norviq.api.routers.agents as agents_mod

    monkeypatch.setattr(agents_mod.settings, "db_command_timeout", 8)
    assert agents_mod._db_statement_timeout_s() == 8.0
    monkeypatch.setattr(agents_mod.settings, "db_command_timeout", 1)
    assert agents_mod._db_statement_timeout_s() == 3.0


async def test_a_freeze_waiting_seconds_on_a_table_lock_is_still_persisted(env) -> None:
    """Round-8 verification (slowread.py): a read waiting 3-5 s on a table lock (a migration) was cut off at 3 s,
    and the freeze was only applied live. Within db_command_timeout it is persisted (200)."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "slowread")
    await _seed_registered(spiffe)
    taken = asyncio.Event()
    holder = asyncio.create_task(_TableLock(3.6).run(taken))
    await asyncio.wait_for(taken.wait(), 5)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
    finally:
        await holder
    assert resp.status_code == 200, resp.text
    assert await _live(cache, spiffe) == (True, None) and await _durable(spiffe) == (True, None)


async def test_a_reset_read_that_times_out_is_logged_as_a_timeout(env, monkeypatch) -> None:
    """Round-8 verification: 7146 logged the TimeoutError's cause, 'CancelledError', which reads as a cancelled
    request rather than a slow registry."""
    import norviq.api.routers.agents as agents_mod

    app, client, cache, ids = env
    spiffe = _agent(ids, "resettimeout")
    await _seed_registered(spiffe)
    monkeypatch.setattr(agents_mod, "_db_statement_timeout_s", lambda: 0.3)
    taken = asyncio.Event()
    holder = asyncio.create_task(_TableLock(1.5).run(taken))
    await asyncio.wait_for(taken.wait(), 5)
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    finally:
        await holder
    assert resp.status_code == 503
    line = next(e for e in logs if e.get("code") == "NRVQ-API-7146")
    assert line["stage"] == "read" and line["error"].startswith("AdminStatementTimeout: admin statement did not answer"), line
