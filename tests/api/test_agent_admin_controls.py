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
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
import structlog
from sqlalchemy import text

from norviq.api.db.session import close_db, create_tables, get_session, init_db, upsert_agent_registry
from norviq.api.main import create_app
from norviq.api.routers.agents import warm_agent_overrides
from norviq.config import settings
from norviq.engine.cache import RedisCache


def _env(name: str) -> str:
    value = (os.getenv(name) or "").strip().strip("\"'")
    if not value:
        pytest.fail(f"{name} must be set for these PostgreSQL/Redis integration tests")
    return value


@pytest.fixture
async def env():
    old_url = settings.pg_url
    settings.pg_url = _env("NRVQ_PG_URL")
    await init_db()
    await create_tables()
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
        settings.pg_url = old_url


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


class _BrokenSession:
    async def execute(self, *_a, **_k):
        raise RuntimeError("database unavailable")

    async def commit(self) -> None:  # pragma: no cover - never reached
        return None


async def test_a_failed_durable_write_is_a_503_not_a_200(env) -> None:
    """FAIL-ON-BUG: the write sat in a try/except that logged NRVQ-API-7033 and returned 200 anyway.

    A freeze is still applied live first — Postgres being down must not stop an admin stopping an agent —
    but the caller is told it is not durable. An unfreeze is NOT applied live: a lift that the next restart
    silently undoes is worse than one that visibly failed."""
    app, client, cache, ids = env

    async def _broken():
        yield _BrokenSession()

    app.dependency_overrides[get_session] = _broken
    try:
        spiffe = _agent(ids, "db-down")
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        assert resp.status_code == 503 and "NOT persisted" in resp.json()["detail"]
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"

        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
        assert resp.status_code == 503
        assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", "a failed unfreeze lifted the live freeze"
    finally:
        app.dependency_overrides.pop(get_session, None)


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
        async def apply_admin_trust_control(self, spiffe_id, *, frozen, cap, display=None):
            if not frozen and cap is None and not hit.is_set():
                hit.set()
                await gate.wait()
            await self._real.apply_admin_trust_control(spiffe_id, frozen=frozen, cap=cap, display=display)

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


async def test_freeze_with_the_store_down_is_persisted_and_applied_at_the_next_start(env) -> None:
    """FAIL-ON-BUG (review N2). With Redis down a freeze was an unhandled 500 and nothing reached Postgres.
    It is durable now and the 503 says it is not live yet; warm_agent_overrides applies it at the next
    start. A cap with the store down changes nothing."""
    app, client, cache, ids = env
    spiffe, capped = _agent(ids, "n2"), _agent(ids, "n2cap")
    await _seed_registered(spiffe)
    await _seed_registered(capped)

    class _Down(_Proxy):
        def _client(self):
            raise ConnectionError("redis down")

        async def apply_admin_trust_control(self, *a, **k):
            raise ConnectionError("redis down")

    app.state.cache = _Down(cache)
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        cap_resp = await client.put(f"/api/v1/agents/{capped}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and "persisted but NOT live" in resp.json()["detail"]
    assert (await _row(spiffe))["frozen"] is True
    await warm_agent_overrides(cache)
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1"
    assert cap_resp.status_code == 503
    assert (await _row(capped))["trust_cap"] is None, "a cap the store did not take was left durable"


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "%20",
        "not-a-spiffe-id",
        "spiffe://norviq/ns/a/sa/b%2A",
        "spiffe://norviq/ns/%2E%2E/sa/x",
        "spiffe://Norviq/ns/a/sa/b",
        "spiffe://norviq/ns/a/sa/" + "x" * 600,
    ],
)
async def test_admin_trust_routes_refuse_an_id_that_is_not_a_spiffe_id(env, bad) -> None:
    """FAIL-ON-BUG (review N3). The upsert wrote a frozen registry row for any string, '*' and '../../x'
    included. PUT, reset and DELETE validate the id's shape first (422) and write nothing."""
    _, client, cache, _ = env
    resp = await client.put(f"/api/v1/agents/{bad}/trust", json={"score": 0}, headers=_hdr())
    assert resp.status_code == 422, resp.text
    assert (await client.post(f"/api/v1/agents/{bad}/trust/reset", headers=_hdr())).status_code == 422
    assert (await client.delete(f"/api/v1/agents/{bad}", headers=_hdr())).status_code == 422
    async with _session() as session:
        n = (
            await session.execute(
                text(
                    "SELECT count(*) FROM agent_registry WHERE spiffe_id NOT LIKE 'spiffe://%/%' "
                    "OR spiffe_id LIKE '%*%' OR spiffe_id LIKE '% %' OR length(spiffe_id) > 500"
                )
            )
        ).scalar()
    assert n == 0


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

    async def _broken():
        yield _BrokenSession()

    app.dependency_overrides[get_session] = _broken
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.3}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_session, None)
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
