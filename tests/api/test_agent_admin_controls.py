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
        "spiffe://",
        "spiffe://norviq/ns/a/sa/b%2A",
        "spiffe://norviq/ns/a/sa/b%3F",
        "spiffe://norviq/ns/a/sa/my%20agent",
        "spiffe://norviq/ns/a/sa/b%5B0%5D",
        "spiffe://norviq/ns/a/sa/" + "x" * 600,
    ],
)
async def test_admin_trust_routes_refuse_an_id_that_is_not_safe_to_write_under(env, bad) -> None:
    """FAIL-ON-BUG (review N3). The upsert wrote a frozen registry row for any string, '*' and ' '
    included. PUT, reset and DELETE refuse what the evaluator refuses (no "spiffe://" prefix) plus an
    empty id, whitespace, glob characters and more than 512 characters (422), and write nothing. Counted
    for these exact ids, so rows another run left in a shared database cannot fail it."""
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
    ],
)
async def test_an_operator_chosen_id_the_product_accepts_can_still_be_frozen(env, label) -> None:
    """Review round 2, N10: the first version enforced the SPIFFE spec's character set and 422'd ids that
    POST /keys mints and the evaluator registers ('spiffe://acme-agent', '.../sa/agent:v2'), so such an
    agent was listed but could not be frozen. The rule is now the product's own plus the dangerous shapes."""
    _, client, cache, ids = env
    spiffe = label.format(u=uuid.uuid4().hex[:8])
    ids.append(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    assert (await _row(spiffe))["frozen"] is True and await cache._client().get(f"agent_frozen:{spiffe}") == "1"


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


class _CommitFailsOnce(_Proxy):
    """The route's session; its first commit fails. `landed` decides whether the server committed anyway
    (a lost ack) or rolled back. The rollback releases the advisory lock, as a dropped connection does."""

    def __init__(self, real, state: dict) -> None:
        super().__init__(real)
        self._state = state

    async def commit(self):
        if self._state.get("failed"):
            return await self._real.commit()
        self._state["failed"] = True
        if self._state.get("landed"):
            await self._real.commit()
        else:
            await self._real.rollback()
        if "gate" in self._state:
            self._state["hit"].set()
            await self._state["gate"].wait()
        raise ConnectionError("connection lost during COMMIT")


def _override_session(app, state: dict) -> None:
    async def _factory():
        gen = get_session()
        try:
            yield _CommitFailsOnce(await gen.__anext__(), state)
        finally:
            await gen.aclose()

    app.dependency_overrides[get_session] = _factory


async def test_a_failed_commit_never_writes_back_over_a_freeze_committed_meanwhile(env) -> None:
    """FAIL-ON-BUG (review round 2, R2). A cap's MULTI landed, its commit failed (lock released), and a
    freeze from another replica committed with 200 in the gap. The old code then restored what Redis held
    before the cap — no freeze — over it: registry frozen, agent unfrozen. Now Redis is set from the row,
    re-read under a fresh lock."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "r2")
    await _seed_registered(spiffe)
    state = {"gate": asyncio.Event(), "hit": asyncio.Event()}
    _override_session(app, state)
    try:
        cap = asyncio.create_task(client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr()))
        await asyncio.wait_for(state["hit"].wait(), 5)
        app.dependency_overrides.pop(get_session, None)
        freeze = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        _override_session(app, state)
        state["gate"].set()
        cap_resp = await asyncio.wait_for(cap, 10)
    finally:
        app.dependency_overrides.pop(get_session, None)
    assert freeze.status_code == 200 and cap_resp.status_code == 503
    assert (await _row(spiffe))["frozen"] is True
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", "the stale restore erased the freeze"


async def test_a_commit_whose_ack_was_lost_is_reported_as_applied_and_the_store_matches(env) -> None:
    """Review round 2: the commit landed but the client saw an error. The old restore put the looser
    pre-change state back while the registry kept the new cap, and answered 'not applied'."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "ack")
    await _seed_registered(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.5}, headers=_hdr())).status_code == 200
    _override_session(app, {"landed": True})
    try:
        resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.2}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 200, resp.text
    assert (await _row(spiffe))["trust_cap"] == pytest.approx(0.2)
    assert float(await cache._client().get(f"agent_trust_override:{spiffe}")) == pytest.approx(0.2)


async def test_registry_unreachable_after_a_failed_commit_leaves_the_stricter_state_live(env) -> None:
    """Review round 2, R2's other branch: if Postgres cannot be reached to re-read the row, no other admin
    write can commit either, so the stricter of the old and new state is safe — and the 503 says the state
    is not confirmed (7148, ERROR)."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "unreach")
    await _seed_registered(spiffe)
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    state: dict = {}
    calls = {"n": 0}

    async def _factory():
        calls["n"] += 1
        if calls["n"] > 1:  # the reconcile's fresh session: Postgres is gone
            yield _BrokenSession()
            return
        gen = get_session()
        try:
            yield _CommitFailsOnce(await gen.__anext__(), state)
        finally:
            await gen.aclose()

    app.dependency_overrides[get_session] = _factory
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("State uncertain")
    assert await cache._client().get(f"agent_frozen:{spiffe}") == "1", "a clear that may not have committed went live"
    assert [entry["outcome"] for entry in logs if entry.get("code") == "NRVQ-API-7148"] == [
        "commit_unconfirmed_stricter_state_live"
    ]


async def test_a_store_that_cannot_be_reset_after_a_failed_clear_says_state_uncertain(env) -> None:
    """FAIL-ON-BUG (review round 2, R3). The clear's MULTI did not confirm and putting the store back failed
    too: the old code answered 'not applied' while the freeze might be lifted live."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "r3")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200

    class _StoreGone(_Proxy):
        async def apply_admin_trust_control(self, spiffe_id, *, frozen, cap, display=None):
            if not frozen:  # the clear lands, then Redis goes away before anything else answers
                await self._real.apply_admin_trust_control(spiffe_id, frozen=frozen, cap=cap, display=display)
            raise ConnectionError("redis gone")

    app.state.cache = _StoreGone(cache)
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.state.cache = cache
    assert resp.status_code == 503 and resp.json()["detail"].startswith("State uncertain")
    errors = [entry for entry in logs if entry.get("code") == "NRVQ-API-7148"]
    assert errors and errors[0]["log_level"] == "error"
    assert (await _row(spiffe))["frozen"] is True


@pytest.fixture
def short_waits(monkeypatch):
    import norviq.api.routers.agents as agents_mod

    monkeypatch.setattr(agents_mod, "_LOCK_TIMEOUT", "300ms")
    monkeypatch.setattr(agents_mod, "_STORE_TIMEOUT_S", 0.3)
    return agents_mod


async def test_every_admin_route_waits_for_the_agents_lock_and_applies_nothing_on_contention(env, short_waits) -> None:
    """Pins the lock in PUT, DELETE and the reset (round 2, N7/N11). While another admin write holds the
    agent, each answers 503 'in progress' and changes nothing — in particular a freeze is NOT applied live
    outside the lock, as it used to be when a lock wait timed out like a database outage."""
    _, client, cache, ids = env
    spiffe = _agent(ids, "held")
    await _seed_registered(spiffe)
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})
    async with _HeldLock(spiffe):
        put = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())
        delete = await client.delete(f"/api/v1/agents/{spiffe}", headers=_hdr())
        reset = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    for resp in (put, delete, reset):
        assert resp.status_code == 503 and "in progress" in resp.json()["detail"], resp.text
    assert await cache._client().get(f"agent_frozen:{spiffe}") is None, "a contended freeze went live unserialized"
    row = await _row(spiffe)
    assert row is not None and row["frozen"] is False
    assert await cache._client().exists(f"agent_history:{spiffe}") == 1


async def test_a_hung_store_is_cut_off_and_does_not_hold_the_lock(env, short_waits) -> None:
    """Round 2, N8: a store that hangs (not refuses) kept the lock and a DB connection ~20 s per request.
    Every store call under the lock is bounded; a cap against a hung store is a prompt 503 and the agent's
    lock is free again straight after."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "hung")

    class _Hung(_Proxy):
        async def apply_admin_trust_control(self, *a, **k):
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
    """Round 2, N9: the reset writes nothing to Postgres; ending its transaction only releases the lock.
    A failure there used to answer 503 'nothing was cleared' with no 7145, after the history was deleted."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "n9")
    await _seed_registered(spiffe)
    await cache._client().zadd(f"agent_history:{spiffe}", {'{"decision": "block"}': time.time()})

    class _EndFails(_Proxy):
        async def commit(self):
            raise ConnectionError("connection lost")

        async def rollback(self):
            await self._real.rollback()
            raise ConnectionError("connection lost")

    async def _factory():
        gen = get_session()
        try:
            yield _EndFails(await gen.__anext__())
        finally:
            await gen.aclose()

    app.dependency_overrides[get_session] = _factory
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.post(f"/api/v1/agents/{spiffe}/trust/reset", headers=_hdr())
    finally:
        app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 200 and resp.json()["history_entries_cleared"] == 1
    assert [entry["code"] for entry in logs if entry.get("code") in ("NRVQ-API-7145", "NRVQ-API-7146")] == [
        "NRVQ-API-7145"
    ]


async def test_the_conditional_delete_alone_keeps_a_freeze_that_committed_after_the_check(env, monkeypatch) -> None:
    """Pins DELETE's `WHERE frozen = false AND trust_cap IS NULL` on its own (round 2, N11): with the lock
    disabled, a freeze committed between DELETE's check and its delete must make the delete a 409."""
    import norviq.api.routers.agents as agents_mod

    async def _no_lock(*_a, **_k):
        return None

    monkeypatch.setattr(agents_mod, "_lock_agent", _no_lock)
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


async def test_admin_store_writes_and_the_reset_are_each_one_multi(env) -> None:
    """Pins the atomicity claims (round 2, N11): the freeze/cap write and the reset's read-and-delete each go
    to Redis as ONE transactional pipeline executed once — not two round-trips, not a plain pipeline."""
    _, _, cache, ids = env
    spiffe = _agent(ids, "multi")
    seen: list = []
    real_client = cache._client()

    class _Cache(_Proxy):
        def _client(self):
            return _Spy(real_client, seen)

    spy = _Cache(cache)
    await RedisCache.apply_admin_trust_control(spy, spiffe, frozen=False, cap=0.3)
    import norviq.api.routers.agents as agents_mod

    await agents_mod._reset_multi(spy, f"agent_history:{spiffe}", f"agent_profile:{spiffe}")
    assert seen == [{"transaction": True, "executes": 1}, {"transaction": True, "executes": 1}]


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


async def test_a_failed_commit_with_the_store_gone_too_says_state_uncertain(env) -> None:
    """Review round 2, R3 (probe P2): the clear's MULTI landed, the commit failed and the store went away
    before it could be set from the registry. Postgres keeps the freeze; the store cannot be fixed from
    here, so the answer must not be 'not applied' — it is 'State uncertain' with 7148 at ERROR."""
    app, client, cache, ids = env
    spiffe = _agent(ids, "r3commit")
    assert (await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0}, headers=_hdr())).status_code == 200
    calls = {"n": 0}

    class _GoneAfterFirst(_Proxy):
        async def apply_admin_trust_control(self, spiffe_id, *, frozen, cap, display=None):
            calls["n"] += 1
            if calls["n"] > 1:
                raise ConnectionError("redis gone")
            await self._real.apply_admin_trust_control(spiffe_id, frozen=frozen, cap=cap, display=display)

    app.state.cache = _GoneAfterFirst(cache)
    _override_session(app, {})
    try:
        with structlog.testing.capture_logs() as logs:
            resp = await client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 1.0}, headers=_hdr())
    finally:
        app.state.cache = cache
        app.dependency_overrides.pop(get_session, None)
    assert resp.status_code == 503 and resp.json()["detail"].startswith("State uncertain")
    assert [(e["outcome"], e["log_level"]) for e in logs if e.get("code") == "NRVQ-API-7148"] == [
        ("commit_failed_store_not_set_from_registry", "error")
    ]
    assert (await _row(spiffe))["frozen"] is True
