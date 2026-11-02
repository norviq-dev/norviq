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
