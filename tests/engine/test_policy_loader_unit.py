# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for policy loader persistence behavior."""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from norviq.api.db.session import close_db, create_tables, init_db
from norviq.config import settings
from norviq.engine.policy_loader import PolicyLoader


class _EvaluatorStub:
    def bind_loader(self, loader: object) -> None:
        return None

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        return None

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str) -> None:
        return None


class _CacheStub:
    _pool = None

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        return None

    async def set_policy(
        self, namespace: str, agent_class: str, rego: str, priority: int = 100, version: int = 0
    ) -> None:
        return None

    async def publish_policy_event(self, operation: str, namespace: str, agent_class: str, version: int = 0) -> None:
        return None

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        return 0


@pytest.fixture
async def db_engine() -> AsyncEngine:
    pg_url = (os.getenv("NRVQ_PG_URL") or "postgresql://norviq:norviq_local_dev@127.0.0.1:5433/norviq?sslmode=disable").strip().strip("\"'")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()
    # Strip the sslmode query param (asyncpg takes `ssl=`, not `sslmode=`) — mirrors session.py.
    engine = create_async_engine(
        pg_url.replace("postgresql://", "postgresql+asyncpg://").split("?")[0],
        connect_args={"ssl": False},
    )
    try:
        yield engine
    finally:
        await engine.dispose()
        await close_db()
        settings.pg_url = old_url


@pytest.fixture
async def loader(db_engine: AsyncEngine) -> PolicyLoader:
    cache = _CacheStub()
    evaluator = _EvaluatorStub()
    policy_loader = PolicyLoader(cache=cache, evaluator=evaluator)  # type: ignore[arg-type]
    yield policy_loader
    await policy_loader.close()


@pytest.fixture
async def loader_fresh(db_engine: AsyncEngine) -> PolicyLoader:
    cache = _CacheStub()
    evaluator = _EvaluatorStub()
    policy_loader = PolicyLoader(cache=cache, evaluator=evaluator)  # type: ignore[arg-type]
    yield policy_loader
    await policy_loader.close()


@pytest.mark.asyncio
async def test_create_writes_to_db(loader: PolicyLoader, db_engine: AsyncEngine) -> None:
    namespace = f"ns1-{uuid.uuid4().hex}"
    agent_class = "class1"
    await loader.create(namespace, agent_class, "package x", "admin", 100)
    async with db_engine.begin() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT namespace, agent_class FROM policies "
                    "WHERE namespace = :namespace AND agent_class = :agent_class"
                ),
                {"namespace": namespace, "agent_class": agent_class},
            )
        ).mappings().first()
    assert row is not None
    assert row["namespace"] == namespace


@pytest.mark.asyncio
async def test_create_writes_to_versions_table(loader: PolicyLoader, db_engine: AsyncEngine) -> None:
    namespace = f"ns2-{uuid.uuid4().hex}"
    agent_class = "class2"
    await loader.create(namespace, agent_class, "package y", "admin", 100)
    async with db_engine.begin() as conn:
        count = (
            await conn.execute(
                text(
                    "SELECT COUNT(*) AS count FROM policy_versions "
                    "WHERE policy_id IN (SELECT id FROM policies WHERE namespace = :namespace)"
                ),
                {"namespace": namespace},
            )
        ).scalar_one()
    assert int(count) >= 1


@pytest.mark.asyncio
async def test_warm_cache_loads_from_db(loader_fresh: PolicyLoader, db_engine: AsyncEngine) -> None:
    namespace = f"ns3-{uuid.uuid4().hex}"
    agent_class = "class3"
    async with db_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO policies "
                "(id, name, namespace, agent_class, rego_source, version, enforcement_mode, priority, created_at) "
                "VALUES (gen_random_uuid(), :name, :namespace, :agent_class, :rego_source, 1, 'block', 100, NOW())"
            ),
            {
                "name": "test",
                "namespace": namespace,
                "agent_class": agent_class,
                "rego_source": "package z",
            },
        )
    await loader_fresh.warm_cache()
    assert f"{namespace}:{agent_class}" in loader_fresh._policies
