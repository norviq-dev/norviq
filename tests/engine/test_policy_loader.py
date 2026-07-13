# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for PolicyLoader with real Redis cache integration."""

from __future__ import annotations

import os
import uuid

import pytest

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader
from norviq.exceptions import NorviqError


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def loader(redis_url: str) -> PolicyLoader:
    """Create policy loader with connected dependencies."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    engine = OPAEvaluator(cache)
    policy_loader = PolicyLoader(cache=cache, evaluator=engine)
    yield policy_loader
    await engine.close()
    await cache.close()


def _suffix() -> str:
    """Create random suffix for test key isolation."""
    return uuid.uuid4().hex


async def test_load_checks_memory_then_redis_then_none(loader: PolicyLoader) -> None:
    """load should return memory, then Redis, then None."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "agent"
    source = f"package p.{suffix}"
    assert await loader.load(ns, cls) is None
    await loader._cache.set_policy(ns, cls, source)
    assert await loader.load(ns, cls) == source
    await loader._cache.set_policy(ns, cls, f"{source}.updated")
    assert await loader.load(ns, cls) == source


async def test_create_increments_versions(loader: PolicyLoader) -> None:
    """create should auto-increment version for policy key."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "support"
    assert await loader.create(ns, cls, "package p.v1", saved_by="dev-a") == 1
    assert await loader.create(ns, cls, "package p.v2", saved_by="dev-b") == 2
    versions = loader.get_versions(ns, cls)
    assert [item.version for item in versions] == [1, 2]


async def test_create_updates_cache_and_evaluator(loader: PolicyLoader) -> None:
    """create should persist policy to cache and evaluator."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "planner"
    rego = f"package p.{suffix}.allow"
    await loader.create(ns, cls, rego, saved_by="dev")
    assert await loader._cache.get_policy(ns, cls) == rego
    assert loader._evaluator._policies[f"{ns}:{cls}"]["rego"] == rego


async def test_rollback_restores_previous_policy(loader: PolicyLoader) -> None:
    """rollback should create new version using historical source."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "planner"
    old = "package p.old"
    new = "package p.new"
    await loader.create(ns, cls, old, saved_by="a")
    await loader.create(ns, cls, new, saved_by="b")
    restored = await loader.rollback(ns, cls, 1)
    assert restored == old
    assert loader.get_current(ns, cls) == old
    assert loader.get_versions(ns, cls)[-1].version == 3


async def test_rollback_missing_version_raises(loader: PolicyLoader) -> None:
    """rollback should raise NorviqError when target is absent."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "planner"
    await loader.create(ns, cls, "package p.v1")
    with pytest.raises(NorviqError) as exc:
        await loader.rollback(ns, cls, 99)
    assert exc.value.code == "NRVQ-REG-5004"


async def test_version_history_is_capped_at_ten(loader: PolicyLoader) -> None:
    """create should retain only the latest ten versions."""
    suffix = _suffix()
    ns = f"ns-{suffix}"
    cls = "planner"
    for index in range(12):
        await loader.create(ns, cls, f"package p.v{index + 1}")
    versions = loader.get_versions(ns, cls)
    assert len(versions) == 10
    assert versions[0].version == 3
    assert versions[-1].version == 12


async def test_reload_all_loads_every_policy(loader: PolicyLoader, monkeypatch: pytest.MonkeyPatch) -> None:
    """reload_all should reload every in-memory key into evaluator."""
    suffix = _suffix()
    seen: list[tuple[str, str, str]] = []

    def _record(namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        seen.append((namespace, agent_class, rego_source))

    monkeypatch.setattr(loader._evaluator, "load_policy", _record)
    await loader.create(f"ns-{suffix}-a", "class-a", "package p.a")
    await loader.create(f"ns-{suffix}-b", "class-b", "package p.b")
    seen.clear()
    assert await loader.reload_all() == 2
    assert set(seen) == {
        (f"ns-{suffix}-a", "class-a", "package p.a"),
        (f"ns-{suffix}-b", "class-b", "package p.b"),
    }
