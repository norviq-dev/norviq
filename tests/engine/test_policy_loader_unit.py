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

    # Signature widened to match the caller (policy_loader.py's warm_cache/load_from_db now pass `priority`);
    # was drifting stale and made every real-DB test below fail with an unexpected-kwarg TypeError.
    def reload_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int | None = None) -> None:
        return None


class _CacheStub:
    _pool = None

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        return None

    async def set_policy(
        self, namespace: str, agent_class: str, rego: str, priority: int = 100, version: int = 0
    ) -> None:
        return None

    # Signature widened to match the caller (policy_loader.py's create()/apply_to_target() now pass `origin`
    # for HA echo-suppression) — was drifting stale and made every real-DB create() test fail.
    async def publish_policy_event(
        self, operation: str, namespace: str, agent_class: str, version: int = 0, origin: str | None = None
    ) -> None:
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


class _SyncEvaluatorStub:
    """Tracks load/unload so the HA remote-event path is assertable without a live evaluator."""
    def __init__(self) -> None:
        self.loaded: list[tuple[str, str]] = []
        self.unloaded: list[tuple[str, str]] = []

    def bind_loader(self, loader: object) -> None:
        return None

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int | None = None) -> None:
        self.loaded.append((namespace, agent_class))

    def unload_policy(self, namespace: str, agent_class: str) -> None:
        self.unloaded.append((namespace, agent_class))


async def test_apply_remote_event_delete_unloads_local_state() -> None:
    """HA: a delete published by a PEER replica must unload THIS replica's in-memory policy + evaluator index
    (no DB read needed — the peer already deleted the row). This is the H2 propagation half."""
    loader = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    loader._policies = {"payments:billing": {"rego": "package x", "priority": 100}}
    loader._versions = {"payments:billing": []}

    await loader.apply_remote_event("delete", "payments", "billing")

    assert "payments:billing" not in loader._policies
    assert "payments:billing" not in loader._versions
    assert ("payments", "billing") in loader._evaluator.unloaded  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_apply_remote_event_upsert_refreshes_version_history(
    loader: PolicyLoader, db_engine: AsyncEngine
) -> None:
    """FIX-5 regression: apply_remote_event's upsert branch previously called only `load_from_db` (refreshes
    `_policies`, so GET /policies is correct cluster-wide) but never refreshed `_versions` — so the FIX-A
    version-snapshot mode-patch (`apply_to_target`'s `history[-1].enforcement_mode = ...`) only ever landed
    on the ORIGINATING replica. A peer serving a rollback-to-current request would read a stale
    `_versions[key][-1].enforcement_mode`. Simulate: loader A creates a policy then reapplies the same rego
    under a new enforcement_mode (mode-change branch: DB UPDATE + patches loader A's OWN `_versions[-1]` in
    memory) — a fresh peer replica B (empty `_versions` for this key) then applies the remote upsert event
    and must see the SAME enforcement_mode in its own `_versions[-1]`, proving cross-replica rollback
    fidelity."""
    namespace = f"ns5-{uuid.uuid4().hex}"
    agent_class = "class5"
    rego = 'package remoteevt\ndefault decision = "block"'
    key = f"{namespace}:{agent_class}"

    await loader.create(namespace, agent_class, rego, "admin", 100, enforcement_mode="block")
    # Same-rego reapply with a new mode -> mode-change branch: DB UPDATE + patches _versions[-1] locally.
    result = await loader.apply_to_target(namespace, agent_class, namespace, agent_class, enforcement_mode="audit")
    assert result is not None
    assert loader._versions[key][-1].enforcement_mode == "audit"

    # A fresh peer replica: knows nothing about this key yet (empty _versions).
    peer = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    try:
        assert key not in peer._versions

        await peer.apply_remote_event("upsert", namespace, agent_class)

        assert key in peer._versions and peer._versions[key]
        assert peer._versions[key][-1].enforcement_mode == "audit"  # matches the originator, not stale
    finally:
        await peer.close()


@pytest.mark.asyncio
async def test_rehydrate_versions_for_key_caps_to_max_versions(
    loader: PolicyLoader, db_engine: AsyncEngine
) -> None:
    """RETENTION regression: `_rehydrate_versions_for_key` (apply_remote_event's upsert branch) must cap the
    stored history to `_MAX_VERSIONS`, exactly like the append path (`create()`) and the full-rehydrate path
    (`_rehydrate_versions`). The DB may retain more rows than `_MAX_VERSIONS` (policy_version_keep_count can
    exceed it), and previously this single-key path stored the WHOLE DB history — so a peer replica that
    received an upsert accumulated an unbounded version list the live append path would never build,
    diverging rollback targets across replicas. Seed the DB with more rows than `_MAX_VERSIONS`, apply the
    remote upsert on a fresh peer, and assert its in-memory history holds exactly `_MAX_VERSIONS` (the most
    recent), not the full DB count."""
    from norviq.engine.policy_loader import _MAX_VERSIONS

    namespace = f"ns7-{uuid.uuid4().hex}"
    agent_class = "class7"
    rego = 'package retention\ndefault decision = "block"'
    key = f"{namespace}:{agent_class}"
    total_db_rows = _MAX_VERSIONS + 5  # keep_count > _MAX_VERSIONS: DB retains more than memory should hold

    # create() writes version 1; seed the remaining rows directly so the DB history exceeds _MAX_VERSIONS.
    await loader.create(namespace, agent_class, rego, "admin", 100, enforcement_mode="block")
    async with db_engine.begin() as conn:
        policy_id = (
            await conn.execute(
                text("SELECT id FROM policies WHERE namespace = :ns AND agent_class = :cls"),
                {"ns": namespace, "cls": agent_class},
            )
        ).scalar_one()
        for version in range(2, total_db_rows + 1):
            await conn.execute(
                text(
                    "INSERT INTO policy_versions "
                    "(id, policy_id, version, rego_source, saved_at, saved_by, priority, enforcement_mode) "
                    "VALUES (:id, :policy_id, :version, :rego_source, NOW(), :saved_by, 100, 'block')"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "policy_id": policy_id,
                    "version": version,
                    "rego_source": rego,
                    "saved_by": "admin",
                },
            )

    # A fresh peer replica applies the remote upsert -> rehydrates just this key from the durable table.
    peer = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    try:
        await peer.apply_remote_event("upsert", namespace, agent_class)
        # Pre-fix this held all `total_db_rows` snapshots; must be capped to _MAX_VERSIONS.
        assert len(peer._versions[key]) == _MAX_VERSIONS
        # The cap keeps the most recent versions (tail), matching create()/_rehydrate_versions.
        assert peer._versions[key][-1].version == total_db_rows
        assert peer._versions[key][0].version == total_db_rows - _MAX_VERSIONS + 1
    finally:
        await peer.close()


@pytest.mark.asyncio
async def test_apply_remote_event_upsert_converges_applied_at(
    loader: PolicyLoader, db_engine: AsyncEngine
) -> None:
    """HA C1 regression: `_applied_at` was previously process-local only (never persisted/broadcast) — a
    replica pinned by an operator's session kept showing the pre-apply (or null) `last_applied` forever
    after a peer applied. `create()` and the mode-change branch of `apply_to_target()` now stamp
    `policies.applied_at` with the DB's own NOW() and hydrate this replica's `_applied_at` from that exact
    returned value; `load_from_db` (which `apply_remote_event`'s upsert branch calls) now reads that same
    column back. Simulate: loader A creates a policy, then reapplies the same rego under a new
    enforcement_mode (mode-change branch: DB UPDATE ... applied_at = NOW() RETURNING applied_at) — a fresh
    peer replica B (empty `_applied_at` for this key) then applies the remote upsert event and must see the
    SAME `applied_at` timestamp loader A now holds, proving cross-replica convergence of the display
    timestamp the same way version/mode already converge."""
    namespace = f"ns6-{uuid.uuid4().hex}"
    agent_class = "class6"
    rego = 'package remoteapplied\ndefault decision = "block"'

    await loader.create(namespace, agent_class, rego, "admin", 100, enforcement_mode="block")
    assert loader.get_applied_at(namespace, agent_class) is not None

    # Same-rego reapply with a new mode -> mode-change branch: DB UPDATE ... applied_at = NOW() RETURNING,
    # re-stamping the originator's in-memory value from the exact persisted value.
    result = await loader.apply_to_target(namespace, agent_class, namespace, agent_class, enforcement_mode="audit")
    assert result is not None
    originator_applied_at = loader.get_applied_at(namespace, agent_class)
    assert originator_applied_at is not None

    # A fresh peer replica: knows nothing about this key yet (empty _applied_at).
    peer = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    try:
        assert peer.get_applied_at(namespace, agent_class) is None

        await peer.apply_remote_event("upsert", namespace, agent_class)

        peer_applied_at = peer.get_applied_at(namespace, agent_class)
        assert peer_applied_at is not None
        assert peer_applied_at == originator_applied_at  # matches the originator's persisted stamp, not null/stale
    finally:
        await peer.close()


async def test_apply_remote_event_never_raises_on_bad_input() -> None:
    """The sync listener must survive a malformed/failed event — best-effort, never crash the loop."""
    loader = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    # an upsert with no DB configured would raise internally; apply_remote_event must swallow it
    await loader.apply_remote_event("upsert", "ns", "cls")  # no exception propagates


def test_each_loader_has_a_distinct_origin() -> None:
    """HA: the per-process origin id lets the sync listener skip its OWN echoes."""
    a = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    b = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    assert a._origin and b._origin and a._origin != b._origin


async def test_in_memory_entry_carries_enforcement_mode() -> None:
    """M4: the in-memory entry now carries enforcement_mode so list_policies can report it (was absent →
    the editor rewrote every saved policy to 'audit' on the next Save)."""
    loader = PolicyLoader(cache=_CacheStub(), evaluator=_SyncEvaluatorStub())  # type: ignore[arg-type]
    loader._update_memory("ns:cls", "package a", 100, "audit")
    assert loader._policies["ns:cls"]["enforcement_mode"] == "audit"
    # default when unspecified is block (never a silent audit downgrade)
    loader._update_memory("ns:cls2", "package b", 100)
    assert loader._policies["ns:cls2"]["enforcement_mode"] == "block"
