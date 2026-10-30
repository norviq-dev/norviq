# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The embedded engine must enforce the policy that was SAVED after a reload, mode included (backlog §6).

`norviq-engine` (and any injected sidecar in embedded mode) keeps its own `PolicyLoader` and learns about
policy writes from exactly one place: `SidecarProxy._on_policy_invalidated`, fired by the
`norviq:policy:invalidated` message that `create()` and `apply_to_target()` publish, which calls
`PolicyLoader._reload_policy`. That method read the Redis policy mirror and nothing else, and both halves
of that were wrong:

* A HIT rebuilt the entry as `{"rego", "priority"}`. The mirror has never carried `enforcement_mode`
  (`RedisCache.set_policy` stores rego, priority and version), so the evaluator's `"block"` default took
  over: re-saving a policy that is in audit mode made the engine hard-block what the console calls a
  trial.
* A MISS returned with a debug line. The mirror expires after `redis_ttl_policy_s` (60s), and a mode-only
  apply (rego unchanged) publishes the event without rewriting the mirror, so switching a policy from
  Audit to Enforce a minute after it was saved never reached the engine: it kept letting through what the
  operator had just told it to block, until a restart.

These drive the real handler with a real Redis mirror and a real Postgres row, and judge the outcome by
the engine's DECISION, not only by its in-memory dict.

The same rig pins two follow-ups: a stored priority of 0 must come back as 0 from every Postgres read,
and a DELETE must reach the engine, whose only channel is `norviq:policy:invalidated` (the delete tests
run its real pub/sub watcher).
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from structlog.testing import capture_logs

from norviq.api.db.session import close_db, create_tables, init_db
from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import POLICY_AUDIT_WOULD_BLOCK_PREFIX, OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sidecar.proxy import SidecarProxy
from tests.engine.test_priority_enforcement import FakeCache, _healthy_trust

_RULE = "reload_probe_block"


class _ConsoleEvaluatorStub:
    """The API replica the operator saves on. Its own evaluator is irrelevant here."""

    def bind_loader(self, loader: object) -> None:
        return None

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        return None

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int | None = None) -> None:
        return None


@pytest.fixture
async def redis_cache() -> RedisCache:
    url = os.getenv("NRVQ_REDIS_URL")
    if not url:
        pytest.fail("NRVQ_REDIS_URL must be set: the point of these tests is the real Redis policy mirror")
    cache = RedisCache(url=url)
    await cache.connect()
    yield cache
    await cache.close()


@pytest.fixture
async def _schema() -> None:
    pg_url = (os.getenv("NRVQ_PG_URL") or "postgresql://norviq:norviq_local_dev@127.0.0.1:5433/norviq?sslmode=disable").strip().strip("\"'")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()
    try:
        yield
    finally:
        await close_db()
        settings.pg_url = old_url


@pytest.fixture
async def rig(redis_cache: RedisCache, _schema: None, tmp_path):
    """One console replica and one embedded engine sharing Redis and Postgres, as in a cluster.

    The engine's evaluator gets the trust-neutral FakeCache so its decision is decided by policy alone;
    its LOADER gets the real Redis client, because the loader is what reads the policy mirror.
    """
    namespace = f"reload-{uuid.uuid4().hex[:12]}"
    agent_class = "support"
    console = PolicyLoader(redis_cache, _ConsoleEvaluatorStub())  # type: ignore[arg-type]
    engine_eval = OPAEvaluator(FakeCache())  # type: ignore[arg-type]
    _healthy_trust(engine_eval)
    engine = PolicyLoader(redis_cache, engine_eval)
    proxy = SidecarProxy(socket_path=str(tmp_path / "nrvq.sock"))
    proxy._evaluator = engine_eval  # what start() wires in embedded mode
    try:
        yield {"ns": namespace, "cls": agent_class, "console": console, "engine": engine,
               "engine_eval": engine_eval, "proxy": proxy, "cache": redis_cache}
    finally:
        try:
            async with console._db_engine().begin() as conn:
                await conn.execute(
                    text("DELETE FROM policy_versions WHERE policy_id IN "
                         "(SELECT id FROM policies WHERE namespace = :ns)"),
                    {"ns": namespace},
                )
                await conn.execute(text("DELETE FROM policies WHERE namespace = :ns"), {"ns": namespace})
        finally:
            await redis_cache.delete_policy(namespace, agent_class)
            await engine_eval.close()
            await engine.close()
            await console.close()


def _rego(namespace: str, body: str = "") -> str:
    package = "p_" + namespace.replace("-", "_")
    return (f'package norviq.{package}\ndefault decision = "block"\nrule_id = "{_RULE}"\n'
            f'reason = "reload probe"\n{body}')


def _layer(namespace: str, name: str, default: str, rule: str) -> str:
    """A one-rule policy with its own package, so several can be loaded side by side in one namespace."""
    package = "p_" + namespace.replace("-", "_") + "_" + name
    return f'package norviq.{package}\ndefault decision = "{default}"\nrule_id = "{rule}"\nreason = "layer probe"\n'


async def _decide(rig, evaluator: OPAEvaluator | None = None) -> tuple[str, str]:
    event = ToolCallEvent(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        tool_name="execute_sql",
        tool_params={"query": "SELECT 1"},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{rig['ns']}/sa/agent",
            namespace=rig["ns"],
            agent_class=rig["cls"],
        ),
        session_id="sess-reload",
    )
    decision = await (evaluator or rig["engine_eval"]).evaluate(event)
    return decision.decision, decision.rule_id


_ENFORCED = ("block", _RULE)
_AUDITED = ("audit", f"{POLICY_AUDIT_WOULD_BLOCK_PREFIX}{_RULE}")


async def test_switching_to_enforce_reaches_the_engine_after_the_redis_mirror_expired(rig) -> None:
    """The fail-open direction. A policy trialled in audit mode is switched to Enforce once the mirror
    has aged out; the engine must start blocking. It kept auditing (letting the call through)."""
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    rego = _rego(ns)
    await console.create(ns, cls, rego, saved_by="op", enforcement_mode="audit")
    await engine.load_from_db(ns, cls)  # what the engine's warm_cache did at startup
    assert await _decide(rig) == _AUDITED

    await rig["cache"].delete_policy(ns, cls)  # redis_ttl_policy_s (60s) passing, or a flush/eviction
    # Mode-only apply from the console: rego unchanged, so it publishes the invalidation WITHOUT
    # rewriting the mirror.
    result = await console.apply_to_target(ns, cls, ns, cls, saved_by="op", enforcement_mode="block")
    assert result is not None and result[1] is False, "expected the same-rego, mode-only apply branch"
    await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    assert engine.get_entry(ns, cls)["enforcement_mode"] == "block"
    assert await _decide(rig) == _ENFORCED


async def test_resaving_an_audit_mode_policy_does_not_make_the_engine_hard_block(rig) -> None:
    """The mode drop. An ordinary edit to a policy in audit mode leaves a FRESH mirror entry, which has
    no enforcement_mode in it; the engine rebuilt its entry from that and fell back to "block"."""
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    await console.create(ns, cls, _rego(ns), saved_by="op", enforcement_mode="audit")
    await engine.load_from_db(ns, cls)
    assert await _decide(rig) == _AUDITED

    edited = _rego(ns, body="# reworded\n")
    await console.create(ns, cls, edited, saved_by="op", enforcement_mode="audit")
    assert await rig["cache"].get_policy(ns, cls) == edited, "the mirror should be fresh for this case"
    await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    assert engine.get_current(ns, cls) == edited
    assert engine.get_entry(ns, cls).get("enforcement_mode") == "audit"
    assert await _decide(rig) == _AUDITED


async def test_switching_to_audit_while_the_mirror_is_still_fresh_reaches_the_engine(rig) -> None:
    """A mode-only apply inside the mirror's TTL hits a mirror entry written by the PREVIOUS save. Even a
    mirror that carried the mode would be stale here, which is why the reload reads Postgres."""
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    rego = _rego(ns)
    await console.create(ns, cls, rego, saved_by="op", enforcement_mode="block")
    await engine.load_from_db(ns, cls)
    assert await _decide(rig) == _ENFORCED

    result = await console.apply_to_target(ns, cls, ns, cls, saved_by="op", enforcement_mode="audit")
    assert result is not None and result[1] is False
    assert await rig["cache"].get_policy(ns, cls) == rego, "the mirror should still hold the create() entry"
    await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    assert engine.get_entry(ns, cls)["enforcement_mode"] == "audit"
    assert await _decide(rig) == _AUDITED


async def test_a_reloaded_entry_is_the_one_a_cold_start_builds(rig) -> None:
    """Field parity with the normal load path: after a reload on a mirror miss, rego, priority, mode and
    the applied_at stamp all match what `load_from_db` gives a freshly started engine."""
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    await console.create(ns, cls, _rego(ns), saved_by="op", priority=100, enforcement_mode="block")
    await engine.load_from_db(ns, cls)

    edited = _rego(ns, body="# v2\n")
    await console.create(ns, cls, edited, saved_by="op", priority=450, enforcement_mode="audit")
    await rig["cache"].delete_policy(ns, cls)
    await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    cold = PolicyLoader(rig["cache"], _ConsoleEvaluatorStub())  # type: ignore[arg-type]
    try:
        expected = await cold.load_from_db(ns, cls)
        assert expected == {"rego": edited, "priority": 450, "enforcement_mode": "audit"}
        assert engine.get_entry(ns, cls) == expected
        assert engine.get_applied_at(ns, cls) == cold.get_applied_at(ns, cls) is not None
        # The evaluator's own index carries the priority the layer stack is ordered by.
        assert rig["engine_eval"]._policies[f"{ns}:{cls}"]["priority"] == 450
    finally:
        await cold.close()


async def test_a_reload_that_finds_no_row_unloads_the_entry(rig) -> None:
    """No row means the policy was deleted, so the engine unloads it, which is what a cold start builds.
    This used to keep the entry ("unloading is the delete path's job"), but the engine has no other delete
    path: it never hears the mutation stream the API replicas use, and a deleted policy kept enforcing on
    it until a restart. The unload is logged, not silent."""
    ns, cls, engine = rig["ns"], rig["cls"], rig["engine"]
    engine._update_memory(f"{ns}:{cls}", _rego(ns), 100, "block")
    rig["engine_eval"].load_policy(ns, cls, _rego(ns), priority=100)

    with capture_logs() as logs:
        await engine._reload_policy(ns, cls)

    assert engine.get_entry(ns, cls) is None
    assert f"{ns}:{cls}" not in rig["engine_eval"]._policies
    unloaded = [e for e in logs if e["event"] == "nrvq.policy.reload_unloaded"]
    assert [(e["code"], e["log_level"], e["was_loaded"]) for e in unloaded] == [("NRVQ-REG-5023", "info", True)]
    assert not [e for e in logs if e["event"] == "nrvq.policy.reloaded" or e["log_level"] in ("warning", "error")]


async def test_a_reload_that_cannot_reach_postgres_is_an_error_and_keeps_the_previous_entry_whole(
    rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Now that the reload reads Postgres, a DB fault must surface as the handler's NRVQ-SDC-3022 error,
    not be absorbed into a "reloaded" line, and must not leave a half-built entry behind. Nor may it
    unload: a read that failed is not a row that is missing, and only the second means a delete."""
    ns, cls, engine = rig["ns"], rig["cls"], rig["engine"]
    before = {"rego": _rego(ns), "priority": 300, "enforcement_mode": "audit"}
    engine._update_memory(f"{ns}:{cls}", before["rego"], before["priority"], before["enforcement_mode"])
    rig["engine_eval"].load_policy(ns, cls, before["rego"], priority=before["priority"])

    async def _db_down(namespace: str, agent_class: str) -> dict | None:
        raise ConnectionRefusedError("postgres unreachable")

    monkeypatch.setattr(engine, "load_from_db", _db_down)
    with capture_logs() as logs:
        await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    assert [(e["event"], e["code"]) for e in logs if e["log_level"] == "error"] == [
        ("nrvq.sidecar.reload_failed", "NRVQ-SDC-3022")
    ]
    assert not [e for e in logs if e["event"] in ("nrvq.policy.reloaded", "nrvq.sidecar.policy_reloaded",
                                                  "nrvq.policy.reload_unloaded")]
    assert engine.get_entry(ns, cls) == before
    assert rig["engine_eval"]._policies[f"{ns}:{cls}"]["priority"] == before["priority"]


# --- Priority 0 -----------------------------------------------------------------------------------------
# 0 is a legal priority (the namespace band is 0-499), and every DB read path wrote
# `int(row["priority"] or 100)`, so a stored 0 came back as 100. The layer stack below makes that a
# different DECISION: a class allow at 0 sits under a namespace-tier block at 50, so the tier wins on
# the replica that saved it; read back at 100, the class allow outranks the tier and the call goes through.

_TIER_BLOCK = "ns_tier_block"
_CLASS_ALLOW = "class_allow"


async def _save_a_priority_0_allow_under_a_namespace_tier(rig) -> None:
    ns, cls, console = rig["ns"], rig["cls"], rig["console"]
    await console.create(ns, f"namespace:{ns}", _layer(ns, "tier", "block", _TIER_BLOCK), saved_by="op", priority=50)
    await console.create(ns, cls, _layer(ns, "cls", "allow", _CLASS_ALLOW), saved_by="op", priority=0)
    assert console.get_entry(ns, cls)["priority"] == 0, "the saving replica holds 0; everything else must agree"


async def test_a_priority_0_policy_is_reloaded_at_priority_0(rig) -> None:
    """The embedded engine reloads every write through `load_from_db`, so it drifted from the saving
    replica on every write, not only after a restart."""
    ns, cls, engine = rig["ns"], rig["cls"], rig["engine"]
    await _save_a_priority_0_allow_under_a_namespace_tier(rig)
    for key in (f"{ns}:namespace:{ns}", f"{ns}:{cls}"):
        await rig["proxy"]._on_policy_invalidated(key)

    assert await _decide(rig) == ("block", _TIER_BLOCK)
    assert engine.get_entry(ns, cls)["priority"] == 0
    assert rig["engine_eval"]._policies[f"{ns}:{cls}"]["priority"] == 0


async def test_a_cold_start_keeps_priority_0_in_the_entry_and_the_version_history(rig) -> None:
    """`warm_cache` builds the entry and `_rehydrate_versions` the history a rollback restores from."""
    ns, cls = rig["ns"], rig["cls"]
    await _save_a_priority_0_allow_under_a_namespace_tier(rig)

    cold_eval = OPAEvaluator(FakeCache())  # type: ignore[arg-type]
    _healthy_trust(cold_eval)
    cold = PolicyLoader(rig["cache"], cold_eval)
    try:
        await cold.warm_cache()
        assert await _decide(rig, cold_eval) == ("block", _TIER_BLOCK)
        assert cold.get_entry(ns, cls)["priority"] == 0
        assert cold.get_versions(ns, cls)[-1].priority == 0
    finally:
        await cold_eval.close()
        await cold.close()


async def test_a_peer_replica_keeps_priority_0_after_the_sync_event(rig) -> None:
    """`apply_remote_event` reads the entry through `load_from_db` and the history through
    `_rehydrate_versions_for_key`."""
    ns, cls = rig["ns"], rig["cls"]
    await _save_a_priority_0_allow_under_a_namespace_tier(rig)

    peer = PolicyLoader(rig["cache"], _ConsoleEvaluatorStub())  # type: ignore[arg-type]
    try:
        await peer.apply_remote_event("upsert", ns, cls)
        assert peer.get_entry(ns, cls)["priority"] == 0
        assert peer.get_versions(ns, cls)[-1].priority == 0
    finally:
        await peer.close()


def test_no_read_path_treats_a_stored_priority_of_0_as_missing() -> None:
    """Five copies of the idiom shipped. A `priority ... or <default>` reads 0 as absent; use
    `stored_priority`, which defaults only on NULL."""
    falsy_default = re.compile(r"""priority["']\]\s+or\b|get\(\s*["']priority["'][^)]*\)\s+or\b""")
    repo = Path(__file__).resolve().parents[2]
    offenders = [
        f"{path.relative_to(repo)}:{number}: {line.strip()}"
        for path in sorted((repo / "norviq").rglob("*.py"))
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if falsy_default.search(line)
    ]
    assert not offenders, "\n".join(offenders)


# --- Deletes --------------------------------------------------------------------------------------------
# `delete()` published only on norviq:policy_events, which only the API replicas subscribe to. The engine
# listens on norviq:policy:invalidated, so a deleted policy kept enforcing on it until a restart, and a
# deleted RELAXATION kept relaxing. These run the engine's real watcher on the real Redis channel, so they
# fail if the delete is never published there, not only if the handler mishandles it.

_INVALIDATED = "norviq:policy:invalidated"


async def _eventually(predicate, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.05)
    return True


async def _subscribers(cache: RedisCache) -> int:
    return int((await cache._pool.pubsub_numsub(_INVALIDATED))[0][1])


@pytest.fixture
async def watching(rig):
    """`SidecarProxy._watch_policy_events` subscribed on the real channel, as `start()` wires it in
    embedded mode. Redis pub/sub is not scoped to a db number, so other suites' keys may arrive too; every
    assertion here is about this test's own namespace."""
    proxy, cache = rig["proxy"], rig["cache"]
    proxy._cache = cache
    before = await _subscribers(cache)
    proxy._policy_event_task = asyncio.create_task(proxy._watch_policy_events())
    deadline = time.monotonic() + 5.0
    while await _subscribers(cache) <= before:
        assert time.monotonic() < deadline, "the engine's watcher never subscribed"
        await asyncio.sleep(0.02)
    try:
        yield rig
    finally:
        proxy._policy_event_task.cancel()
        await asyncio.gather(proxy._policy_event_task, return_exceptions=True)
        proxy._cache = None  # the redis_cache fixture owns and closes the client


def _relaxation(ns: str, cls: str, shape: str):
    """(layers that stay, the relaxation that is deleted, decision with it, decision without it)."""
    if shape == "class allow outranking a namespace-tier block":
        kept = [(f"namespace:{ns}", "block", _TIER_BLOCK, 50)]
        relaxing = (cls, "allow", _CLASS_ALLOW, 200)
        return kept, relaxing, ("allow", _CLASS_ALLOW), ("block", _TIER_BLOCK)
    kept = [(cls, "allow", _CLASS_ALLOW, 100), ("__pack__", "block", "pack_block", 100)]
    relaxing = ("__pack_weaken__", "allow", "pack_weaken_allow", 100)
    return kept, relaxing, ("allow", _CLASS_ALLOW), ("block", "pack_block")


@pytest.mark.parametrize("shape", ["class allow outranking a namespace-tier block", "pack weaken over a pack block"])
async def test_a_deleted_relaxation_stops_relaxing_on_the_embedded_engine(watching, shape: str) -> None:
    rig = watching
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    kept, relaxing, relaxed, enforced = _relaxation(ns, cls, shape)
    for scope, default, rule, priority in [*kept, relaxing]:
        await console.create(ns, scope, _layer(ns, rule, default, rule), saved_by="op", priority=priority)
    scopes = [scope for scope, *_ in [*kept, relaxing]]
    assert await _eventually(lambda: all(engine.get_entry(ns, s) is not None for s in scopes)), (
        "the engine never heard the creates, so this test would prove nothing about the delete"
    )
    assert await _decide(rig) == relaxed

    assert await console.delete(ns, relaxing[0]) is True
    assert await _eventually(lambda: engine.get_entry(ns, relaxing[0]) is None), (
        "the delete never reached the embedded engine; it is still enforcing the deleted policy"
    )
    assert f"{ns}:{relaxing[0]}" not in rig["engine_eval"]._policies
    assert await _decide(rig) == enforced


async def test_a_delete_notice_that_meets_a_db_error_does_not_unload(
    watching, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delete notice arrives, but the engine's read fails. Unloading on that would drop a policy on
    any transient fault, including a blocking one on a plain upsert notice, so the entry stays whole and
    the failure is the handler's NRVQ-SDC-3022 error."""
    rig = watching
    ns, cls, console, engine = rig["ns"], rig["cls"], rig["console"], rig["engine"]
    key = f"{ns}:{cls}"
    await console.create(ns, cls, _rego(ns), saved_by="op", priority=300)
    assert await _eventually(lambda: engine.get_entry(ns, cls) is not None)
    before = engine.get_entry(ns, cls)

    async def _db_down(namespace: str, agent_class: str) -> dict | None:
        raise ConnectionRefusedError("postgres unreachable")

    handled = {"nrvq.sidecar.reload_failed", "nrvq.sidecar.policy_reloaded", "nrvq.policy.reload_unloaded"}
    monkeypatch.setattr(engine, "load_from_db", _db_down)
    with capture_logs() as logs:
        assert await console.delete(ns, cls) is True
        assert await _eventually(lambda: any(e["event"] in handled and e.get("key") == key for e in logs)), (
            "the delete notice never reached the engine"
        )

    assert engine.get_entry(ns, cls) == before
    assert key in rig["engine_eval"]._policies
    mine = [e for e in logs if e.get("key") == key]
    assert [(e["event"], e["code"]) for e in mine if e["log_level"] == "error"] == [
        ("nrvq.sidecar.reload_failed", "NRVQ-SDC-3022")
    ]
    assert not [e for e in mine if e["event"] in handled - {"nrvq.sidecar.reload_failed"}]
