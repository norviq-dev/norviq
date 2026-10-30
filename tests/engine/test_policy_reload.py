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
"""

from __future__ import annotations

import os
import uuid

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


async def _decide(rig) -> tuple[str, str]:
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
    decision = await rig["engine_eval"].evaluate(event)
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


async def test_a_reload_that_finds_no_policy_is_logged_as_a_warning(rig) -> None:
    """An invalidation for a scope with no row (it was deleted after the save) must be visible. It used to
    be a DEBUG line, which production log levels drop, so a reload that did nothing looked like one that
    worked. The entry already in memory is left alone: unloading is the delete path's job."""
    ns, cls, engine = rig["ns"], rig["cls"], rig["engine"]
    engine._update_memory(f"{ns}:{cls}", _rego(ns), 100, "block")

    with capture_logs() as logs:
        await engine._reload_policy(ns, cls)

    warnings = [entry for entry in logs if entry["log_level"] == "warning"]
    assert [(w["event"], w["code"]) for w in warnings] == [("nrvq.policy.reload_not_found", "NRVQ-REG-5023")]
    assert not [entry for entry in logs if entry["event"] == "nrvq.policy.reloaded"]
    assert engine.get_entry(ns, cls) == {"rego": _rego(ns), "priority": 100, "enforcement_mode": "block"}


async def test_a_reload_that_cannot_reach_postgres_is_an_error_and_keeps_the_previous_entry_whole(
    rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Now that the reload reads Postgres, a DB fault must surface as the handler's NRVQ-SDC-3022 error,
    not be absorbed into a "reloaded" line, and must not leave a half-built entry behind."""
    ns, cls, engine = rig["ns"], rig["cls"], rig["engine"]
    before = {"rego": _rego(ns), "priority": 300, "enforcement_mode": "audit"}
    engine._update_memory(f"{ns}:{cls}", before["rego"], before["priority"], before["enforcement_mode"])

    async def _db_down(namespace: str, agent_class: str) -> dict | None:
        raise ConnectionRefusedError("postgres unreachable")

    monkeypatch.setattr(engine, "load_from_db", _db_down)
    with capture_logs() as logs:
        await rig["proxy"]._on_policy_invalidated(f"{ns}:{cls}")

    assert [(e["event"], e["code"]) for e in logs if e["log_level"] == "error"] == [
        ("nrvq.sidecar.reload_failed", "NRVQ-SDC-3022")
    ]
    assert not [e for e in logs if e["event"] in ("nrvq.policy.reloaded", "nrvq.sidecar.policy_reloaded")]
    assert engine.get_entry(ns, cls) == before
