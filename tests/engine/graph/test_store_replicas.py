# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The asset graph with more than one API replica.

The chart runs two API replicas. Each keeps its own live graph per namespace and used to save the
WHOLE graph as a new snapshot row; every reader takes the newest row. So the last replica to write
erased whatever the other had recorded since: a namespace's audit log showed a tool called three
times that the graph did not have, call counts read about a third of the audit's, and a node DELETE
on one replica was undone by the other's next save.

Each test runs two builders + two GraphStore instances (one per "replica") against ONE shared store
— a fake Redis and a fake Postgres whose advisory lock is shared — which is the deployment shape.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from structlog.testing import capture_logs

from norviq.api.db.models import AssetGraph
from norviq.api.graph_maintenance import remove_graph_node
from norviq.engine.graph import store as store_module
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.store import GraphStore, GraphStoreBusy

NS = "analytics"
AGENT = "spiffe://norviq/ns/analytics/sa/default"


class _Pool:
    """One Redis shared by every replica: values, SET NX for the lock, the release script, TIME."""

    def __init__(self, clock=None) -> None:
        self.values: dict[str, str] = {}
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.fail_sets = False
        self.fail_deletes = False
        self.fail_time = False

    # Each call yields to the event loop, as a real Redis round trip does; without it no task can run
    # between a save serializing the graph and the save finishing.
    async def set(self, key: str, value: str, ex: int | None = None, px: int | None = None,
                  nx: bool = False) -> bool | None:
        await asyncio.sleep(0)
        if self.fail_sets and not key.startswith("lock:"):
            raise ConnectionError("redis: connection refused")
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True

    async def get(self, key: str) -> str | None:
        await asyncio.sleep(0)
        return self.values.get(key)

    async def delete(self, key: str) -> int:
        await asyncio.sleep(0)
        if self.fail_deletes:
            raise ConnectionError("redis: connection refused")
        return 1 if self.values.pop(key, None) is not None else 0

    async def eval(self, script: str, numkeys: int, key: str, token: str) -> int:
        """The store's compare-and-delete release: delete ``key`` only while it holds ``token``."""
        assert "redis.call('get', KEYS[1]) == ARGV[1]" in script and numkeys == 1
        await asyncio.sleep(0)
        if self.values.get(key) == token:
            del self.values[key]
            return 1
        return 0

    async def time(self) -> tuple[int, int]:
        await asyncio.sleep(0)
        if self.fail_time:
            raise ConnectionError("redis: TIME refused")
        now = self.clock()
        return int(now.timestamp()), now.microsecond


class _Cache:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool


class _Postgres:
    """One database shared by every replica: snapshot rows + the advisory lock + its clock."""

    def __init__(self, clock=None) -> None:
        self.rows: list[AssetGraph] = []
        self.lock = asyncio.Lock()
        self.lock_calls = 0
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.fail_commit = False
        self.down = False

    def latest(self, namespace: str) -> AssetGraph | None:
        rows = [r for r in self.rows if r.namespace == namespace]
        return max(rows, key=lambda r: r.built_at) if rows else None

    def factory(self):
        db = self

        async def get_session():
            if db.down:
                raise ConnectionError("postgres: connection refused")
            session = _Session(db)
            try:
                yield session
            finally:
                await session.close()

        return get_session


class _Session:
    def __init__(self, db: _Postgres) -> None:
        self._db = db
        self._pending: list[AssetGraph] = []
        self._locked = False

    # Each call yields to the event loop, as a network round trip does, so concurrent sessions really
    # interleave; without that, a test of the lock passes with no lock at all.
    async def execute(self, statement, params=None):
        await asyncio.sleep(0)
        if "pg_advisory_xact_lock" in str(statement):
            await self._db.lock.acquire()
            self._locked = True
            self._db.lock_calls += 1

    async def scalar(self, statement):
        await asyncio.sleep(0)
        sql = str(statement)
        if "clock_timestamp()" in sql:
            return self._db.clock()
        params = statement.compile().params
        namespace = next(v for k, v in params.items() if k.startswith("namespace"))
        if "graph_json ?" in sql:  # the newest row that records tombstones
            rows = [r for r in self._db.rows if r.namespace == namespace and "tombstones" in r.graph_json]
            return max(rows, key=lambda r: r.built_at).graph_json if rows else None
        latest = self._db.latest(namespace)
        if sql.startswith("SELECT asset_graph.built_at \n"):
            return latest.built_at if latest is not None else None
        return latest

    def add(self, row: AssetGraph) -> None:
        self._pending.append(row)

    async def commit(self) -> None:
        await asyncio.sleep(0)
        if self._db.fail_commit:
            self._pending = []
            self._release()
            raise ConnectionError("postgres: connection lost during COMMIT")
        for row in self._pending:
            # JSONB round trip: enums become strings, nothing is shared with the writer's objects.
            row.graph_json = json.loads(json.dumps(row.graph_json))
            if row.built_at is None:
                row.built_at = datetime.now(timezone.utc)
            self._db.rows.append(row)
        self._pending = []
        self._release()

    async def rollback(self) -> None:
        self._pending = []
        self._release()

    async def close(self) -> None:
        self._pending = []
        self._release()
        # Handing the connection back to the pool is more than one round trip; a task waiting on the
        # lock runs in that gap, which is the window the in-process lock exists for.
        for _ in range(3):
            await asyncio.sleep(0)

    def _release(self) -> None:
        if self._locked:
            self._locked = False
            self._db.lock.release()


def _replicas(with_db: bool, clock=None, skews: tuple[float, float] = (0, 0)):
    """Two (builder, store) pairs sharing one Redis and, optionally, one Postgres.

    With ``clock``, Postgres and Redis TIME read it and each builder's wall clock is it plus that
    replica's skew in seconds."""
    pool = _Pool(clock)
    db = _Postgres(clock) if with_db else None
    stores = [GraphStore(_Cache(pool), session_factory=db.factory() if db else None) for _ in range(2)]
    if clock is None:
        return (AssetGraphBuilder(), stores[0]), (AssetGraphBuilder(), stores[1]), db
    builders = [AssetGraphBuilder(wall_clock=lambda s=skew: clock() + timedelta(seconds=s)) for skew in skews]
    return (builders[0], stores[0]), (builders[1], stores[1]), db


async def _persisted(store: GraphStore, db: _Postgres | None) -> dict:
    """What every reader sees: the newest DB row (GET /asset-graph), else the cached snapshot."""
    if db is not None:
        row = db.latest(NS)
        return row.graph_json if row is not None else {}
    loaded = await store.load(NS)
    return loaded.to_dict() if loaded is not None else {}


def _tools(payload: dict) -> dict[str, int]:
    return {n["id"]: n["properties"]["call_count"] for n in payload.get("nodes", []) if n.get("type") == "tool"}


def _call(graph: AssetGraphBuilder, tool: str, trust: float | None = None, agent: str = AGENT) -> None:
    graph.record_tool_call(agent, tool, "allow", namespace=NS, agent_class="analyst", trust_score=trust)


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_tool_recorded_by_one_replica_survives_the_other_replicas_save(with_db: bool) -> None:
    """FAIL-ON-BUG: get_order was in the audit log three times and absent from the graph."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    _call(a, "get_customer")
    await store_a.save(NS, a)
    _call(b, "get_order")
    await store_b.save(NS, b)
    _call(a, "search_kb")
    await store_a.save(NS, a)  # a never saw get_order; before the fix this row dropped it

    tools = _tools(await _persisted(store_a, db))
    assert set(tools) == {"tool:get_customer", "tool:get_order", "tool:search_kb"}


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_call_counts_from_both_replicas_add_up(with_db: bool) -> None:
    """FAIL-ON-BUG: snapshot counts were about a third of the audit's (one replica's share)."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    for _ in range(3):
        _call(a, "get_customer")
        await store_a.save(NS, a)
        _call(b, "get_customer")
        _call(b, "get_customer")
        await store_b.save(NS, b)
    await store_a.save(NS, a)

    persisted = await _persisted(store_a, db)
    assert _tools(persisted)["tool:get_customer"] == 9
    edge = next(e for e in persisted["edges"] if e["target"] == "tool:get_customer")
    assert edge["properties"]["call_count"] == 9
    # And each replica's own builder converged on the same total, so its next save starts from it.
    assert a.graph.nodes["tool:get_customer"]["properties"]["call_count"] == 9


async def test_concurrent_saves_from_both_replicas_lose_nothing() -> None:
    """Saves race in production (background tasks on two pods). The read-merge-write must be
    serialized, or two writers merge the same row and one's calls vanish."""
    (a, store_a), (b, store_b), db = _replicas(True)

    async def replica(graph: AssetGraphBuilder, store: GraphStore, tool: str, n: int) -> None:
        for _ in range(n):
            _call(graph, tool)
            _call(graph, "shared")
            await store.save(NS, graph)

    await asyncio.gather(replica(a, store_a, "only_a", 7), replica(b, store_b, "only_b", 5),
                         replica(a, store_a, "only_a", 4))
    await store_a.save(NS, a)
    await store_b.save(NS, b)

    tools = _tools(await _persisted(store_a, db))
    assert tools == {"tool:only_a": 11, "tool:only_b": 5, "tool:shared": 16}
    # Every write takes the advisory lock. Not one lock per save() call: two loops share builder a, so
    # some of its saves collapse into the one already waiting and never write.
    assert db is not None and len(db.rows) >= 2
    assert db.lock_calls == len(db.rows), "every snapshot write must take the namespace advisory lock"


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_trust_is_the_most_recent_one_whichever_replica_saves_last(with_db: bool) -> None:
    """FAIL-ON-BUG: graph trust flipped between replicas' numbers and disagreed with the roster."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    _call(a, "get_customer", trust=0.52)
    await store_a.save(NS, a)
    _call(b, "get_customer", trust=0.455)
    await store_b.save(NS, b)
    await store_a.save(NS, a)  # a's copy is older; it must not win just by writing last

    agent = next(n for n in (await _persisted(store_a, db))["nodes"] if n["id"] == AGENT)
    assert agent["properties"]["trust_score"] == 0.455
    assert agent["properties"]["trust_category"] == "medium"


def _request(graph: AssetGraphBuilder, store: GraphStore):
    async def _restore(_ns: str) -> None:
        return None

    evaluator = SimpleNamespace(get_graph=lambda _ns: graph, _restore_graph=_restore)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(evaluator=evaluator, graph_store=store)))


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_removal_on_one_replica_is_not_saved_back_by_the_other(with_db: bool) -> None:
    """FAIL-ON-BUG: DELETE returned 200, then the other replica's next save restored the node."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    _call(a, "send_email")
    _call(a, "get_customer")
    await store_a.save(NS, a)
    _call(b, "send_email")
    await store_b.save(NS, b)

    assert await remove_graph_node(_request(a, store_a), NS, "tool:send_email") is True
    _call(b, "get_customer")  # b still holds tool:send_email in memory
    await store_b.save(NS, b)

    persisted = await _persisted(store_b, db)
    assert "tool:send_email" not in _tools(persisted)
    assert not any("tool:send_email" in (e["source"], e["target"]) for e in persisted["edges"])
    assert "tool:send_email" not in b.graph, "b must drop its own copy, or it returns on a later save"
    assert _tools(persisted)["tool:get_customer"] == 2


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_node_only_the_other_replica_recorded_can_be_removed(with_db: bool) -> None:
    """FAIL-ON-BUG: GET served the node, DELETE on the replica that lacked it said 404."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    _call(a, "get_customer")
    await store_a.save(NS, a)
    _call(b, "process_payment")
    await store_b.save(NS, b)

    assert await remove_graph_node(_request(a, store_a), NS, "tool:process_payment") is True
    assert "tool:process_payment" not in _tools(await _persisted(store_a, db))
    # Absent everywhere now: a second DELETE is an honest 404.
    assert await remove_graph_node(_request(b, store_b), NS, "tool:process_payment") is False


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_tool_called_again_after_removal_comes_back_with_only_the_new_calls(with_db: bool) -> None:
    """A removal is not a block: new traffic is new evidence and must show, without the old count."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    for _ in range(4):
        _call(b, "read_env")
    await store_b.save(NS, b)
    assert await remove_graph_node(_request(a, store_a), NS, "tool:read_env") is True

    _call(b, "read_env")
    await store_b.save(NS, b)
    await store_a.save(NS, a)

    assert _tools(await _persisted(store_a, db))["tool:read_env"] == 1


async def test_a_snapshot_written_by_the_previous_release_is_merged_not_overwritten() -> None:
    """Rolling upgrade: an old pod wrote a row with no activity stamps and no tombstones. A new pod
    that never restored it must merge it, and must still be able to read it."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    old_payload = {
        "nodes": [
            {"id": AGENT, "type": "agent", "label": "analyst", "namespace": NS, "last_seen_tick": 3,
             "properties": {"agent_class": "analyst", "agent_classes": ["analyst"], "trust_score": 0.6,
                            "trust_category": "medium"}},
            {"id": "tool:get_order", "type": "tool", "label": "get_order", "namespace": NS, "last_seen_tick": 2,
             "properties": {"risk_level": "medium", "call_count": 3}},
        ],
        "edges": [
            {"source": AGENT, "target": "tool:get_order", "type": "calls",
             "properties": {"call_count": 3, "last_decision": "allow",
                            "last_timestamp": "2026-11-01T10:00:00+00:00"}},
        ],
    }
    db.rows.append(AssetGraph(namespace=NS, node_count=2, edge_count=1, graph_json=old_payload,
                              built_at=datetime(2026, 11, 1, 10, 0, tzinfo=timezone.utc)))

    _call(a, "get_customer", trust=0.5)
    await store_a.save(NS, a)

    persisted = await _persisted(store_a, db)
    assert _tools(persisted) == {"tool:get_order": 3, "tool:get_customer": 1}
    agent = next(n for n in persisted["nodes"] if n["id"] == AGENT)
    assert agent["properties"]["trust_score"] == 0.5, "the stamped (newer) copy wins over the unstamped one"
    reread = AssetGraphBuilder()
    reread.from_dict(old_payload)
    assert reread.get_node_count()["tools"] == 1


async def test_a_merged_row_sorts_newest_even_when_this_pods_clock_is_behind() -> None:
    """Readers take the newest built_at. A union written by a pod whose clock lags the previous
    writer's would otherwise sort BEHIND the row it was merged from and never be served."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    ahead = datetime(2099, 1, 1, tzinfo=timezone.utc)
    db.rows.append(AssetGraph(namespace=NS, node_count=0, edge_count=0, built_at=ahead,
                              graph_json={"nodes": [{"id": "tool:x", "type": "tool", "properties": {"call_count": 1}}],
                                          "edges": []}))
    _call(a, "get_customer")
    await store_a.save(NS, a)

    assert set(_tools(db.latest(NS).graph_json)) == {"tool:x", "tool:get_customer"}


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_call_made_before_the_removal_but_saved_after_it_does_not_bring_the_node_back(with_db: bool) -> None:
    """The removal covers every call made before it, including one the other replica had not saved
    yet. Without the tombstone, b's unsaved call reads as fresh activity and b re-saves the node."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    _call(b, "export_records")
    await store_b.save(NS, b)
    _call(b, "export_records")  # recorded on b, not yet saved
    assert await remove_graph_node(_request(a, store_a), NS, "tool:export_records") is True
    await store_b.save(NS, b)

    assert "tool:export_records" not in _tools(await _persisted(store_b, db))
    assert "tool:export_records" not in b.graph


async def test_a_removed_node_written_back_by_a_previous_release_pod_stays_removed() -> None:
    """Rolling upgrade: a pod on the previous release knows nothing of tombstones and writes its whole
    graph, removed node included. The next save by an upgraded pod must not take that copy back."""
    (a, store_a), (b, store_b), db = _replicas(True)
    assert db is not None
    _call(b, "delete_record")
    _call(b, "get_customer")
    await store_b.save(NS, b)
    stale = json.loads(json.dumps(db.latest(NS).graph_json))  # what the old pod still holds
    assert await remove_graph_node(_request(a, store_a), NS, "tool:delete_record") is True
    stale.pop("tombstones", None)
    db.rows.append(AssetGraph(namespace=NS, node_count=0, edge_count=0, graph_json=stale,
                              built_at=datetime.now(timezone.utc)))

    _call(a, "search_kb")
    await store_a.save(NS, a)

    persisted = db.latest(NS).graph_json
    assert "tool:delete_record" not in _tools(persisted)
    assert "tool:delete_record" in persisted.get("tombstones", {}), "the tombstone must survive the old pod's row"


async def test_saves_queued_behind_a_running_one_collapse_into_one_write() -> None:
    """Saves of a namespace are serialized now, and the evaluator saves once per tool call. Without
    collapsing, every call adds a waiting save and the backlog grows with the call rate."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    saves = []
    for _ in range(20):
        _call(a, "get_customer")
        saves.append(asyncio.ensure_future(store_a.save(NS, a)))
    await asyncio.gather(*saves)

    assert len(db.rows) <= 2, f"{len(db.rows)} snapshot writes for one burst"
    assert _tools(db.latest(NS).graph_json)["tool:get_customer"] == 20, "a collapsed save lost a call"


async def test_two_first_calls_restoring_at_once_keep_one_builder() -> None:
    """Two first calls for a namespace both load the snapshot. The one that finished second used to
    replace the builder the first had already recorded into, so that call never reached the graph."""
    from norviq.engine.evaluator import OPAEvaluator

    release = asyncio.Event()

    class _SlowStore:
        def __init__(self) -> None:
            self.calls = 0

        async def load(self, _namespace: str) -> AssetGraphBuilder:
            self.calls += 1
            if self.calls == 1:
                await release.wait()  # the first load to start finishes last, after the other recorded
            return AssetGraphBuilder()

    evaluator = OPAEvaluator(_Cache(_Pool()))
    evaluator.bind_graph_store(_SlowStore())  # type: ignore[arg-type]
    second = asyncio.ensure_future(evaluator._restore_graph(NS))
    await asyncio.sleep(0)
    assert evaluator._graph_store.calls == 1, "the slow load must be in flight before the second starts"
    await evaluator._restore_graph(NS)
    _call(evaluator.get_graph(NS), "get_order")
    release.set()
    await second

    assert "tool:get_order" in evaluator.get_graph(NS).graph


async def test_a_snapshot_that_expired_from_the_cache_does_not_empty_the_graph() -> None:
    """Without a database the snapshot is only the cached copy, which expires after five minutes. An
    absent snapshot is not one that dropped elements: the next save must keep what the builder holds."""
    (a, store_a), _, _ = _replicas(False)
    for tool in ("get_customer", "get_order", "search_kb"):
        _call(a, tool)
    await store_a.save(NS, a)
    store_a._cache._pool.values.clear()  # the cache TTL ran out

    _call(a, "send_email")
    await store_a.save(NS, a)

    assert _tools(await _persisted(store_a, None)) == {
        "tool:get_customer": 1, "tool:get_order": 1, "tool:search_kb": 1, "tool:send_email": 1}


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_call_recorded_while_a_save_is_in_flight_is_counted_once(with_db: bool) -> None:
    """FAIL-ON-BUG, one replica is enough. The evaluator saves in a background task, so calls land
    while a save is waiting on Redis or Postgres. The saved payload shared its property dicts with the
    live graph, so those calls showed up in what the save recorded as stored without being in the row.
    The next merge then subtracted them: three calls persisted as two."""
    (a, store_a), _, db = _replicas(with_db)
    _call(a, "get_customer")
    save = asyncio.ensure_future(store_a.save(NS, a))
    in_flight = 0
    while not save.done():
        await asyncio.sleep(0)
        _call(a, "get_customer")
        in_flight += 1
    await save
    _call(a, "get_customer")
    await store_a.save(NS, a)

    expected = 1 + in_flight + 1
    persisted = await _persisted(store_a, db)
    assert _tools(persisted)["tool:get_customer"] == expected
    edge = next(e for e in persisted["edges"] if e["target"] == "tool:get_customer")
    assert edge["properties"]["call_count"] == expected
    assert a.graph.nodes["tool:get_customer"]["properties"]["call_count"] == expected


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_background_saves_on_both_replicas_keep_every_call(with_db: bool) -> None:
    """The production shape: each call records, then queues its save as a task, on two replicas.

    FAIL-ON-BUG in redis-only: without a database the saves were serialized within one process only,
    so the two replicas read the same cached copy, each wrote back its merge, and one's calls were
    lost. The Redis lock serializes them across replicas."""
    (a, store_a), (b, store_b), db = _replicas(with_db)
    saves = []
    for i in range(30):
        graph, store = (a, store_a) if i % 3 else (b, store_b)
        _call(graph, "get_customer")
        _call(graph, "only_a" if graph is a else "only_b")
        saves.append(asyncio.ensure_future(store.save(NS, graph)))
        await asyncio.sleep(0)
    await asyncio.gather(*saves)
    await store_a.save(NS, a)
    await store_b.save(NS, b)
    await store_a.save(NS, a)

    assert _tools(await _persisted(store_a, db)) == {
        "tool:get_customer": 30, "tool:only_a": 20, "tool:only_b": 10}


async def test_saves_stay_collapsed_under_sustained_calls() -> None:
    """FAIL-ON-BUG: a finished save cleared the queued marker that the save waiting behind it had
    set, so the next call queued another save. Under steady traffic the backlog grew with every
    write (39 pending saves after 300 calls) instead of staying at one running and one waiting."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    saves = []
    pending = []
    for _ in range(300):
        _call(a, "get_customer")
        saves.append(asyncio.ensure_future(store_a.save(NS, a)))
        await asyncio.sleep(0)
        pending.append(sum(1 for s in saves if not s.done()))
    await asyncio.gather(*saves)

    assert max(pending) <= 2, f"{max(pending)} saves pending at once"
    assert _tools(db.latest(NS).graph_json)["tool:get_customer"] == 300


# ---------------------------------------------------------------------------------------------------
# The cache and the database: what is cached is what committed, and a database outage still updates it.


async def test_a_removal_whose_commit_fails_is_not_served_from_the_cache() -> None:
    """FAIL-ON-BUG: the cache was written inside the transaction, before COMMIT. A removal whose
    commit failed was already in the cache, so every graph surface (they read the cache first) showed
    the node gone for five minutes while the DELETE reported an error and the row still held it."""
    (a, store_a), (_, store_b), db = _replicas(True)
    assert db is not None
    _call(a, "send_email")
    _call(a, "get_customer")
    await store_a.save(NS, a)

    db.fail_commit = True
    with pytest.raises(ConnectionError):
        await remove_graph_node(_request(a, store_a), NS, "tool:send_email")

    served = await store_b.load(NS)
    assert served is not None and "tool:send_email" in served.graph, "the cache served an uncommitted removal"
    assert "tool:send_email" in _tools(db.latest(NS).graph_json)

    # Nor does the replica carry the failed removal out on its next ordinary save.
    db.fail_commit = False
    _call(a, "send_email")
    await store_a.save(NS, a)
    assert _tools(db.latest(NS).graph_json) == {"tool:send_email": 2, "tool:get_customer": 1}
    assert "tool:send_email" not in db.latest(NS).graph_json.get("tombstones", {})


async def test_redis_only_a_removal_redis_refused_is_not_carried_out_later() -> None:
    """FAIL-ON-BUG: without a database, a removal whose cache write failed stayed in the builder as a
    tombstone, so the next ordinary save removed the node after the DELETE had failed."""
    (a, store_a), _, _ = _replicas(False)
    _call(a, "send_email")
    await store_a.save(NS, a)
    pool = store_a._cache._pool
    pool.fail_sets = True
    with pytest.raises(ConnectionError):
        await remove_graph_node(_request(a, store_a), NS, "tool:send_email")

    pool.fail_sets = False
    _call(a, "send_email")
    await store_a.save(NS, a)
    assert _tools(await _persisted(store_a, None)) == {"tool:send_email": 2}


async def test_a_committed_save_stands_when_the_cache_write_fails() -> None:
    """FAIL-ON-BUG: the cache write ran before COMMIT, so with Redis refusing writes no snapshot
    reached Postgres at all and the save failed. The row commits now; the cache is a copy of it, and a
    copy that cannot be written is deleted so readers go to Postgres instead of an older payload."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    _call(a, "get_customer")
    await store_a.save(NS, a)
    pool = store_a._cache._pool
    pool.fail_sets = True

    _call(a, "get_customer")
    await store_a.save(NS, a)  # must not raise: the row committed

    assert _tools(db.latest(NS).graph_json)["tool:get_customer"] == 2
    assert f"graph:{NS}" not in pool.values, "a stale cached copy would hide the committed row"
    pool.fail_sets = False
    _call(a, "get_customer")
    await store_a.save(NS, a)
    assert _tools(db.latest(NS).graph_json)["tool:get_customer"] == 3, "the committed save was counted twice"


async def _within(awaitable, what: str, seconds: float = 5.0):
    """Fail, rather than hang, when the code under test never reaches the point the test waits for.
    There is no pytest-timeout here, so an unbounded wait turned a regression into a stalled job."""
    try:
        return await asyncio.wait_for(awaitable, seconds)
    except asyncio.TimeoutError:
        pytest.fail(f"{what} did not happen within {seconds}s")


class _GatedPool:
    """The shared Redis, except that this replica's lock requests wait for ``release``."""

    def __init__(self, inner: _Pool) -> None:
        self.inner = inner
        self.arrived = asyncio.Event()
        self.release = asyncio.Event()

    def __getattr__(self, name: str):
        return getattr(self.inner, name)

    async def set(self, key: str, value: str, ex: int | None = None, px: int | None = None,
                  nx: bool = False) -> bool | None:
        if key.startswith("lock:"):
            self.arrived.set()
            await self.release.wait()
        return await self.inner.set(key, value, ex=ex, px=px, nx=nx)


async def test_a_late_cache_write_does_not_replace_a_newer_commit() -> None:
    """The cache is written after the commit now, outside the advisory lock. A replica that committed
    first but reached the cache last would overwrite the newer row's copy with its older one and serve
    it for five minutes. It checks, under the Redis lock, that its row is still the newest."""
    (a, store_a), (b, store_b), db = _replicas(True)
    assert db is not None
    gated = _GatedPool(store_a._cache._pool)
    store_a = GraphStore(_Cache(gated), session_factory=db.factory())  # type: ignore[arg-type]
    _call(a, "get_customer")
    late = asyncio.ensure_future(store_a.save(NS, a))
    # a has committed and is waiting to write the cache
    await _within(gated.arrived.wait(), "the committed save taking the Redis lock before its cache write")

    _call(b, "get_order")
    await store_b.save(NS, b)  # merges a's row, commits after it, caches the union
    gated.release.set()
    await late

    served = await store_b.load(NS)
    assert served is not None
    assert _tools(served.to_dict()) == {"tool:get_customer": 1, "tool:get_order": 1}


async def test_while_the_database_is_down_saves_merge_into_the_cached_copy() -> None:
    """FAIL-ON-BUG: once the cache moved after the commit, a save with Postgres down updated nothing,
    so the console froze on the last committed graph for the whole outage. The calls are merged into
    the cached copy, without erasing what is already there, and reach Postgres once it is back."""
    (a, store_a), (b, store_b), db = _replicas(True)
    assert db is not None
    _call(a, "get_customer")
    await store_a.save(NS, a)

    db.down = True
    _call(b, "get_order")
    with pytest.raises(ConnectionError):
        await store_b.save(NS, b)
    served = await store_a.load(NS)
    assert served is not None
    assert _tools(served.to_dict()) == {"tool:get_customer": 1, "tool:get_order": 1}

    _call(b, "get_order")  # a second cache-only write must not count the first one again
    with pytest.raises(ConnectionError):
        await store_b.save(NS, b)
    _call(a, "get_customer")
    with pytest.raises(ConnectionError):
        await store_a.save(NS, a)
    served = await store_a.load(NS)
    assert served is not None
    assert _tools(served.to_dict()) == {"tool:get_customer": 2, "tool:get_order": 2}

    db.down = False
    await store_b.save(NS, b)
    await store_a.save(NS, a)
    assert _tools(db.latest(NS).graph_json) == {"tool:get_customer": 2, "tool:get_order": 2}
    served = await store_b.load(NS)
    assert served is not None and _tools(served.to_dict()) == {"tool:get_customer": 2, "tool:get_order": 2}


async def test_a_cache_only_write_keeps_a_newer_commit() -> None:
    """One replica cannot reach Postgres while the other can. The replica that is down must merge into
    the copy the other just committed and cached, not overwrite it with its own graph."""
    (a, store_a), (b, _), db = _replicas(True)
    assert db is not None
    down = db.factory()

    async def unreachable():
        raise ConnectionError("postgres: connection refused")
        yield  # pragma: no cover - makes this an async generator, like get_session

    store_b = GraphStore(store_a._cache, session_factory=unreachable)
    _call(a, "get_customer")
    await store_a.save(NS, a)
    _call(b, "get_order")
    with pytest.raises(ConnectionError):
        await store_b.save(NS, b)

    _call(a, "search_kb")
    await store_a.save(NS, a)  # commits, and caches the committed row (without b's get_order)
    _call(b, "get_order")
    with pytest.raises(ConnectionError):
        await store_b.save(NS, b)

    served = await store_a.load(NS)
    assert served is not None
    assert _tools(served.to_dict()) == {"tool:get_customer": 1, "tool:search_kb": 1, "tool:get_order": 2}
    store_b._session_factory = down
    await store_b.save(NS, b)
    assert _tools(db.latest(NS).graph_json) == {"tool:get_customer": 1, "tool:search_kb": 1, "tool:get_order": 2}


# ---------------------------------------------------------------------------------------------------
# Redis-only mode: the cross-replica lock.


async def test_redis_only_saves_take_a_lock_and_release_only_their_own() -> None:
    """FAIL-ON-BUG: without a database there was no cross-replica lock at all. The lock is SET NX PX
    with a token and released by compare-and-delete: a save whose lock lapsed and was taken by another
    replica must leave that replica's lock alone."""
    (a, store_a), _, _ = _replicas(False)
    pool = store_a._cache._pool
    seen: list[str | None] = []
    real_get = pool.get

    async def get(key: str) -> str | None:
        if key == f"graph:{NS}":
            seen.append(pool.values.get(f"lock:graph:{NS}"))
            pool.values[f"lock:graph:{NS}"] = "another-replica"  # our TTL lapsed; someone else holds it
        return await real_get(key)

    pool.get = get
    _call(a, "get_customer")
    await store_a.save(NS, a)

    assert seen and seen[0] not in (None, "another-replica"), "the read-merge-write ran without the lock"
    assert pool.values.get(f"lock:graph:{NS}") == "another-replica", "released a lock it no longer held"


async def test_redis_only_save_waits_for_the_lock_then_gives_up_without_losing_calls(monkeypatch) -> None:
    """FAIL-ON-BUG: a save never waited for another replica's read-merge-write. When the lock stays
    taken, the save fails rather than writing unlocked, and the builder keeps the call for its next one."""
    monkeypatch.setattr(store_module, "_LOCK_WAIT_S", 0.05)
    (a, store_a), _, _ = _replicas(False)
    pool = store_a._cache._pool
    pool.values[f"lock:graph:{NS}"] = "another-replica"
    _call(a, "get_customer")
    with pytest.raises(GraphStoreBusy):
        await _within(store_a.save(NS, a), "the save giving up on a held lock")
    assert f"graph:{NS}" not in pool.values

    del pool.values[f"lock:graph:{NS}"]  # the other replica finished
    _call(a, "get_customer")
    await store_a.save(NS, a)
    assert _tools(await _persisted(store_a, None))["tool:get_customer"] == 2
    assert f"lock:graph:{NS}" not in pool.values


# ---------------------------------------------------------------------------------------------------
# Clocks: activity and removals are stamped on the shared clock, and a fast clock's stamps are bounded.


class _TrueClock:
    """The database's (or Redis's) clock. Tests move it explicitly."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


HOUR = 3600.0


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_pod_running_an_hour_fast_does_not_keep_its_trust_score(with_db: bool) -> None:
    """FAIL-ON-BUG: trust and last decision come from whichever copy was active last, by pod wall
    clock. A pod an hour fast stamped its score an hour ahead, and for that hour it beat every newer
    score the other replica recorded."""
    clock = _TrueClock()
    (a, store_a), (b, store_b), db = _replicas(with_db, clock, skews=(HOUR, 0))
    _call(a, "get_customer", trust=0.52)
    await store_a.save(NS, a)
    clock.advance(1)
    _call(b, "get_customer", trust=0.455)
    await store_b.save(NS, b)
    clock.advance(1)
    await store_a.save(NS, a)

    agent = next(n for n in (await _persisted(store_a, db))["nodes"] if n["id"] == AGENT)
    assert agent["properties"]["trust_score"] == 0.455


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_removal_on_a_fast_pod_does_not_swallow_later_calls(with_db: bool) -> None:
    """FAIL-ON-BUG: a removal is stamped, and covers every call made before it. Stamped an hour ahead,
    it also covered every call for the next hour, so a tool called again a minute after its removal
    stayed off the graph."""
    clock = _TrueClock()
    (a, store_a), (b, store_b), db = _replicas(with_db, clock, skews=(HOUR, 0))
    _call(b, "read_env")
    await store_b.save(NS, b)
    clock.advance(1)
    assert await remove_graph_node(_request(a, store_a), NS, "tool:read_env") is True
    clock.advance(60)
    _call(b, "read_env")
    await store_b.save(NS, b)

    assert _tools(await _persisted(store_b, db)).get("tool:read_env") == 1


@pytest.mark.parametrize("with_db", [False, True], ids=["redis-only", "postgres"])
async def test_a_removal_on_a_slow_pod_covers_the_calls_made_before_it(with_db: bool) -> None:
    """FAIL-ON-BUG, the other direction: a pod an hour slow stamped its removal an hour in the past, so
    a call the other replica made before the removal (and had not saved yet) read as newer than it and
    brought the node back."""
    clock = _TrueClock()
    (a, store_a), (b, store_b), db = _replicas(with_db, clock, skews=(-HOUR, 0))
    _call(b, "export_records")
    await store_b.save(NS, b)
    clock.advance(30)
    _call(b, "export_records")  # before the removal, saved after it
    clock.advance(30)
    assert await remove_graph_node(_request(a, store_a), NS, "tool:export_records") is True
    clock.advance(1)
    await store_b.save(NS, b)

    assert "tool:export_records" not in _tools(await _persisted(store_b, db))


async def test_a_stamp_from_the_future_is_bounded_to_the_present() -> None:
    """A row written by a pod that never measured the shared clock (a fast pod's first write, or the
    previous release) can carry stamps far ahead. Unbounded, a 2099 trust score and a 2099 removal won
    every comparison until 2099. Now they are pulled back to the present at the next merge, so the
    next real call wins."""
    clock = _TrueClock()
    (_, _), (b, store_b), db = _replicas(True, clock)
    assert db is not None
    future = "2099-01-01T00:00:00.000000+00:00"
    db.rows.append(AssetGraph(
        namespace=NS, node_count=1, edge_count=0, built_at=clock() - timedelta(seconds=1),
        graph_json={"nodes": [{"id": AGENT, "type": "agent", "label": "analyst", "namespace": NS,
                               "last_seen_at": future,
                               "properties": {"agent_class": "analyst", "agent_classes": ["analyst"],
                                              "trust_score": 0.9, "trust_category": "high"}}],
                    "edges": [], "tombstones": {"tool:get_order": future}}))
    await store_b.save(NS, b)  # the first merge on the shared clock bounds both stamps
    clock.advance(1)
    _call(b, "get_order", trust=0.4)
    await store_b.save(NS, b)

    persisted = db.latest(NS).graph_json
    agent = next(n for n in persisted["nodes"] if n["id"] == AGENT)
    assert agent["properties"]["trust_score"] == 0.4
    assert _tools(persisted).get("tool:get_order") == 1


async def test_a_previous_release_row_does_not_erase_a_removal_for_the_other_replica() -> None:
    """FAIL-ON-BUG: a row written by a previous-release pod has no ``tombstones`` key, and it was merged
    as "nothing removed". Only the replica that made the removal still held the tombstone; the other
    one merged the old pod's copy of the node and saved it back for good."""
    (a, store_a), (b, store_b), db = _replicas(True)
    assert db is not None
    _call(b, "delete_record")
    _call(b, "get_customer")
    await store_b.save(NS, b)
    stale = json.loads(json.dumps(db.latest(NS).graph_json))
    assert await remove_graph_node(_request(a, store_a), NS, "tool:delete_record") is True
    stale.pop("tombstones", None)
    for element in stale["nodes"] + stale["edges"]:
        element.pop("last_seen_at", None)  # the previous release stamps nothing
    db.rows.append(AssetGraph(namespace=NS, node_count=0, edge_count=0, graph_json=stale,
                              built_at=datetime.now(timezone.utc) + timedelta(seconds=1)))

    _call(b, "search_kb")
    await store_b.save(NS, b)  # b, not a: b never held the tombstone

    persisted = db.latest(NS).graph_json
    assert "tool:delete_record" not in _tools(persisted)
    assert "tool:delete_record" in persisted["tombstones"]
    assert "tool:delete_record" not in b.graph


def test_every_snapshot_records_its_tombstones_even_when_there_are_none() -> None:
    """The key's absence is what marks a previous-release row, so this release always writes it."""
    graph = AssetGraphBuilder()
    _call(graph, "get_customer")
    assert graph.to_dict()["tombstones"] == {}


def _events(logs: list[dict], event: str) -> list[dict]:
    return [entry for entry in logs if entry.get("event") == event]


async def test_a_save_that_cannot_read_the_shared_clock_says_so() -> None:
    """FAIL-ON-BUG: a Redis TIME failure was swallowed with a bare `return`. The save went on with the
    builder's own wall clock and no skew bound, and nothing said so. It is logged now, and the log
    says whether the builder has ever had the shared clock (False: its stamps are not bounded)."""
    (a, store_a), _, _ = _replicas(False)
    pool = store_a._cache._pool
    pool.fail_time = True
    _call(a, "get_customer")
    with capture_logs() as logs:
        await store_a.save(NS, a)
    assert _tools(await _persisted(store_a, None)) == {"tool:get_customer": 1}, "the save must still happen"
    [failed] = _events(logs, "nrvq.graph.clock_sync_failed")
    assert failed["code"] == "NRVQ-GRP-11024" and failed["log_level"] == "warning"
    assert failed["source"] == "redis" and failed["reference_clock"] is False

    pool.fail_time = False
    _call(a, "get_customer")
    await store_a.save(NS, a)
    pool.fail_time = True
    _call(a, "get_customer")
    with capture_logs() as logs:
        await store_a.save(NS, a)
    [failed] = _events(logs, "nrvq.graph.clock_sync_failed")
    assert failed["reference_clock"] is True, "after one good read the builder keeps that offset"


async def test_a_database_clock_that_is_not_a_time_is_reported() -> None:
    """The Postgres clock read had the same silent shape: a non-datetime answer left the builder on
    its own clock without a word."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    db.clock = lambda: None
    _call(a, "get_customer")
    with capture_logs() as logs:
        await store_a.save(NS, a)
    assert _tools(db.latest(NS).graph_json) == {"tool:get_customer": 1}
    [failed] = _events(logs, "nrvq.graph.clock_sync_failed")
    assert failed["source"] == "postgres" and failed["reference_clock"] is False


async def test_a_stale_cached_copy_that_cannot_be_deleted_is_reported() -> None:
    """FAIL-ON-BUG: when the committed row could not be cached, the stale key is deleted so readers
    go to Postgres. If that delete failed too, the error was dropped with `pass`, and readers were
    served the older copy for up to 300 s with nothing in the log that said so."""
    (a, store_a), _, db = _replicas(True)
    assert db is not None
    _call(a, "get_customer")
    await store_a.save(NS, a)
    pool = store_a._cache._pool
    pool.fail_sets = True
    pool.fail_deletes = True
    _call(a, "get_customer")
    with capture_logs() as logs:
        await store_a.save(NS, a)  # the row committed; the save stands
    assert _tools(db.latest(NS).graph_json)["tool:get_customer"] == 2
    assert f"graph:{NS}" in pool.values, "premise: the older cached copy is still there"
    [publish] = _events(logs, "nrvq.graph.cache_publish_failed")
    [stale] = _events(logs, "nrvq.graph.cache_invalidate_failed")
    assert publish["code"] == "NRVQ-GRP-11019"
    assert stale["code"] == "NRVQ-GRP-11025" and stale["log_level"] == "warning"
    assert stale["stale_for_s"] == 300
