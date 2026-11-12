# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Persistence helpers for graph snapshots in cache and PostgreSQL."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import weakref
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import select, text

from norviq.api.db.models import AssetGraph
from norviq.engine.graph.asset_graph import AssetGraphBuilder, knows_tombstones


def compute_graph_version(graph: AssetGraphBuilder) -> str:
    """Short content hash of the graph structure — the cache-version key for analysis results."""
    return hashlib.sha256(json.dumps(graph.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()[:16]

log = structlog.get_logger()


# Advisory-lock class for "one writer per namespace snapshot". Two-key form, so it can never collide
# with the single-key schema-init lock in api/db/session.py; the second key is hashtext(namespace).
_SNAPSHOT_LOCK_CLASS = 0x4E52_0002  # "NR" + slot 2

_CACHE_TTL_S = 300
# The Redis lock around a cache read-merge-write. A save holds it for one merge (milliseconds); the TTL
# only matters when a pod dies holding it. A holder that overran the TTL can still write once after
# another took the lock, which loses that one merge's increments from the cache, never from Postgres.
_LOCK_TTL_MS = 10_000
_LOCK_WAIT_S = 5.0
_RELEASE_LUA = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end"
# Marks a cached payload that holds calls a replica could not write to Postgres (see _cache_while_db_down).
_UNSAVED_KEY = "unsaved_writers"
_UNSAVED_CAP = 64


class GraphStoreBusy(RuntimeError):
    """The namespace's Redis lock was not free within the wait. Nothing was written; the builder keeps
    its unsaved calls for the next save."""


class GraphStore:
    """Persist and load graph snapshots from Redis and JSONB tables.

    The chart runs several API replicas and each keeps its own live builder per namespace. Every write
    therefore reads the latest snapshot, merges it into the caller's builder
    (`AssetGraphBuilder.merge_persisted`) and writes the union, all under one lock per namespace: an
    asyncio lock for tasks in this process and a Postgres transaction advisory lock across processes.
    Before, each replica saved its whole graph and the newest row won, so whatever the other replicas
    had recorded since their last write disappeared from every graph surface.

    Without Postgres the cached copy is the only one, and the cross-process lock is a Redis lock
    (`_redis_lock`). With Postgres the cache is written only after the row commits, and only while that
    row is still the newest; when the database write fails, a save still merges its calls into the
    cached copy, so readers of the cache (`load`) keep seeing them (`_cache_while_db_down`).
    """

    def __init__(self, cache, session_factory=None) -> None:
        """Store dependencies for cache-first graph persistence."""
        self._cache = cache
        self._session_factory = session_factory
        self._locks: dict[str, asyncio.Lock] = {}
        # (namespace, id(builder)) -> the token of the save waiting for the lock with that builder.
        self._queued: dict[tuple[str, int], object] = {}
        # builder -> namespace -> (writer token, baseline) of its last cache-only write. See
        # _cache_while_db_down; cleared when the builder next commits.
        self._outage: weakref.WeakKeyDictionary[AssetGraphBuilder, dict[str, tuple[str, dict]]] = (
            weakref.WeakKeyDictionary())

    async def save(self, namespace: str, graph: AssetGraphBuilder) -> None:
        """Merge ``graph`` with the persisted snapshot and save the result (``graph`` becomes it too).

        The evaluator calls this once per tool call. Saves of one namespace are serialized now, so a
        save that finds another save of the same builder still WAITING for the lock returns at once:
        that one has not read the builder yet, so it will carry this call too. At most one save runs
        and one waits, instead of a backlog that grows with the call rate.
        """
        key = (namespace, id(graph))
        if key in self._queued:
            return
        token = object()
        self._queued[key] = token
        try:
            await self._write(namespace, graph, None, queued=(key, token))
        finally:
            # Only this save's own marker. By now it is usually the NEXT save's, set while this one ran;
            # clearing that let every later call queue another save, and the backlog grew without bound.
            self._unqueue(key, token)

    def _unqueue(self, key: tuple[str, int], token: object) -> None:
        if self._queued.get(key) is token:
            del self._queued[key]

    async def remove_node(self, namespace: str, graph: AssetGraphBuilder, node_id: str) -> bool:
        """Remove ``node_id`` from the namespace's persisted graph and record a tombstone for it.

        Decided against the merged graph, not this process's builder alone: a node another replica
        recorded is on the console, so it has to be removable here. Returns False, writing nothing,
        when the node is in neither.
        """
        return await self._write(namespace, graph, node_id)

    async def _write(self, namespace: str, graph: AssetGraphBuilder, remove: str | None,
                     queued: tuple[tuple[str, int], object] | None = None) -> bool:
        """Load -> merge -> (remove) -> write, serialized per namespace."""
        lock = self._locks.setdefault(namespace, asyncio.Lock())
        async with lock:
            if queued is not None:
                self._unqueue(*queued)  # from here on this save reads the builder: later calls queue anew
            if self._session_factory is None:
                # The asyncio lock only orders this process's saves. Two replicas sharing one Redis each
                # read the cached copy, merged and wrote it back, and the second write erased the
                # first's calls.
                async with self._redis_lock(namespace):
                    await self._sync_clock_from_redis(graph)
                    graph.merge_persisted(await self._load_cache_payload(namespace))
                    undo = graph.removal_undo(remove) if remove is not None else None
                    if remove is not None and not graph.remove_node(remove):
                        return False
                    payload = graph.to_dict()
                    try:
                        await self._save_cache(namespace, payload)
                    except BaseException:
                        if undo is not None:
                            undo()
                        raise
                graph.mark_persisted(payload)
            else:
                try:
                    payload = await self._write_db(namespace, graph, remove)
                except Exception as exc:
                    # A removal that did not commit is not shown anywhere: the DELETE fails instead.
                    if remove is None:
                        await self._cache_while_db_down(namespace, graph, exc)
                    raise
                if payload is None:
                    return False
        await self._invalidate_analysis(namespace)
        log.info("nrvq.graph.saved", namespace=namespace, code="NRVQ-GRP-11015")
        return True

    async def _invalidate_analysis(self, namespace: str) -> None:
        """The graph changed -> invalidate any cached analysis results for this namespace."""
        invalidate = getattr(self._cache, "delete_analysis_scope", None)
        if invalidate is not None:
            await invalidate(namespace)

    @asynccontextmanager
    async def _redis_lock(self, namespace: str):
        """Hold ``lock:graph:<namespace>`` across replicas: SET NX PX with a random token, released by
        compare-and-delete so a holder whose TTL lapsed never frees a lock someone else now holds.
        Raises GraphStoreBusy when the lock stays taken for _LOCK_WAIT_S."""
        pool = self._cache._pool
        key = f"lock:graph:{namespace}"
        token = secrets.token_hex(16)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _LOCK_WAIT_S
        delay = 0.002
        while not await pool.set(key, token, nx=True, px=_LOCK_TTL_MS):
            if loop.time() >= deadline:
                log.warning("nrvq.graph.lock_busy", namespace=namespace, waited_s=_LOCK_WAIT_S,
                            code="NRVQ-GRP-11020")
                raise GraphStoreBusy(f"graph lock for namespace {namespace!r} not free after {_LOCK_WAIT_S}s")
            await asyncio.sleep(delay)
            delay = min(delay * 2, 0.05)
        try:
            yield
        finally:
            try:
                await pool.eval(_RELEASE_LUA, 1, key, token)
            except Exception as exc:  # noqa: BLE001 - the TTL frees it; the write itself already happened
                log.warning("nrvq.graph.lock_release_failed", namespace=namespace, error=str(exc),
                            code="NRVQ-GRP-11023")

    async def _sync_clock_from_redis(self, graph: AssetGraphBuilder) -> None:
        """Without a database, Redis TIME is the clock every replica shares (see AssetGraphBuilder.now)."""
        try:
            sent = graph.wall_now()
            seconds, micros = await self._cache._pool.time()
            received = graph.wall_now()
        except Exception as exc:  # noqa: BLE001 - the save goes on; it does not depend on the clock
            # Not silent: a builder that never reads the shared clock stamps with its own wall clock
            # and its stamps are not bounded, so the skew protection is off until TIME works.
            log.warning("nrvq.graph.clock_sync_failed", source="redis", error=type(exc).__name__,
                        reference_clock=graph.has_reference_clock, code="NRVQ-GRP-11024")
            return
        reference = datetime.fromtimestamp(int(seconds), tz=timezone.utc) + timedelta(microseconds=int(micros))
        graph.set_reference_clock(reference, sent + (received - sent) / 2)

    async def _save_cache(self, namespace: str, payload: dict[str, object]) -> None:
        """Write serialized graph to cache with five-minute TTL."""
        await self._cache._pool.set(f"graph:{namespace}", json.dumps(payload), ex=_CACHE_TTL_S)

    async def _load_cache_payload(self, namespace: str) -> dict[str, object] | None:
        """The cached snapshot as a dict, or None."""
        raw = await self._cache._pool.get(f"graph:{namespace}")
        return json.loads(raw) if raw else None

    async def _write_db(self, namespace: str, graph: AssetGraphBuilder,
                        remove: str | None) -> dict[str, object] | None:
        """Under a per-namespace advisory lock: read the latest snapshot row, merge, insert the union.

        Returns the saved payload, or None when ``remove`` was not present. Once the row has committed
        this does not raise: the builder is marked persisted and the cache is published best-effort.
        Raising there made the caller treat a committed save as failed, and the builder's next save
        counted the same calls a second time.
        """
        session, agen = await self._acquire_session()
        committed = False
        try:
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:cls, hashtext(:ns))"),
                {"cls": _SNAPSHOT_LOCK_CLASS, "ns": namespace},
            )
            await self._sync_clock_from_db(session, graph)
            row = await session.scalar(
                select(AssetGraph).where(AssetGraph.namespace == namespace).order_by(AssetGraph.built_at.desc()).limit(1)
            )
            stored = dict(row.graph_json) if row is not None and row.graph_json else None
            if stored is not None and not knows_tombstones(stored):
                stored["tombstones"] = await self._last_known_tombstones(session, namespace)
            graph.merge_persisted(stored)
            undo = graph.removal_undo(remove) if remove is not None else None
            if remove is not None and not graph.remove_node(remove):
                await session.rollback()
                return None
            payload = graph.to_dict()
            # Every reader takes the row with the newest built_at, so the union must sort after the row
            # it was merged from even when this pod's clock is behind the pod that wrote that row.
            built_at = graph.now()
            if row is not None and row.built_at is not None and row.built_at >= built_at:
                built_at = row.built_at + timedelta(microseconds=1)
            session.add(
                AssetGraph(
                    namespace=namespace,
                    built_at=built_at,
                    node_count=len(payload.get("nodes", [])),  # type: ignore[arg-type]
                    edge_count=len(payload.get("edges", [])),  # type: ignore[arg-type]
                    graph_json=payload,
                )
            )
            # The cache is written after the commit, never before: a cache written first served a
            # payload whose commit then failed (a removal that never happened, for five minutes).
            try:
                await session.commit()
            except BaseException:
                if undo is not None:
                    undo()  # the removal did not happen; the builder must not carry it out later
                raise
            committed = True
            graph.mark_persisted(payload)
            self._forget_outage(graph, namespace)
            await self._publish_committed(session, namespace, payload, built_at)
            return payload
        finally:
            try:
                if agen is not None:
                    await agen.aclose()
                else:
                    await session.close()
            except Exception as exc:
                if not committed:
                    raise
                log.warning("nrvq.graph.session_close_failed", namespace=namespace, error=str(exc),
                            code="NRVQ-GRP-11022")

    async def _sync_clock_from_db(self, session, graph: AssetGraphBuilder) -> None:
        """Read the database clock, which every replica shares (see AssetGraphBuilder.now)."""
        sent = graph.wall_now()
        reference = await session.scalar(text("SELECT clock_timestamp()"))
        received = graph.wall_now()
        if not isinstance(reference, datetime):
            log.warning("nrvq.graph.clock_sync_failed", source="postgres", error=type(reference).__name__,
                        reference_clock=graph.has_reference_clock, code="NRVQ-GRP-11024")
            return
        graph.set_reference_clock(reference, sent + (received - sent) / 2)

    async def _last_known_tombstones(self, session, namespace: str) -> dict:
        """The tombstones of the newest row that records them.

        The newest row lacks the key when a pod on the previous release wrote it during a rolling
        upgrade. Merging it as "no removals" let the next upgraded writer re-save, for good, every node
        that had been removed, unless that writer happened to be the replica that made the removal.
        """
        snapshot = await session.scalar(
            select(AssetGraph.graph_json)
            .where(AssetGraph.namespace == namespace, AssetGraph.graph_json.has_key("tombstones"))
            .order_by(AssetGraph.built_at.desc()).limit(1)
        )
        value = snapshot.get("tombstones") if isinstance(snapshot, dict) else None
        return dict(value) if isinstance(value, dict) else {}

    async def _publish_committed(self, session, namespace: str, payload: dict[str, object],
                                 built_at: datetime) -> None:
        """Write the committed payload to the cache while it is still the newest row.

        After the commit the advisory lock is gone, so a writer that committed later may already have
        cached its own row; overwriting that with this older one would serve stale data for the TTL.
        The newest-row check and the write happen under the namespace's Redis lock, which every cache
        writer takes. If the cache cannot be written, the key is deleted so readers go to Postgres.
        """
        try:
            async with self._redis_lock(namespace):
                latest = await session.scalar(
                    select(AssetGraph.built_at).where(AssetGraph.namespace == namespace)
                    .order_by(AssetGraph.built_at.desc()).limit(1)
                )
                if latest is not None and latest != built_at:
                    return
                await self._save_cache(namespace, payload)
        except Exception as exc:  # noqa: BLE001 - the row is committed; the cache is a copy of it
            log.warning("nrvq.graph.cache_publish_failed", namespace=namespace, error=str(exc),
                        code="NRVQ-GRP-11019")
            try:
                await self._cache._pool.delete(f"graph:{namespace}")
            except Exception as exc2:  # noqa: BLE001 - Redis is down; its copy expires with the TTL
                # The older cached copy stays and `load` serves it until the TTL ends.
                log.warning("nrvq.graph.cache_invalidate_failed", namespace=namespace,
                            error=str(exc2), stale_for_s=_CACHE_TTL_S, code="NRVQ-GRP-11025")

    def _forget_outage(self, graph: AssetGraphBuilder, namespace: str) -> None:
        entries = self._outage.get(graph)
        if entries is not None:
            entries.pop(namespace, None)

    async def _cache_while_db_down(self, namespace: str, graph: AssetGraphBuilder, error: Exception) -> None:
        """The database write failed: merge this builder's calls into the CACHED copy.

        The cache used to be written before the database, so it kept updating while Postgres was down.
        Written only after a commit, readers of the cache (`load`: the /api/v1/graph analysis routes,
        a restarting replica's restore) would see nothing new for the whole outage. Writing this
        builder's graph over the cache would drop what other replicas committed or cached, so it is merged in,
        under the Redis lock, without touching the builder: its baseline must keep describing what
        Postgres holds, or its next real save counts the wrong share as saved.

        The payload lists this writer in ``unsaved_writers``. While the cached copy still lists it, it
        already holds this builder's earlier cache-only calls and the next merge is measured from them;
        once a committed payload has replaced it, the merge is measured from the database baseline again.
        """
        log.warning("nrvq.graph.db_write_failed", namespace=namespace, error=str(error),
                    code="NRVQ-GRP-11018")
        try:
            async with self._redis_lock(namespace):
                cached = await self._load_cache_payload(namespace)
                writers = [w for w in ((cached or {}).get(_UNSAVED_KEY) or []) if isinstance(w, str)]
                entries = self._outage.setdefault(graph, {})
                token, base = entries.get(namespace, (secrets.token_hex(8), {}))
                payload, own = graph.merged_copy(cached, base if token in writers else None)
                if token not in writers:
                    writers.append(token)
                payload[_UNSAVED_KEY] = writers[-_UNSAVED_CAP:]
                await self._save_cache(namespace, payload)
                entries[namespace] = (token, own)
        except Exception as exc:  # noqa: BLE001 - Redis is down too; the builder still holds the calls
            log.warning("nrvq.graph.cache_fallback_failed", namespace=namespace, error=str(exc),
                        code="NRVQ-GRP-11021")
            return
        await self._invalidate_analysis(namespace)

    async def load(self, namespace: str) -> AssetGraphBuilder | None:
        """Load graph from Redis and fallback to latest DB snapshot."""
        cached = await self._load_cache(namespace)
        if cached is not None:
            return cached
        if self._session_factory is None:
            log.debug("nrvq.graph.cache_miss", namespace=namespace, code="NRVQ-GRP-11016")
            return None
        loaded = await self._load_db(namespace)
        if loaded is None:
            log.debug("nrvq.graph.cache_miss", namespace=namespace, code="NRVQ-GRP-11016")
        return loaded

    async def _load_cache(self, namespace: str) -> AssetGraphBuilder | None:
        """Load graph snapshot from cache key."""
        raw = await self._cache._pool.get(f"graph:{namespace}")
        if not raw:
            return None
        graph = AssetGraphBuilder()
        graph.from_dict(json.loads(raw))
        return graph

    async def _load_db(self, namespace: str) -> AssetGraphBuilder | None:
        """Load latest graph snapshot for namespace from PostgreSQL."""
        session, agen = await self._acquire_session()
        try:
            row = await session.scalar(
                select(AssetGraph).where(AssetGraph.namespace == namespace).order_by(AssetGraph.built_at.desc()).limit(1)
            )
        finally:
            if agen is not None:
                await agen.aclose()
            else:
                await session.close()
        if row is None or not row.graph_json:
            return None
        graph = AssetGraphBuilder()
        graph.from_dict(dict(row.graph_json))
        return graph

    async def _acquire_session(self):
        """Acquire session from async generator dependency or awaitable factory."""
        provider_result = self._session_factory()
        if hasattr(provider_result, "__anext__"):
            agen = provider_result
            session = await agen.__anext__()
            return session, agen
        session = await provider_result
        return session, None
