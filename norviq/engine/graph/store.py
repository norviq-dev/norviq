# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Persistence helpers for graph snapshots in cache and PostgreSQL."""

from __future__ import annotations

import hashlib
import json

import structlog
from sqlalchemy import select

from norviq.api.db.models import AssetGraph
from norviq.engine.graph.asset_graph import AssetGraphBuilder


def compute_graph_version(graph: AssetGraphBuilder) -> str:
    """Short content hash of the graph structure — the cache-version key for analysis results."""
    return hashlib.sha256(json.dumps(graph.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()[:16]

log = structlog.get_logger()


class GraphStore:
    """Persist and load graph snapshots from Redis and JSONB tables."""

    def __init__(self, cache, session_factory=None) -> None:
        """Store dependencies for cache-first graph persistence."""
        self._cache = cache
        self._session_factory = session_factory

    async def save(self, namespace: str, graph: AssetGraphBuilder) -> None:
        """Save graph to Redis and optional PostgreSQL JSONB table."""
        payload = graph.to_dict()
        await self._save_cache(namespace, payload)
        if self._session_factory is not None:
            await self._save_db(namespace, payload)
        # The graph changed -> invalidate any cached analysis results for this namespace.
        invalidate = getattr(self._cache, "delete_analysis_scope", None)
        if invalidate is not None:
            await invalidate(namespace)
        log.info("nrvq.graph.saved", namespace=namespace, code="NRVQ-GRP-11015")

    async def _save_cache(self, namespace: str, payload: dict[str, object]) -> None:
        """Write serialized graph to cache with five-minute TTL."""
        await self._cache._pool.set(f"graph:{namespace}", json.dumps(payload), ex=300)

    async def _save_db(self, namespace: str, payload: dict[str, object]) -> None:
        """Insert graph snapshot row in PostgreSQL JSONB table."""
        session, agen = await self._acquire_session()
        try:
            row = AssetGraph(
                namespace=namespace,
                node_count=len(payload.get("nodes", [])),  # type: ignore[arg-type]
                edge_count=len(payload.get("edges", [])),  # type: ignore[arg-type]
                graph_json=payload,
            )
            session.add(row)
            await session.commit()
        finally:
            if agen is not None:
                await agen.aclose()
            else:
                await session.close()

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
