# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for graph store cache persistence."""

from __future__ import annotations

import json

from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.store import GraphStore


class _FakePool:
    """Tiny async key/value store."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, ex: int | None = None, px: int | None = None,
                  nx: bool = False) -> bool | None:
        """Set cache value with ignored TTL (NX honoured: the store takes a lock with it)."""
        _ = ex, px
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True

    async def eval(self, script: str, numkeys: int, key: str, token: str) -> int:
        """The store's compare-and-delete lock release."""
        _ = script, numkeys
        if self.values.get(key) == token:
            del self.values[key]
            return 1
        return 0

    async def get(self, key: str) -> str | None:
        """Get cache value."""
        return self.values.get(key)


class _FakeCache:
    """Cache wrapper exposing Redis-compatible _pool."""

    def __init__(self) -> None:
        self._pool = _FakePool()


async def test_save_and_load_cache() -> None:
    """Round-trip graph via cache-backed graph store."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://agent", "search_kb", "allow")
    store = GraphStore(_FakeCache())
    await store.save("default", graph)
    loaded = await store.load("default")
    assert loaded is not None
    assert loaded.get_node_count()["agents"] == 1
    raw = await store._cache._pool.get("graph:default")
    assert raw is not None
    assert "nodes" in json.loads(raw)
