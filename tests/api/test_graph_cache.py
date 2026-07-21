# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Graph analysis results are cached per (namespace, graph-version) — a repeated call computes once and
is served from cache, and the cache invalidates when the graph snapshot changes."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from norviq.api.routers.graph import _cached_analysis
from norviq.engine.graph.store import compute_graph_version


class _FakeGraph:
    def __init__(self, data: dict) -> None:
        self._data = data
        self.graph = "G"

    def to_dict(self) -> dict:
        return self._data


class _FakeCache:
    def __init__(self) -> None:
        self.store: dict = {}

    async def get_analysis(self, ns, ver, atype, params=""):
        return self.store.get((ns, ver, atype, params))

    async def set_analysis(self, ns, ver, atype, result, params="", ttl=600):
        self.store[(ns, ver, atype, params)] = result

    async def delete_analysis_scope(self, ns):
        keys = [k for k in self.store if k[0] == ns]
        for k in keys:
            del self.store[k]
        return len(keys)


def _request(graph: _FakeGraph, cache: _FakeCache) -> SimpleNamespace:
    async def _load(_ns):
        return graph

    state = SimpleNamespace(cache=cache, graph_store=SimpleNamespace(load=_load))
    return SimpleNamespace(app=SimpleNamespace(state=state))


def test_cached_analysis_computes_once_then_serves_from_cache() -> None:
    cache = _FakeCache()
    req = _request(_FakeGraph({"nodes": [1], "edges": []}), cache)
    calls = {"n": 0}

    def compute(_g):
        calls["n"] += 1
        return {"result": 42}

    async def run():
        r1 = await _cached_analysis(req, "default", "summary", "", compute)
        r2 = await _cached_analysis(req, "default", "summary", "", compute)
        return r1, r2

    r1, r2 = asyncio.run(run())
    assert r1 == r2 == {"result": 42}
    assert calls["n"] == 1  # second call served from cache


def test_version_changes_invalidate() -> None:
    g1 = _FakeGraph({"nodes": [1], "edges": []})
    g2 = _FakeGraph({"nodes": [1, 2], "edges": []})
    assert compute_graph_version(g1) != compute_graph_version(g2)
    assert compute_graph_version(g1) == compute_graph_version(_FakeGraph({"nodes": [1], "edges": []}))


def test_no_cache_falls_back_to_compute() -> None:
    req = _request(_FakeGraph({"nodes": [], "edges": []}), None)  # type: ignore[arg-type]
    req.app.state.cache = None
    out = asyncio.run(_cached_analysis(req, "default", "summary", "", lambda _g: {"ok": True}))
    assert out == {"ok": True}
