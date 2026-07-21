# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for the per-pod in-process TTL cache (norviq.engine.inproc_cache)."""

from __future__ import annotations

import pytest

from norviq.engine import inproc_cache
from norviq.engine.inproc_cache import _MISS, TTLCache


def test_disabled_when_ttl_zero_is_pure_passthrough() -> None:
    c = TTLCache(ttl_s=0.0)
    assert c.enabled is False
    c.set("k", "v")
    assert c.get("k") is _MISS      # set is a no-op, get always misses
    assert len(c) == 0


def test_disabled_when_ttl_negative() -> None:
    c = TTLCache(ttl_s=-1.0)
    assert c.enabled is False
    c.set("k", "v")
    assert c.get("k") is _MISS


def test_hit_returns_value_within_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(inproc_cache.time, "monotonic", lambda: now[0])
    c = TTLCache(ttl_s=5.0)
    c.set("k", {"a": 1})
    now[0] = 1004.9                 # still inside the 5s window
    assert c.get("k") == {"a": 1}


def test_expiry_is_a_miss_and_evicts(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(inproc_cache.time, "monotonic", lambda: now[0])
    c = TTLCache(ttl_s=5.0)
    c.set("k", "v")
    now[0] = 1005.0                 # exactly at expiry -> expired (>=)
    assert c.get("k") is _MISS
    assert len(c) == 0             # lazily swept on the miss


def test_falsy_values_are_not_mistaken_for_a_miss() -> None:
    c = TTLCache(ttl_s=5.0)
    c.set("empty_history", [])
    c.set("none_cap", None)
    assert c.get("empty_history") == []       # not _MISS
    assert c.get("none_cap") is None          # a cached None, distinct from _MISS
    assert c.get("empty_history") is not _MISS


def test_max_entries_fifo_eviction() -> None:
    c = TTLCache(ttl_s=100.0, max_entries=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)                  # evicts the oldest ("a")
    assert c.get("a") is _MISS
    assert c.get("b") == 2
    assert c.get("c") == 3
    assert len(c) == 2


def test_reinsert_refreshes_expiry_and_recency(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(inproc_cache.time, "monotonic", lambda: now[0])
    c = TTLCache(ttl_s=5.0)
    c.set("k", "v1")
    now[0] = 1003.0
    c.set("k", "v2")               # refresh: new value + new 5s expiry from 1003
    now[0] = 1007.0                # 7s after first set, but only 4s after refresh
    assert c.get("k") == "v2"


def test_invalidate_and_clear() -> None:
    c = TTLCache(ttl_s=100.0)
    c.set("a", 1)
    c.set("b", 2)
    c.invalidate("a")
    assert c.get("a") is _MISS
    assert c.get("b") == 2
    c.invalidate("missing")        # absent key is a no-op, never raises
    c.clear()
    assert c.get("b") is _MISS
    assert len(c) == 0
