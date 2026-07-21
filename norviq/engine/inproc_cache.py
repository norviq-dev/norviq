# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Per-pod in-process L1 cache with a monotonic TTL.

The hot path (`OPAEvaluator.evaluate`) makes several sequential cross-pod Redis round trips before it
can decide — posture, the stored trust score, the trust-input reads (history/profile), and the eval
cache. Each round trip is cheap at p50 but carries a fat cross-pod tail (~50ms) that, multiplied over
3-4 hops, dominates the p99. This cache sits in front of the *behavioral-input* reads (things that are
invariant for a few seconds and safe to serve slightly stale) so a warm caller answers from local
memory instead of the network.

It is deliberately NOT used for the kill-switch reads (admin freeze / trust cap): those stay fresh on
every call so an incident-response freeze propagates cluster-wide immediately, not after a TTL. See
`TrustCalculator.calculate`.

Design notes:
- Monotonic clock (`time.monotonic`) so a wall-clock jump never resurrects or prematurely expires an
  entry.
- Single-threaded-async safe: the engine runs one event loop per pod and there is no `await` between
  the read and the write inside `get`/`set`, so no lock is needed (dict ops are atomic under the GIL).
- Bounded: `max_entries` caps per-pod memory; insertion-order eviction (FIFO) keeps it O(1) and
  dependency-free. A `_MISS` sentinel distinguishes "absent" from a legitimately cached ``None``.
- TTL <= 0 disables the cache entirely (`get` always misses, `set` is a no-op) so an operator can
  turn the optimization off with a single setting and get byte-identical fresh-read behavior.
"""

from __future__ import annotations

from collections import OrderedDict
import time
from typing import Any, Hashable

_MISS = object()


class TTLCache:
    """A tiny per-pod TTL cache. Not shared across pods — staleness is bounded by ``ttl_s``."""

    __slots__ = ("_ttl", "_max", "_data")

    def __init__(self, ttl_s: float, max_entries: int = 8192) -> None:
        """Bind the TTL (seconds) and the hard entry cap. ``ttl_s <= 0`` disables the cache."""
        self._ttl = float(ttl_s)
        self._max = max(1, int(max_entries))
        # key -> (expires_at_monotonic, value); insertion-ordered for O(1) FIFO eviction.
        self._data: "OrderedDict[Hashable, tuple[float, Any]]" = OrderedDict()

    @property
    def enabled(self) -> bool:
        """True when this cache actually stores/serves entries (TTL > 0)."""
        return self._ttl > 0

    def get(self, key: Hashable) -> Any:
        """Return the cached value, or the ``_MISS`` sentinel when absent/expired/disabled.

        Callers MUST compare against ``inproc_cache._MISS`` (``is _MISS``), not truthiness, so a
        cached falsy value (empty history list, ``None`` trust cap) is not mistaken for a miss.
        """
        if self._ttl <= 0:
            return _MISS
        entry = self._data.get(key)
        if entry is None:
            return _MISS
        expires_at, value = entry
        if time.monotonic() >= expires_at:
            # Lazily drop the expired entry; a background sweep is unnecessary at this scale.
            self._data.pop(key, None)
            return _MISS
        return value

    def set(self, key: Hashable, value: Any) -> None:
        """Store ``value`` under ``key`` with a fresh TTL. No-op when the cache is disabled."""
        if self._ttl <= 0:
            return
        # Refresh recency/expiry: drop any prior entry so re-insertion moves it to the tail.
        if key in self._data:
            self._data.pop(key, None)
        self._data[key] = (time.monotonic() + self._ttl, value)
        # FIFO-evict the oldest entries past the cap (bounds per-pod memory under key churn).
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def invalidate(self, key: Hashable) -> None:
        """Drop one entry (best-effort; absent keys are ignored)."""
        self._data.pop(key, None)

    def clear(self) -> None:
        """Drop every entry (e.g. on a policy/posture invalidation broadcast)."""
        self._data.clear()

    def __len__(self) -> int:
        """Current entry count (includes not-yet-swept expired entries)."""
        return len(self._data)
