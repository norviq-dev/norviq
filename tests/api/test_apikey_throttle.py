# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The api-key auth resolver must actually THROTTLE repeated failures, not merely log them.

The docstring/comment in api_keys.py claims an online guessing campaign is "rate-limited + visible",
but a resolver that only counts+logs still runs the DB lookup on every attempt with no short-circuit.
These tests are FAIL-ON-BUG: a count-only resolver runs the DB lookup on all N attempts (counter == N);
a throttling resolver stops at _AUTHFAIL_THRESHOLD.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from norviq.api import api_keys as ak


class _CountingSession:
    """Records how many times the resolver reaches the DB lookup; always misses (auth fail)."""

    def __init__(self, counter: list[int]) -> None:
        self.counter = counter

    async def execute(self, _stmt):
        self.counter[0] += 1
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def commit(self) -> None:  # pragma: no cover - never reached on the miss path
        return None


class _ThrottleCache:
    """Windowed INCR counter that ALSO supports peek (the lockout pre-check reads without incrementing)."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def incr_call_count(self, key: str, window_s: int = 60) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def peek_call_count(self, key: str) -> int:
        return self.counts.get(key, 0)


def test_repeated_authfail_short_circuits_before_db_lookup() -> None:
    """After _AUTHFAIL_THRESHOLD failures on one display-prefix, further attempts must NOT hit the DB.

    FAIL-ON-BUG: pre-fix, the DB lookup runs on every one of the 15 attempts (counter == 15) because
    there is no lockout gate; post-fix it runs exactly _AUTHFAIL_THRESHOLD (10) times, then throttles.
    """
    cache = _ThrottleCache()
    counter = [0]
    session = _CountingSession(counter)

    async def _factory():
        yield session

    attempts = 15
    for _ in range(attempts):
        result = asyncio.run(
            ak.authenticate_api_key("nrvq_deadbeef99", session_factory=_factory, cache=cache)
        )
        assert result is None  # a wrong key never authenticates

    # The DB lookup is short-circuited once the failed-auth ceiling is reached.
    assert counter[0] == ak._AUTHFAIL_THRESHOLD, (
        f"expected DB lookup to stop at the throttle ceiling ({ak._AUTHFAIL_THRESHOLD}); "
        f"ran {counter[0]} times — throttle not enforced"
    )
    assert counter[0] < attempts  # explicit: not every attempt reached the DB
    # And the counter stops advancing past the ceiling (throttled attempts do not increment).
    assert cache.counts[ak._authfail_key("nrvq_deadbeef")] == ak._AUTHFAIL_THRESHOLD


def test_throttle_fails_open_when_cache_missing_peek() -> None:
    """A cache without peek support (or no cache) must not throttle — auth degrades open, never harder.

    Guards against the gate breaking the normal path: with no cache the resolver still reaches the DB
    on every attempt (fail-open), preserving availability if Redis is down.
    """
    counter = [0]
    session = _CountingSession(counter)

    async def _factory():
        yield session

    for _ in range(5):
        assert asyncio.run(
            ak.authenticate_api_key("nrvq_abcd1234xyz", session_factory=_factory, cache=None)
        ) is None

    assert counter[0] == 5  # no cache -> no lockout -> DB reached every time


def test_valid_key_below_threshold_still_authenticates() -> None:
    """The throttle gate must not reject a legitimate key while under the failed-auth ceiling."""
    cache = _ThrottleCache()
    full, prefix, key_hash = ak.generate_key()
    row = SimpleNamespace(
        id="1", prefix=prefix, key_hash=key_hash, name="k", namespace="team-a", role="viewer",
        revoked=False, last_used_at=None,
    )

    async def _factory():
        yield SimpleNamespace(
            execute=lambda _stmt: _ok(row),
            commit=_noop,
        )

    principal = asyncio.run(ak.authenticate_api_key(full, session_factory=_factory, cache=cache))
    assert principal is not None and principal["sub"] == f"apikey:{prefix}"


async def _ok(row):
    return SimpleNamespace(scalar_one_or_none=lambda: row)


async def _noop():
    return None
