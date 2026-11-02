# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The boot warms of agent freezes and trust caps, and of namespace posture, must not fail quietly.

Freezes and caps are persisted in agent_registry but enforced from the store, and the store copy is
written by the admin call and by this warm, once per API process start. Nothing else writes it back.

warm_agent_overrides used to catch its own error, log a WARNING and return the count it had reached,
0 when the query itself failed. The lifespan's ERROR (NRVQ-API-7035) sat behind it and only fired when
no session could be opened. So a failed warm logged the same way, and returned the same 0, as a cluster
where nothing is frozen, and the frozen agents ran unfrozen until the next restart. A transient failure
(Postgres still starting, a connection reset) was not tried again.

warm_ns_settings already raised, and the lifespan logged that at ERROR (NRVQ-API-7138), but it too was
one attempt. Both now run under norviq.startup_retry.warm_with_backoff: 3 attempts, 1 s then 2 s apart,
each cut off at WARM_ATTEMPT_TIMEOUT_S.
"""

from __future__ import annotations

import asyncio

import pytest
import structlog

from norviq import startup_retry
from norviq.api.routers import agents, settings_router


@pytest.fixture
def slept(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the backoff's sleeps instead of waiting them out (the helper calls asyncio.sleep)."""
    calls: list[float] = []
    real_sleep = asyncio.sleep

    async def _no_wait(s, *a, **k):
        calls.append(s)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", _no_wait)
    return calls


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _Session:
    def __init__(self, rows=None, boom: Exception | None = None):
        self._rows = rows or []
        self._boom = boom

    async def execute(self, *_a, **_k):
        if self._boom is not None:
            raise self._boom
        return _Rows(self._rows)


def _factory(*sessions):
    """A get_session stand-in that hands out the given sessions in order, one per call."""
    queue = list(sessions)

    async def _gen():
        yield queue.pop(0)

    return _gen


class _Client:
    def __init__(self, store, fail_after: int | None):
        self._store = store
        self._fail_after = fail_after

    async def set(self, key, value):
        if self._fail_after is not None and len(self._store) >= self._fail_after:
            raise ConnectionError("store connection reset")
        self._store[key] = value


class _Cache:
    def __init__(self, fail_after: int | None = None):
        self.store: dict[str, str] = {}
        self._fail_after = fail_after

    def _client(self):
        return _Client(self.store, self._fail_after)

    async def set_trust_override(self, spiffe_id, score):
        await self._client().set(f"agent_trust_override:{spiffe_id}", str(float(score)))


_FROZEN = {"spiffe_id": "spiffe://c/ns/a/sa/x", "frozen": True, "trust_cap": None}
_CAPPED = {"spiffe_id": "spiffe://c/ns/a/sa/y", "frozen": False, "trust_cap": 0.3}


async def test_a_failed_query_raises_instead_of_reporting_nothing_frozen():
    """Before: returned 0 with a WARNING, exactly what a cluster with no freezes returns."""
    with pytest.raises(OSError):
        await agents.warm_agent_overrides(_Cache(), _factory(_Session(boom=OSError("connection refused"))))


async def test_a_store_write_failing_partway_raises():
    """Before: returned 1 of 2, and the second agent ran uncapped with nothing above a WARNING."""
    cache = _Cache(fail_after=1)
    with pytest.raises(ConnectionError):
        await agents.warm_agent_overrides(cache, _factory(_Session(rows=[_FROZEN, _CAPPED])))


async def test_startup_warm_retries_a_transient_failure(slept):
    cache = _Cache()
    with structlog.testing.capture_logs() as logs:
        seeded = await agents.warm_agent_overrides_at_startup(
            cache,
            _factory(_Session(boom=OSError("connection refused")), _Session(rows=[_FROZEN, _CAPPED])),
        )
    assert seeded == 2
    assert cache.store == {
        f"agent_frozen:{_FROZEN['spiffe_id']}": "1",
        f"agent_trust_override:{_CAPPED['spiffe_id']}": "0.3",
    }
    assert slept == [1]
    warnings = [r for r in logs if r["log_level"] == "warning"]
    assert [(r["event"], r["code"]) for r in warnings] == [("nrvq.startup.agent_overrides_warm_retry", "NRVQ-API-7158")]
    assert not [r for r in logs if r["log_level"] == "error"]


async def test_startup_warm_gives_up_after_bounded_attempts_and_logs_an_error(slept):
    """Bounded: WARM_ATTEMPTS tries, 1 s then 2 s apart, then one ERROR an operator can alert on."""
    sessions = [_Session(boom=OSError("connection refused")) for _ in range(startup_retry.WARM_ATTEMPTS)]
    with structlog.testing.capture_logs() as logs:
        seeded = await agents.warm_agent_overrides_at_startup(_Cache(), _factory(*sessions))
    assert seeded is None, "a warm that never completed must not report a count"
    assert startup_retry.WARM_ATTEMPTS == 3 and slept == [1, 2]
    errors = [r for r in logs if r["log_level"] == "error"]
    assert [(r["event"], r["code"]) for r in errors] == [("nrvq.startup.agent_overrides_warm_failed", "NRVQ-API-7035")]
    assert errors[0]["attempts"] == startup_retry.WARM_ATTEMPTS
    assert "connection refused" in errors[0]["error"]


async def test_a_hung_attempt_is_cut_off_and_retried(slept, monkeypatch):
    """A store that stops answering has no client timeout; the attempt bound is what keeps startup finite."""
    monkeypatch.setattr(startup_retry, "WARM_ATTEMPT_TIMEOUT_S", 0.05)

    class _Hang(_Session):
        async def execute(self, *_a, **_k):
            await asyncio.Event().wait()

    cache = _Cache()
    # The outer bound turns "the attempt is never cut off" into a failure instead of a hung suite.
    seeded = await asyncio.wait_for(
        agents.warm_agent_overrides_at_startup(cache, _factory(_Hang(), _Session(rows=[_FROZEN]))), 5
    )
    assert seeded == 1 and cache.store == {f"agent_frozen:{_FROZEN['spiffe_id']}": "1"}


class _NsRow:
    def __init__(self, namespace, mode):
        self.namespace, self.enforcement_mode, self.trust_threshold, self.rate_limit = namespace, mode, None, None


class _NsResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _NsSession(_Session):
    async def execute(self, *_a, **_k):
        if self._boom is not None:
            raise self._boom
        return _NsResult(self._rows)


class _NsCache:
    def __init__(self):
        self.posture: dict[str, dict] = {}

    async def set_ns_settings(self, namespace, fields):
        self.posture[namespace] = fields


async def test_namespace_posture_warm_retries_a_transient_failure(slept):
    """Before: one attempt, so a transient failure left every saved posture absent until the next restart."""
    cache = _NsCache()
    with structlog.testing.capture_logs() as logs:
        ok = await settings_router.warm_ns_settings_at_startup(
            cache, _factory(_NsSession(boom=OSError("connection reset")), _NsSession(rows=[_NsRow("prod", "block")]))
        )
    assert ok is True
    assert cache.posture == {"prod": {"enforcement_mode": "block", "trust_threshold": None, "rate_limit": None}}
    assert slept == [1]
    assert [(r["event"], r["code"]) for r in logs if r["log_level"] == "warning"] == [
        ("nrvq.startup.ns_settings_warm_retry", "NRVQ-API-7159")
    ]


async def test_namespace_posture_warm_gives_up_with_7138_at_error(slept):
    sessions = [_NsSession(boom=OSError("connection reset")) for _ in range(startup_retry.WARM_ATTEMPTS)]
    with structlog.testing.capture_logs() as logs:
        ok = await settings_router.warm_ns_settings_at_startup(_NsCache(), _factory(*sessions))
    assert ok is False
    assert slept == [1, 2]
    assert [(r["event"], r["code"]) for r in logs if r["log_level"] == "error"] == [
        ("nrvq.startup.ns_settings_warm_failed", "NRVQ-API-7138")
    ]


async def test_lifespan_uses_the_retrying_warms():
    """main.py must call the retrying entry points, not the single-shot warms."""
    import inspect

    from norviq.api import main

    src = inspect.getsource(main)
    assert "warm_agent_overrides_at_startup(" in src and "await warm_agent_overrides(" not in src
    assert "warm_ns_settings_at_startup(" in src and "settings_router.warm_ns_settings(" not in src
