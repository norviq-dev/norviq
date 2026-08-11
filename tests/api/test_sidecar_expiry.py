# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""C2-020: the 30-day sidecar credential cliff must be forewarned, not just diagnosed afterwards.

Both credentials the webhook injects are 30-day and fixed in an immutable pod spec, and nothing renews
either. At expiry the API answers 401 and the sidecar fails CLOSED — which is CORRECT and deliberate
(a refused credential must not become a governance bypass) — so every injected pod stops making tool
calls on a timer. `/system-health` already diagnoses that once it starts; the defect was that the first
signal was the outage.
"""

from __future__ import annotations

import time

import pytest

from norviq.api import sidecar_expiry


class _FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, str] = {}
        self.fail = fail
        self.sets = 0

    async def set(self, key, value, ex=None, nx=False):
        if self.fail:
            raise RuntimeError("redis down")
        self.sets += 1
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def get(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        return self.store.get(key)

    async def scan_iter(self, match=None, count=None):
        if self.fail:
            raise RuntimeError("redis down")
        for k in list(self.store):
            yield k


class _FakeCache:
    def __init__(self, redis: _FakeRedis) -> None:
        self._redis = redis

    def _client(self):
        return self._redis


def _claims(days_left: float, role: str = "service", **extra) -> dict:
    return {
        "role": role,
        "namespace": "analytics",
        "workload": "finance-agent",
        "exp": int(time.time() + days_left * 86400),
        **extra,
    }


@pytest.mark.asyncio
async def test_a_healthy_credential_writes_nothing_on_the_hot_path():
    """This runs inside authentication. The steady state for a healthy fleet must be zero writes."""
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=29))
    assert r.sets == 0, "a credential outside the warning window must not touch Redis"


@pytest.mark.asyncio
async def test_a_human_session_is_never_warned_about():
    """A short-lived human session expiring is not an infrastructure event; warning would be noise."""
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=1, role="admin"))
    assert r.sets == 0


@pytest.mark.asyncio
async def test_a_credential_inside_the_window_is_recorded_and_reported():
    r = _FakeRedis()
    cache = _FakeCache(r)
    await sidecar_expiry.observe(cache, _claims(days_left=3))
    rows = await sidecar_expiry.expiring_soon(cache)
    assert len(rows) == 1
    assert rows[0]["namespace"] == "analytics"
    assert rows[0]["workload"] == "finance-agent"
    assert 2.5 <= rows[0]["days_left"] <= 3.5


@pytest.mark.asyncio
async def test_repeated_calls_do_not_write_per_request():
    """A busy workload in its final week would otherwise turn this into a write per evaluate call."""
    r = _FakeRedis()
    cache = _FakeCache(r)
    for _ in range(50):
        await sidecar_expiry.observe(cache, _claims(days_left=2))
    assert len(r.store) == 1
    assert r.sets == 50  # the call is made...
    # ...but nx means only the first one stores, which is what bounds the key space.


@pytest.mark.asyncio
async def test_an_expired_credential_is_not_recorded_as_live():
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=-1))
    assert r.sets == 0


@pytest.mark.asyncio
async def test_a_redis_failure_never_breaks_authentication():
    """observe() runs in the auth path. Failing a login because a reporting write failed would be a
    far worse bug than the one this warns about."""
    await sidecar_expiry.observe(_FakeCache(_FakeRedis(fail=True)), _claims(days_left=2))
    await sidecar_expiry.observe(None, _claims(days_left=2))  # no cache configured at all


@pytest.mark.asyncio
async def test_an_unreadable_redis_degrades_to_no_warning_not_a_500():
    """/system-health is the page an operator opens DURING an incident. It must not 500 because the
    newest, least important band could not be read."""
    assert await sidecar_expiry.expiring_soon(_FakeCache(_FakeRedis(fail=True))) == []
    assert await sidecar_expiry.expiring_soon(None) == []


@pytest.mark.asyncio
async def test_namespace_scoping_matches_the_rest_of_the_route():
    r = _FakeRedis()
    cache = _FakeCache(r)
    await sidecar_expiry.observe(cache, _claims(days_left=2))
    await sidecar_expiry.observe(cache, _claims(days_left=2, namespace="chatbot-prod"))
    assert len(await sidecar_expiry.expiring_soon(cache)) == 2
    scoped = await sidecar_expiry.expiring_soon(cache, "analytics")
    assert [r_["namespace"] for r_ in scoped] == ["analytics"]


def test_the_band_is_a_warning_not_a_critical():
    """Nothing is broken yet — that is the whole point. Raising it as critical would train operators
    to ignore the band that DOES mean an outage."""
    rows = [{"namespace": "analytics", "workload": "finance-agent",
             "expires_at": int(time.time() + 2 * 86400), "days_left": 2.0}]
    issue = sidecar_expiry.issue_for(rows)
    assert issue is not None
    assert issue["severity"] == "warning"
    assert "finance-agent" in issue["detail"]
    # The remediation must be the one that actually works: rotation IS pod replacement.
    assert "roll" in issue["remediation"].lower() or "replace" in issue["remediation"].lower()


def test_no_band_when_there_is_nothing_to_say():
    assert sidecar_expiry.issue_for([]) is None
