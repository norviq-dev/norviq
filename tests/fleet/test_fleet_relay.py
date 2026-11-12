# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Relay tests: relay_once heartbeats + pushes agent/audit rollups; start() is a no-op when off."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from norviq.config import settings
from norviq.fleet_relay import FleetRelayForwarder


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _Scalars(self._rows)

    def all(self):
        return self._rows


class _SpokeSession:
    """Returns agent rows on the first execute (scalars), audit tuples on the second (all)."""

    def __init__(self, agents, audit):
        self._queue = [agents, audit]

    async def execute(self, stmt):
        return _Result(self._queue.pop(0) if self._queue else [])

    async def aclose(self):
        pass


class _Resp:
    def raise_for_status(self):
        return None


class _FakeHub:
    def __init__(self):
        self.posts = []

    async def post(self, url, headers=None, json=None):
        self.posts.append({"url": url, "json": json, "auth": (headers or {}).get("Authorization", "")})
        return _Resp()

    async def aclose(self):
        pass


def _session_factory(agents, audit):
    async def _gen():
        yield _SpokeSession(agents, audit)
    return _gen


@pytest.mark.asyncio
async def test_relay_once_heartbeats_and_pushes_rollups(monkeypatch) -> None:
    monkeypatch.setattr(settings, "fleet_api_url", "http://hub:8080")
    monkeypatch.setattr(settings, "fleet_cluster_id", "cluster-a")
    monkeypatch.setattr(settings, "fleet_cluster_name", "prod-west")
    monkeypatch.setattr(settings, "fleet_oidc_token_url", "")  # -> HS256 self-mint
    monkeypatch.setattr(settings, "legacy_hs256_enabled", True)

    now = datetime.now(timezone.utc)
    agents = [SimpleNamespace(spiffe_id="spiffe://norviq/ns/p/sa/x", namespace="p", agent_class="c",
                              trust_score=0.8, trust_category="High", last_seen=now)]
    audit = [("p", now.replace(minute=0, second=0, microsecond=0), "block", 4),
             ("p", now.replace(minute=0, second=0, microsecond=0), "allow", 120)]
    hub = _FakeHub()
    relay = FleetRelayForwarder(session_factory=_session_factory(agents, audit), client=hub)

    result = await relay.relay_once()
    assert result == {"agents": 1, "audit": 2}
    # two POSTs: heartbeat then rollup, both to this cluster's path, both Bearer-authed
    assert [p["url"] for p in hub.posts] == [
        "http://hub:8080/api/v1/fleet/clusters/cluster-a/heartbeat",
        "http://hub:8080/api/v1/fleet/clusters/cluster-a/rollup",
    ]
    assert all(p["auth"].startswith("Bearer ") for p in hub.posts)
    rollup = hub.posts[1]["json"]
    assert rollup["agents"][0]["spiffe_id"] == "spiffe://norviq/ns/p/sa/x"
    assert {a["decision"] for a in rollup["audit"]} == {"block", "allow"}


@pytest.mark.asyncio
async def test_start_is_noop_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "fleet_enabled", False)
    relay = FleetRelayForwarder()
    await relay.start()
    assert relay._task is None  # no background task created -> single-cluster unaffected
    await relay.stop()


class _RecordingSession(_SpokeSession):
    def __init__(self, agents, audit):
        super().__init__(agents, audit)
        self.statements = []

    async def execute(self, stmt):
        self.statements.append(stmt)
        return await super().execute(stmt)


@pytest.mark.asyncio
async def test_the_rollup_carries_real_agents_and_real_traffic_only() -> None:
    """The spoke's Overview and Agents roster leave out test identities and red-team / Simulate / probe
    calls, by the shared classifier. The rollup sent them all, so the hub counted what no spoke shows."""
    from norviq.api import synthetic

    now = datetime.now(timezone.utc)

    def agent(svid, cls):
        return SimpleNamespace(spiffe_id=svid, namespace="p", agent_class=cls, trust_score=0.8,
                               trust_category="High", last_seen=now)

    agents = [
        agent("spiffe://norviq/ns/p/sa/default", "customer-support"),
        agent("spiffe://norviq/ns/p/sa/policy-tester-k3x9", "customer-support"),
        agent("spiffe://norviq/ns/p/sa/e2e-bot", "e2e-bot"),
    ]
    session = _RecordingSession(agents, [])

    async def _gen():
        yield session

    relay = FleetRelayForwarder(session_factory=_gen, client=_FakeHub())
    pushed_agents, _audit = await relay._aggregate()
    assert [a["spiffe_id"] for a in pushed_agents] == ["spiffe://norviq/ns/p/sa/default"]

    # The audit counts are aggregated in SQL, so the filter has to be in the statement: the shared
    # patterns, one per column. Their behaviour on real rows is in tests/api/test_synthetic_sql_twin_behaviour.py.
    audit_sql = str(session.statements[1].compile(compile_kwargs={"literal_binds": True}))
    where = audit_sql.split("WHERE", 1)[1].split("GROUP BY")[0]
    for pattern in (synthetic._FRAMEWORK_PATTERN, synthetic._CLASS_PATTERN, synthetic._SVID_PATTERN):
        assert pattern in where
