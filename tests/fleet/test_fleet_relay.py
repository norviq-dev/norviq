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
