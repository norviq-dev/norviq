# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet hub API tests (F045): heartbeat/rollup ingest, aggregated reads, cluster-scope RBAC.

Uses the bare-TestClient + dependency_overrides pattern from tests/api/test_api.py (lifespan is not
triggered, so the real fleet DB is never initialized); fleet_get_session is overridden with a fake."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient
from jose import jwt

from norviq.config import settings
from norviq.fleet.db import fleet_get_session
from norviq.fleet.main import create_fleet_app


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


class FakeFleetSession:
    """Records upserts; returns a queue of programmed row-lists for SELECTs."""

    def __init__(self, results=None):
        self.results = list(results or [])
        self.executed = []
        self.committed = False

    async def execute(self, stmt):
        self.executed.append(stmt)
        if getattr(stmt, "is_insert", False):
            return _Result([])
        return _Result(self.results.pop(0) if self.results else [])

    async def commit(self):
        self.committed = True

    async def close(self):
        pass


def _client(session) -> TestClient:
    app = create_fleet_app()

    async def _gen():
        yield session

    app.dependency_overrides[fleet_get_session] = _gen
    return TestClient(app)


def _headers(role: str = "service", cluster: str = "*") -> dict[str, str]:
    token = jwt.encode({"sub": "t", "role": role, "cluster": cluster}, settings.api_secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_heartbeat_upserts_and_returns_status() -> None:
    s = FakeFleetSession()
    c = _client(s)
    try:
        r = c.post("/api/v1/fleet/clusters/cluster-a/heartbeat",
                   json={"name": "prod-west", "endpoint": "https://a", "region": "us-west"},
                   headers=_headers(role="service", cluster="cluster-a"))
        assert r.status_code == 200 and r.json()["status"] == "healthy"
        assert s.committed and len(s.executed) == 1
    finally:
        c.close()


def test_rollup_upserts_agents_and_audit() -> None:
    s = FakeFleetSession()
    c = _client(s)
    try:
        body = {
            "agents": [{"spiffe_id": "spiffe://norviq/ns/p/sa/x", "namespace": "p", "trust_score": 0.8, "trust_category": "High"}],
            "audit": [{"namespace": "p", "bucket_ts": "2026-06-28T11:00:00+00:00", "decision": "block", "count": 4}],
        }
        r = c.post("/api/v1/fleet/clusters/cluster-a/rollup", json=body, headers=_headers(cluster="cluster-a"))
        assert r.status_code == 200
        assert r.json() == {"cluster_id": "cluster-a", "agents_upserted": 1, "audit_upserted": 1}
        assert s.committed and len(s.executed) == 2  # one agent upsert + one audit upsert
    finally:
        c.close()


def test_relay_cannot_write_another_cluster() -> None:
    # cluster-a's service token must not write cluster-b's rollups (cluster-scope on the path).
    s = FakeFleetSession()
    c = _client(s)
    try:
        r = c.post("/api/v1/fleet/clusters/cluster-b/heartbeat", json={"name": "x"}, headers=_headers(cluster="cluster-a"))
        assert r.status_code == 403
        assert not s.committed
    finally:
        c.close()


def test_clusters_status_and_scope() -> None:
    now = datetime.now(timezone.utc)
    rows = [
        SimpleNamespace(id="cluster-a", name="a", region="r1", endpoint="e1", last_heartbeat=now),
        SimpleNamespace(id="cluster-b", name="b", region="r2", endpoint="e2", last_heartbeat=now - timedelta(hours=2)),
    ]
    # admin sees both, with computed status (recent=healthy, old=stale)
    s = FakeFleetSession(results=[rows])
    c = _client(s)
    try:
        out = c.get("/api/v1/fleet/clusters", headers=_headers(role="admin")).json()
        by = {x["id"]: x["status"] for x in out}
        assert by == {"cluster-a": "healthy", "cluster-b": "stale"}
    finally:
        c.close()


def test_audit_summary_sums_by_decision() -> None:
    rows = [("cluster-a", "allow", 120), ("cluster-a", "block", 5), ("cluster-b", "allow", 30)]
    s = FakeFleetSession(results=[rows])
    c = _client(s)
    try:
        out = c.get("/api/v1/fleet/audit/summary?range=24h", headers=_headers(role="admin")).json()
        by = {x["cluster_id"]: x for x in out}
        assert by["cluster-a"]["allow"] == 120 and by["cluster-a"]["block"] == 5 and by["cluster-a"]["total"] == 125
        assert by["cluster-b"]["total"] == 30
    finally:
        c.close()


def test_cluster_scope_blocks_cross_cluster_read() -> None:
    # A viewer scoped to cluster-a may not request cluster-b's data -> 403.
    s = FakeFleetSession(results=[[]])
    c = _client(s)
    try:
        assert c.get("/api/v1/fleet/agents?cluster=cluster-b", headers=_headers(role="viewer", cluster="cluster-a")).status_code == 403
        # its own cluster is fine
        assert c.get("/api/v1/fleet/agents?cluster=cluster-a", headers=_headers(role="viewer", cluster="cluster-a")).status_code == 200
    finally:
        c.close()


def test_unauth_rejected() -> None:
    c = _client(FakeFleetSession())
    try:
        assert c.get("/api/v1/fleet/clusters").status_code == 401
    finally:
        c.close()
