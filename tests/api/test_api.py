# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API endpoint tests for F017."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
from jose import jwt

from norviq.api.main import create_app
from norviq.api.routers import audit as audit_router
from norviq.api.routers import health as health_router
from norviq.config import settings
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.trust import TrustScore


class FakeCache:
    """In-memory cache test double."""

    def __init__(self) -> None:
        self.trust: dict[str, TrustScore] = {}
        self.policy: dict[str, str] = {}

    def _client(self) -> "FakeCache":
        """Return self for scan_iter compatibility."""
        return self

    async def scan_iter(self, pattern: str):
        """Yield trust keys."""
        for spiffe_id in self.trust:
            yield f"trust:{spiffe_id}"

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        """Get trust by id."""
        return self.trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        """Set trust by id."""
        self.trust[spiffe_id] = score

    async def set_policy(self, namespace: str, agent_class: str, rego: str) -> None:
        """Set policy source."""
        self.policy[f"{namespace}:{agent_class}"] = rego

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        """Delete policy source."""
        self.policy.pop(f"{namespace}:{agent_class}", None)


class FakeEvaluator:
    """Policy evaluator stub."""

    def load_policy(self, namespace: str, agent_class: str, rego_source: str) -> None:
        """Accept loaded policy."""


class FakeSession:
    """Minimal async session for audit queries."""

    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    async def execute(self, stmt):
        """Return canned scalar and grouped results."""
        sql = str(stmt)
        if "GROUP BY" in sql:
            return SimpleNamespace(all=lambda: [("tool.alpha", 2)])
        if "count(audit_log.id)" in sql and "decision" in sql:
            return SimpleNamespace(scalar=lambda: 1)
        if "count(audit_log.id)" in sql:
            return SimpleNamespace(scalar=lambda: len(self.rows))
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: self.rows),
        )

    async def scalar(self, stmt):
        """Return scalar query results."""
        sql = str(stmt)
        if "count(audit_log.id)" in sql and "decision" in sql:
            return 1
        if "count(audit_log.id)" in sql:
            return len(self.rows)
        return self.rows[0] if self.rows else None

    async def close(self) -> None:
        """No-op close."""


def _client() -> TestClient:
    """Create API test client with fake app state."""
    app = create_app()
    cache = FakeCache()
    app.state.cache = cache
    app.state.loader = PolicyLoader(cache, FakeEvaluator())
    app.state.cache._redis = object()
    return TestClient(app)


def _auth_headers() -> dict[str, str]:
    """Build valid auth header for protected endpoints."""
    token = jwt.encode({"sub": "test-user"}, settings.api_secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_health_and_readyz() -> None:
    """Serve healthz and readyz payloads."""
    async def fake_session():
        return FakeSession([])

    health_router.get_session = fake_session
    client = _client()
    try:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json() == {"status": "ready", "redis": True, "db": True}
    finally:
        client.close()


def test_readyz_db_failure_returns_false() -> None:
    """Return db=false when readiness DB probe fails."""

    class FailingSession:
        async def execute(self, stmt) -> None:
            raise RuntimeError("db down")

        async def close(self) -> None:
            return None

    async def fake_session():
        return FailingSession()

    health_router.get_session = fake_session
    client = _client()
    try:
        assert client.get("/readyz").json() == {"status": "ready", "redis": True, "db": False}
    finally:
        client.close()


def test_policy_crud_flow() -> None:
    """Create, list, get, delete policy."""
    client = _client()
    try:
        body = {"namespace": "payments", "agent_class": "planner", "rego_source": "package norviq.allow"}
        created = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert created.status_code == 200
        assert created.json()["version"] == 1
        listed = client.get("/api/v1/policies").json()
        assert listed and listed[0]["namespace"] == "payments"
        fetched = client.get("/api/v1/policies/payments/planner")
        assert fetched.status_code == 200
        assert fetched.json()["rego_source"] == "package norviq.allow"
        assert client.delete("/api/v1/policies/payments/planner", headers=_auth_headers()).json() == {"deleted": True}
    finally:
        client.close()


def test_policy_get_missing_returns_404() -> None:
    """Return 404 for missing policy lookup."""
    client = _client()
    try:
        response = client.get("/api/v1/policies/missing/missing")
        assert response.status_code == 404
    finally:
        client.close()


def test_audit_list_filter_and_stats() -> None:
    """List and filter audit records plus stats."""
    row = SimpleNamespace(
        id=uuid4(),
        event_id=uuid4(),
        tool_name="tool.alpha",
        decision="block",
        agent_id="spiffe://example/ns/default/sa/a",
        namespace="default",
        rule_id="deny",
        reason="test",
        trust_score=0.5,
        latency_ms=12.3,
        timestamp_utc=datetime.now(timezone.utc),
        payload={"ok": True},
    )

    async def fake_session():
        return FakeSession([row])

    audit_router.get_session = fake_session
    client = _client()
    try:
        records = client.get("/api/v1/audit/records?decision=block").json()
        assert len(records) == 1 and records[0]["decision"] == "block"
        stats = client.get("/api/v1/audit/stats").json()
        assert stats["total"] == 1 and stats["blocked"] == 1 and stats["top_tools"][0]["tool_name"] == "tool.alpha"
    finally:
        client.close()


def test_agents_list_and_update_trust() -> None:
    """Update trust score and list agent."""
    client = _client()
    try:
        spiffe = "spiffe://example/ns/default/sa/agent-one"
        updated = client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.61}, headers=_auth_headers())
        assert updated.status_code == 200
        listed = client.get("/api/v1/agents").json()
        assert len(listed) == 1 and listed[0]["spiffe_id"] == spiffe
    finally:
        client.close()


def test_invalid_trust_score_returns_422() -> None:
    """Reject out-of-range trust score with 422."""
    client = _client()
    try:
        spiffe = "spiffe://example/ns/default/sa/agent-one"
        response = client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 2.5}, headers=_auth_headers())
        assert response.status_code == 422
    finally:
        client.close()
