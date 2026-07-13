# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API endpoint tests for F017."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import text

from norviq.api.db.session import create_tables, ensure_schema_compatibility, get_session
from norviq.api.main import create_app
from norviq.config import settings
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.trust import TrustScore


def _override_session(client: "TestClient", session_obj: object) -> None:
    """Override the get_session async-generator dependency the FastAPI-correct way.

    Do NOT monkeypatch get_session: `Depends(get_session)` captures the original at
    route-definition time, so monkeypatching the module attribute is a no-op AND masks
    the P-15 async-generator bug (see docs/engineering/bug-patterns.md). Use
    dependency_overrides so the real session lifecycle is exercised.
    """

    async def _gen():
        yield session_obj

    client.app.dependency_overrides[get_session] = _gen


class FakeCache:
    """In-memory cache test double."""

    def __init__(self) -> None:
        self.trust: dict[str, TrustScore] = {}
        self.policy: dict[str, dict] = {}
        self.values: dict[str, str] = {}

    def _client(self) -> "FakeCache":
        """Return self for scan_iter compatibility."""
        return self

    async def ping(self) -> bool:
        """Readiness probe hook — a healthy fake Redis answers PING."""
        return True

    async def scan_iter(self, pattern: str):
        """Yield trust keys."""
        if pattern == "trust:*":
            for spiffe_id in self.trust:
                yield f"trust:{spiffe_id}"

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        """Get trust by id."""
        return self.trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        """Set trust by id."""
        self.trust[spiffe_id] = score

    async def set(self, key: str, value: str) -> None:
        """Set generic key/value for route tests."""
        self.values[key] = value

    async def get(self, key: str) -> str | None:
        """Get generic key/value for route tests."""
        return self.values.get(key)

    async def delete(self, key: str) -> None:
        """Delete generic key/value for route tests."""
        self.values.pop(key, None)

    async def set_policy(
        self,
        namespace: str,
        agent_class: str,
        rego: str,
        priority: int = 100,
        version: int = 0,
    ) -> None:
        """Set policy source."""
        self.policy[f"{namespace}:{agent_class}"] = {"rego": rego, "priority": int(priority), "version": int(version)}

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        """Delete policy source."""
        self.policy.pop(f"{namespace}:{agent_class}", None)

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        """No-op invalidation for API unit tests."""
        return 0

    async def invalidate_all_eval(self) -> int:
        """No-op global invalidation for API unit tests."""
        return 0

    async def publish_policy_event(
        self, operation: str, namespace: str, agent_class: str, version: int = 0, origin: str = ""
    ) -> None:
        """No-op policy event publish for API unit tests. `origin` mirrors RedisCache's HA echo-suppression
        id (PolicyLoader.create() now always passes it — see norviq/engine/cache.py publish_policy_event)."""
        return None

    async def list_policy_entries(self) -> dict[str, dict]:
        """Return fake policy entries keyed like Redis policy:* keys."""
        return {f"policy:{key}": value for key, value in self.policy.items()}

    async def set_trust_override(self, spiffe_id: str, score: float) -> None:
        """AGT-TRUST-02: durable admin trust cap — mirrors RedisCache.set_trust_override's
        agent_trust_override:{spiffe} key via the generic set()/get()/delete() this fake already backs."""
        await self.set(f"agent_trust_override:{spiffe_id}", str(float(score)))

    async def clear_trust_override(self, spiffe_id: str) -> None:
        """AGT-TRUST-02: remove the admin trust cap."""
        await self.delete(f"agent_trust_override:{spiffe_id}")


class FakeEvaluator:
    """Policy evaluator stub."""

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        """Accept loaded policy."""

    def bind_loader(self, loader: object) -> None:
        """Accept loader binding."""

    async def _evaluate_opa(
        self, key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = ""
    ) -> dict:
        """Stub OPA eval: raise for a broken rego, else return a valid decision shape."""
        if "decision" not in rego_source:
            raise RuntimeError("opa eval failed: rego did not produce a decision")
        return {"decision": "allow", "rule_id": "default_allow", "reason": ""}


class FakeSession:
    """Minimal async session for audit queries."""

    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    async def execute(self, stmt):
        """Return canned scalar and grouped results."""
        sql = str(stmt)
        if "GROUP BY" in sql:
            return SimpleNamespace(all=lambda: [SimpleNamespace(tool_name="tool.alpha", count=2)])
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
        if "avg(audit_log.latency_ms)" in sql:
            # K2: real avg-latency KPI — return the seeded rows' own latency_ms (float), not a row object.
            return self.rows[0].latency_ms if self.rows else None
        if "count(audit_log.id)" in sql and "decision" in sql:
            return 1
        if "count(audit_log.id)" in sql:
            return len(self.rows)
        return self.rows[0] if self.rows else None

    async def scalars(self, stmt):
        """Return an object with .all() yielding ORM rows, mirroring AsyncSession.scalars(stmt) (distinct
        from execute(stmt).scalars() — the dry-run replay path calls this directly, see policies.py
        _replay_recent)."""
        return SimpleNamespace(all=lambda: self.rows)

    async def close(self) -> None:
        """No-op close."""


def _client() -> TestClient:
    """Create API test client with fake app state."""
    app = create_app()
    cache = FakeCache()
    app.state.cache = cache
    app.state.loader = PolicyLoader(cache, FakeEvaluator())
    # HA-CRITICAL: production never serves traffic until warm_cache() sets this True (readyz gates on it,
    # see norviq/api/routers/health.py) — these unit tests aren't exercising the warm-cache mechanic itself,
    # so start "warm" like a live pod would be, matching what /readyz assumes.
    app.state.loader._warmed = True
    # H2/F-52: PolicyLoader.create()/delete() are DB-authoritative — they always hit Postgres via the
    # loader's own lazily-created pooled engine (_db_engine()), independent of Depends(get_session).
    # starlette's TestClient dispatches each request through its own (short-lived) background-thread event
    # loop, so a QueuePool-cached connection from one request is dead by the next — a multi-request test
    # (create → list → get → delete) then dies with "Event loop is closed" on request 2+. Pre-seed the
    # loader's engine with NullPool (fresh connection per checkout, nothing cross-loop to reuse) so it's
    # robust regardless of which/how-many requests a test makes. Lazy (no I/O until the loader path is
    # actually exercised), so this is a no-op for every test that never calls loader.create()/delete().
    from sqlalchemy.ext.asyncio import create_async_engine as _create_async_engine
    from sqlalchemy.pool import NullPool as _NullPool

    app.state.loader._db = _create_async_engine(
        app.state.loader._db_url(), poolclass=_NullPool, connect_args=app.state.loader._build_connect_args()
    )
    app.state.cache._redis = object()
    return TestClient(app)


@pytest.fixture
async def real_db() -> None:
    """Initialize a real Postgres-backed session for tests that hit routes with NO FakeSession override.

    create_policy/apply_policy call `assert_apply_allowed(session, ...)` (a real `Depends(get_session)`
    query against namespace_settings) and PolicyLoader.create() persists to the `policies` table via its
    own DB engine — there is no in-memory fake for this path, so these specific tests need a live DB.
    Skips (does not fail) when no local Postgres is reachable — a genuine category-(a) environment gap,
    not a product bug.

    Uses NullPool rather than the product `init_db()`'s pooled engine: starlette's TestClient always
    dispatches the ASGI app through its OWN background-thread event loop, distinct from this pytest-asyncio
    fixture's loop. asyncpg connections are loop-bound, so a pooled connection opened in one loop and
    reused in the other blows up with "attached to a different loop". NullPool opens/closes a fresh
    connection per checkout, so every use (schema setup here, the request inside TestClient, cleanup below)
    is self-contained regardless of which loop touches it."""
    import norviq.api.db.session as db_session_mod
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.skip("NRVQ_PG_URL not set — no local Postgres configured for this integration test")
    old_url = settings.pg_url
    settings.pg_url = pg_url

    engine = None
    try:
        engine = create_async_engine(
            db_session_mod._async_pg_url(), poolclass=NullPool, connect_args=db_session_mod._build_connect_args()
        )
        db_session_mod._engine = engine
        db_session_mod._session_factory = async_sessionmaker(engine, expire_on_commit=False)
        await create_tables()
        await ensure_schema_compatibility()
    except Exception as exc:  # pragma: no cover - environment probe, not a product assertion
        db_session_mod._engine = None
        db_session_mod._session_factory = None
        if engine is not None:
            await engine.dispose()
        settings.pg_url = old_url
        pytest.skip(f"Postgres at {pg_url!r} unreachable/unusable for this integration test: {exc}")

    try:
        yield
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM policy_versions WHERE policy_id IN (SELECT id FROM policies WHERE namespace = 'payments')")
            )
            await conn.execute(text("DELETE FROM policies WHERE namespace = 'payments'"))
        await engine.dispose()
        db_session_mod._engine = None
        db_session_mod._session_factory = None
        settings.pg_url = old_url


def _auth_headers(role: str = "admin", sub: str = "test-user", namespace: str | None = None) -> dict[str, str]:
    """Build valid auth header for protected endpoints."""
    claims: dict[str, object] = {"sub": sub, "role": role}
    if namespace is not None:
        claims["namespace"] = namespace
    token = jwt.encode(claims, settings.api_secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_me_returns_normalized_claims() -> None:
    """A3: /api/v1/me returns the server's view of the caller (sub/role/namespace); unauth -> 401."""
    client = _client()
    try:
        resp = client.get("/api/v1/me", headers=_auth_headers(role="admin"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["sub"] == "test-user" and body["role"] == "admin"
        assert client.get("/api/v1/me").status_code == 401
    finally:
        client.close()


def test_health_and_readyz(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve healthz and readyz payloads. (subprocess mode: readyz omits the server-only opa key)."""
    monkeypatch.setattr(settings, "opa_mode", "subprocess")
    client = _client()
    _override_session(client, FakeSession([]))
    try:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").json() == {
            "status": "ready", "redis": True, "db": True, "policies_warm": True,
        }
    finally:
        client.close()


def test_readyz_db_failure_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DB outage makes /readyz return 503 (NotReady) so the pod drains traffic, not a false 200."""
    monkeypatch.setattr(settings, "opa_mode", "subprocess")

    class FailingSession:
        async def execute(self, stmt) -> None:
            raise RuntimeError("db down")

        async def close(self) -> None:
            return None

    client = _client()
    _override_session(client, FailingSession())
    try:
        resp = client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json() == {
            "status": "not-ready", "redis": True, "db": False, "policies_warm": True,
        }
    finally:
        client.close()


def test_policy_write_accepts_service_role_rejects_viewer() -> None:
    """C1: only the allowlisted control-plane controller (sub=norviq-webhook) writes cross-namespace; a
    viewer is rejected, and a GENERIC service token (not on the allowlist, no ns claim) is now floored to
    its namespace claim — it can no longer write an arbitrary namespace just by holding role=service."""
    client = _client()
    try:
        # viewer is rejected at the auth gate
        assert client.delete("/api/v1/policies/x/y", headers=_auth_headers(role="viewer")).status_code == 403
        # a generic (non-controller) service token no longer gets blanket cross-ns write — floored → 403
        assert client.delete("/api/v1/policies/x/y", headers=_auth_headers(role="service")).status_code == 403
        # the allowlisted webhook controller passes the write-scope gate (404 = not found, NOT 403)
        assert client.delete(
            "/api/v1/policies/x/y", headers=_auth_headers(role="service", sub="norviq-webhook")
        ).status_code == 404
    finally:
        client.close()


async def test_policy_crud_flow(real_db: None) -> None:
    """Create, list, get, delete policy."""
    client = _client()
    try:
        rego = 'package norviq\ndefault decision = "allow"\ndecision = "block" { input.tool_name == "danger" }\nrule_id = "r"\nreason = "x"'
        body = {"namespace": "payments", "agent_class": "planner", "rego_source": rego}
        created = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert created.status_code == 200
        assert created.json()["version"] == 1
        listed = client.get("/api/v1/policies?namespace=payments", headers=_auth_headers()).json()
        assert listed and listed[0]["namespace"] == "payments"
        fetched = client.get("/api/v1/policies/payments/planner", headers=_auth_headers())
        assert fetched.status_code == 200
        assert fetched.json()["rego_source"] == rego
        # Delete response now names exactly what was destroyed (namespace/agent_class/version) for the audit
        # trail — see norviq/api/routers/policies.py delete_policy.
        assert client.delete("/api/v1/policies/payments/planner", headers=_auth_headers()).json() == {
            "deleted": True, "namespace": "payments", "agent_class": "planner", "version": 1,
        }
    finally:
        client.close()


async def test_policy_create_allows_default_allow_with_enforcement(real_db: None) -> None:
    """Allow default-allow rego when explicit enforcement rules exist."""
    client = _client()
    try:
        body = {
            "namespace": "payments",
            "agent_class": "planner",
            "rego_source": 'package norviq\ndefault decision = "allow"\ndecision = "block" { true }\nrule_id = "r"\nreason = "x"',
        }
        response = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert response.status_code == 200
    finally:
        client.close()


async def test_policy_create_allows_spaced_default_allow_with_enforcement(real_db: None) -> None:
    """Allow spaced default-allow assignment when enforcement rules exist."""
    client = _client()
    try:
        body = {
            "namespace": "payments",
            "agent_class": "planner",
            "rego_source": 'package norviq\ndefault   decision= "allow"\ndecision = "block" { true }\nrule_id = "r"\nreason = "x"',
        }
        response = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert response.status_code == 200
    finally:
        client.close()


async def test_policy_create_rejects_regex_flood(real_db: None) -> None:
    """Reject direct API policy with too many regex operations (cap admits the ~11 the shipped
    comprehensive policy uses; a flood well above the cap is still rejected)."""
    client = _client()
    try:
        flood = "".join(
            f'decision = "block" {{ regex.match("p{i}", input.tool_name) }}\n' for i in range(30)
        )
        body = {
            "namespace": "payments",
            "agent_class": "planner",
            "rego_source": f"package norviq\n{flood}rule_id = \"r\"\nreason = \"x\"",
        }
        response = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert response.status_code == 422
    finally:
        client.close()


async def test_policy_create_regex_text_literal_allowed(real_db: None) -> None:
    """Allow regex words in string literals when no regex builtins are called."""
    client = _client()
    try:
        body = {
            "namespace": "payments",
            "agent_class": "planner",
            "rego_source": 'package norviq\ndefault decision = "allow"\ndecision = "block" { input.tool_name == "regex.match literal" }\nrule_id = "r"\nreason = "x"',
        }
        response = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert response.status_code == 200
    finally:
        client.close()


async def test_policy_create_uses_policy_name_when_agent_class_empty(real_db: None) -> None:
    """Use policy_name as storage key for non-agentClass policy payloads."""
    client = _client()
    try:
        body = {
            "namespace": "payments",
            "agent_class": "",
            "policy_name": "payments-baseline",
            "target": {"namespace": "payments"},
            "rego_source": 'package norviq\ndefault decision = "allow"\ndecision = "block" { input.tool_name == "danger" }\nrule_id = "r"\nreason = "x"',
        }
        response = client.post("/api/v1/policies", json=body, headers=_auth_headers())
        assert response.status_code == 200
        assert response.json()["agent_class"] == "payments-baseline"
    finally:
        client.close()


def test_policy_get_missing_returns_404() -> None:
    """Return 404 for missing policy lookup."""
    client = _client()
    try:
        response = client.get("/api/v1/policies/missing/missing", headers=_auth_headers())
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

    client = _client()
    _override_session(client, FakeSession([row]))
    try:
        records = client.get("/api/v1/audit/records?decision=block", headers=_auth_headers()).json()
        assert len(records) == 1 and records[0]["decision"] == "block"
        stats = client.get("/api/v1/audit/stats", headers=_auth_headers()).json()
        assert stats["total"] == 1 and stats["blocked"] == 1 and stats["top_tools"][0]["tool_name"] == "tool.alpha"
    finally:
        client.close()


def test_audit_records_with_range() -> None:
    """List audit records with range filter param."""
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

    client = _client()
    _override_session(client, FakeSession([row]))
    try:
        records = client.get("/api/v1/audit/records?range=1h", headers=_auth_headers()).json()
        assert len(records) == 1
    finally:
        client.close()


def test_audit_records_invalid_range_returns_422() -> None:
    """Reject invalid range token for records endpoint."""
    client = _client()
    _override_session(client, FakeSession([]))
    try:
        response = client.get("/api/v1/audit/records?range=99h", headers=_auth_headers())
        assert response.status_code == 422
    finally:
        client.close()


def test_audit_stats_with_range() -> None:
    """Return stats with range filter param."""
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

    client = _client()
    _override_session(client, FakeSession([row]))
    try:
        stats = client.get("/api/v1/audit/stats?range=7d", headers=_auth_headers()).json()
        assert stats["total"] == 1 and stats["blocked"] == 1
    finally:
        client.close()


def test_top_blocked() -> None:
    """Return top blocked tools."""
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

    client = _client()
    _override_session(client, FakeSession([row]))
    try:
        top = client.get("/api/v1/audit/top-blocked", headers=_auth_headers()).json()
        assert top and top[0]["tool_name"] == "tool.alpha"
    finally:
        client.close()


def test_volume() -> None:
    """Return hourly audit volume buckets."""
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

    client = _client()
    _override_session(client, FakeSession([row]))
    try:
        volume = client.get("/api/v1/audit/volume", headers=_auth_headers()).json()
        assert len(volume) == 1 and volume[0]["block"] == 1
    finally:
        client.close()


def test_dry_run() -> None:
    """Preview policy impact in dry-run endpoint."""
    row = SimpleNamespace(
        id=uuid4(),
        event_id=uuid4(),
        tool_name="tool.alpha",
        decision="block",
        agent_id="spiffe://example/ns/default/sa/a",
        agent_class="planner",  # M3: _replay_recent's synthetic-identity filter reads rec.agent_class
        namespace="default",
        rule_id="deny",
        reason="test",
        trust_score=0.5,
        latency_ms=12.3,
        timestamp_utc=datetime.now(timezone.utc),
        payload={"ok": True},
    )

    from norviq.api.db.session import get_session

    async def _override_session():
        yield FakeSession([row])

    client = _client()
    client.app.dependency_overrides[get_session] = _override_session
    client.app.state.evaluator = FakeEvaluator()
    try:
        body = {"namespace": "payments", "agent_class": "planner", "rego_source": 'package norviq\ndefault decision = "allow"\ndecision = "block" { input.tool_name == "danger" }\nrule_id = "r"\nreason = "x"'}
        response = client.post("/api/v1/policies/dry-run", json=body, headers=_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True  # dry-run now actually validates the submitted rego
        assert data["errors"] == []
        assert data["total_records_checked"] == 1
    finally:
        client.app.dependency_overrides.clear()
        client.close()


async def test_apply_policy(real_db: None) -> None:
    """Apply a saved policy to target scope."""
    client = _client()
    try:
        create_body = {"namespace": "payments", "agent_class": "planner", "rego_source": 'package norviq\ndefault decision = "allow"\ndecision = "block" { input.tool_name == "danger" }\nrule_id = "r"\nreason = "x"'}
        assert client.post("/api/v1/policies", json=create_body, headers=_auth_headers()).status_code == 200
        apply_body = {
            "target_type": "namespace",
            "target_namespace": "payments",
            "target_name": "",
            "target_kind": "",
            "enforcement_mode": "block",
        }
        response = client.post("/api/v1/policies/payments/planner/apply", json=apply_body, headers=_auth_headers())
        assert response.status_code == 200
        assert response.json()["applied"] is True
    finally:
        client.close()


def test_agents_list_and_update_trust() -> None:
    """Update trust score and list agent."""
    client = _client()
    try:
        spiffe = "spiffe://example/ns/default/sa/agent-one"
        updated = client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.61}, headers=_auth_headers())
        assert updated.status_code == 200
        listed = client.get("/api/v1/agents", headers=_auth_headers()).json()
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


def test_update_trust_requires_admin_role() -> None:
    """Reject trust updates for non-admin users."""
    client = _client()
    try:
        spiffe = "spiffe://example/ns/default/sa/agent-one"
        response = client.put(f"/api/v1/agents/{spiffe}/trust", json={"score": 0.4}, headers=_auth_headers(role="viewer"))
        assert response.status_code == 403
    finally:
        client.close()
