# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F046: GET /api/v1/coverage-by-category cross-references the category->rule taxonomy with the rego
actually loaded for a namespace. Covers happy (some rules present), empty (no policy loaded -> 0), and auth."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient
from jose import jwt

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Empty audit store -> the efficacy overlay reports 0 observed/blocked (best-effort)."""

    async def execute(self, stmt):
        _ = stmt
        return SimpleNamespace(all=lambda: [])

    async def close(self) -> None:
        return None


def _client(policies: dict[str, dict]) -> TestClient:
    app = create_app()
    app.state.loader = SimpleNamespace(_policies=policies)

    async def _override():
        yield _FakeSession()

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token() -> str:
    return jwt.encode({"sub": "u", "role": "admin"}, settings.api_secret_key, algorithm="HS256")


def test_coverage_happy_reflects_loaded_rules() -> None:
    # A rego blob that enforces SQL injection (Tool Safety) + PII (Data Protection) for default.
    rego = 'rule_id = "deny_sql_injection" { x }\nrule_id = "pii_detection" { y }'
    client = _client({"default:customer-support": {"rego": rego, "priority": 700}})
    resp = client.get("/api/v1/coverage-by-category?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    cats = {c["category"]: c for c in body["categories"]}
    # deny_sql_injection is 1 of 3 Tool Safety rules -> 33%; pii_detection 1 of 3 Data Protection -> 33%.
    assert cats["Tool Safety"]["covered"] == 1 and cats["Tool Safety"]["score"] == 33
    assert cats["Data Protection"]["covered"] == 1
    assert cats["Prompt Injection"]["covered"] == 0
    assert 0 < body["coverage_pct"] < 100
    # F-44/F-45 honesty: score is presence, declared by basis; the efficacy overlay is present (0 with no audit).
    assert body["basis"] == "rules_present"
    assert cats["Data Protection"]["effective"] is False  # rule present but no blocked traffic -> not proven
    assert all("observed" in c and "blocked" in c for c in body["categories"])


def test_coverage_empty_when_no_policy_loaded() -> None:
    client = _client({})  # nothing loaded
    resp = client.get("/api/v1/coverage-by-category?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["coverage_pct"] == 0
    assert all(c["covered"] == 0 and c["score"] == 0 for c in body["categories"])
    assert len(body["categories"]) >= 1  # the taxonomy still lists every category (empty, not fabricated)


def test_coverage_namespace_isolation() -> None:
    # rego loaded only for a DIFFERENT namespace -> requested namespace shows zero coverage.
    rego = 'rule_id = "deny_sql_injection" { x }'
    client = _client({"other:agent": {"rego": rego, "priority": 700}})
    resp = client.get("/api/v1/coverage-by-category?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.json()["coverage_pct"] == 0


def test_coverage_requires_auth() -> None:
    client = _client({})
    assert client.get("/api/v1/coverage-by-category").status_code in (401, 403)
