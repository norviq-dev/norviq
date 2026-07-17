# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F046: GET /api/v1/coverage-by-category cross-references the category->rule taxonomy with the rego
actually loaded for a namespace. Covers happy (some rules present), empty (no policy loaded -> 0), and auth."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

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
    return jwt.encode(
        {"sub": "u", "role": "admin", "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


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
    # ACCURACY: only categories with a rule loaded are IN SCOPE; un-enabled sectors are "available", not gaps.
    assert cats["Tool Safety"]["in_scope"] is True and cats["Data Protection"]["in_scope"] is True
    assert cats["Prompt Injection"]["in_scope"] is False  # no rule loaded -> not a 0% gap, just not enabled
    # coverage_pct is over IN-SCOPE only (Tool Safety 1/3 + Data Protection 1/3 = 2/6 = 33%), NOT diluted by
    # every sector the product ships (which would have made this ~9%).
    assert body["coverage_pct"] == 33
    assert body["available"] == sum(1 for c in body["categories"] if not c["in_scope"])
    assert body["available"] >= 1


def test_coverage_empty_when_no_policy_loaded() -> None:
    client = _client({})  # nothing loaded
    resp = client.get("/api/v1/coverage-by-category?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["coverage_pct"] == 0
    assert all(c["covered"] == 0 and c["score"] == 0 for c in body["categories"])
    assert len(body["categories"]) >= 1  # the taxonomy still lists every category (empty, not fabricated)
    # nothing loaded -> nothing in scope -> every category is "available", none is a 0% gap.
    assert all(c["in_scope"] is False for c in body["categories"])
    assert body["available"] == len(body["categories"])


def test_coverage_namespace_isolation() -> None:
    # rego loaded only for a DIFFERENT namespace -> requested namespace shows zero coverage.
    rego = 'rule_id = "deny_sql_injection" { x }'
    client = _client({"other:agent": {"rego": rego, "priority": 700}})
    resp = client.get("/api/v1/coverage-by-category?namespace=default", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.json()["coverage_pct"] == 0


def test_coverage_requires_auth() -> None:
    client = _client({})
    assert client.get("/api/v1/coverage-by-category").status_code in (401, 403)


def test_coverage_includes_agent_class_section_key() -> None:
    # The response always carries the agent-class dimension (empty when no per-class policy is applied)
    # so the Overview can render it — the fake session has no policies table → empty list, no 500.
    client = _client({})
    body = client.get("/api/v1/coverage-by-category?namespace=default",
                      headers={"Authorization": f"Bearer {_token()}"}).json()
    assert "agent_class_policies" in body and body["agent_class_policies"] == []
    assert body["namespace_mode"] in ("block", "audit")


# --- _parse_agent_policy: what an APPLIED agent-class policy enforces (pure, no DB) ------------------

def test_parse_intent_policy_extracts_allowlist_refinements_learned() -> None:
    from norviq.api.routers.coverage import _parse_agent_policy
    rego = (
        "package norviq.intent.report_gen\n"
        "# Allowlist (1 tools): warehouse_task\n"
        "# Learned verbs (admin-promoted, override the name heuristic): warehouse_task=delete\n"
        'allow_names := {"warehouse_task"}\n'
        'read_verbs := {"read"}\n'
        "is_read { read_verbs[tool_verb] }\n"
    )
    s = _parse_agent_policy("report-gen", rego, priority=100, mode="block")
    assert s["kind"] == "intent"
    assert s["allow_tools"] == ["warehouse_task"]
    assert "readonly" in s["refinements"]            # is_read present ⇒ Read-only toggle on
    assert "egress" not in s["refinements"]          # no is_egress ⇒ toggle off
    assert s["learned_verbs"] == ["warehouse_task=delete"]


def test_parse_custom_policy_degrades_gracefully() -> None:
    from norviq.api.routers.coverage import _parse_agent_policy
    s = _parse_agent_policy("batch", 'package foo.bar\nrule_id = "x" { true }', priority=500, mode="audit")
    assert s["kind"] == "custom"
    assert s["allow_tools"] == []
    assert s["refinements"] == []
    assert s["enforcement_mode"] == "audit"


def test_parse_capability_policy_kind() -> None:
    from norviq.api.routers.coverage import _parse_agent_policy
    s = _parse_agent_policy("etl", "package norviq.remediation.capability.pg_delete_etl\n", priority=100, mode="block")
    assert s["kind"] == "capability"
