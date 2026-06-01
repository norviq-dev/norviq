# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API tests for red-team routes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.main import create_app
from norviq.sdk.core.decisions import PolicyDecision


class FakeEvaluator:
    """Evaluator stub for /api/v1/evaluate route tests."""

    async def evaluate(self, event) -> PolicyDecision:
        """Return deterministic policy decision."""
        _ = event
        return PolicyDecision(decision="block", rule_id="deny_sql_injection", trust_score=0.41)


def _token() -> str:
    """Create admin auth token."""
    from jose import jwt

    from norviq.config import settings

    return jwt.encode({"sub": "test", "role": "admin"}, settings.api_secret_key, algorithm="HS256")


def test_redteam_suite_report_round_trip() -> None:
    """Run suite and fetch saved report."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.post("/api/v1/redteam/suite", headers=headers)
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    report = client.get(f"/api/v1/redteam/report/{run_id}", headers=headers)
    assert report.status_code == 200
    assert report.json()["total"] >= 25


def test_redteam_catalog() -> None:
    """Return attack catalog list."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.get("/api/v1/redteam/catalog", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_redteam_run_calls_in_process_evaluator() -> None:
    """Run one red-team attack through in-process evaluator."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.post("/api/v1/redteam/run?attack_id=PI-001", headers=headers)
    assert response.status_code == 200
    assert response.json()["actual"] == "block"
    assert response.json()["attack_id"] == "PI-001"


def test_evaluate_route_returns_flat_response() -> None:
    """Return flat decision payload from evaluator result."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    payload = {
        "tool_name": "execute_sql",
        "tool_params": {"query": "SELECT * FROM x"},
        "agent_identity": {
            "spiffe_id": "spiffe://norviq/ns/default/sa/customer-support",
            "namespace": "default",
            "agent_class": "customer-support",
        },
        "session_id": "redteam-test",
    }
    response = client.post("/api/v1/evaluate", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"decision": "block", "rule_id": "deny_sql_injection", "trust_score": 0.41}
