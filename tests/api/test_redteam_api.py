# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API tests for red-team routes."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.redteam.attacks import ATTACKS
from norviq.sdk.core.decisions import PolicyDecision


class FakeEvaluator:
    """Evaluator stub for /api/v1/evaluate route tests."""

    async def evaluate(self, event) -> PolicyDecision:
        """Return deterministic policy decision."""
        _ = event
        return PolicyDecision(decision="block", rule_id="deny_sql_injection", trust_score=0.41)


class _FakeSession:
    """Returns the seeded agent classes for the distinct-agent_class query (F-44)."""

    def __init__(self, classes: list[str]) -> None:
        self.classes = classes

    async def execute(self, stmt):
        _ = stmt  # only the distinct-agent_class query is issued by the redteam router
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(self.classes)))

    async def close(self) -> None:
        return None


def _client(seeded: list[str] | None = None) -> TestClient:
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    session = _FakeSession(seeded if seeded is not None else [])

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token(role: str = "admin") -> str:
    """Create an auth token for the given role."""
    from jose import jwt

    from norviq.config import settings

    return jwt.encode({"sub": "test", "role": role}, settings.api_secret_key, algorithm="HS256")


def test_redteam_endpoints_are_admin_only() -> None:
    """F-43: the red-team router is admin-only — a viewer is 403 on catalog/suite/run/targets/report."""
    client = _client(seeded=["finance-agent"])
    vh = {"Authorization": f"Bearer {_token('viewer')}"}
    assert client.get("/api/v1/redteam/catalog", headers=vh).status_code == 403
    assert client.post("/api/v1/redteam/suite", headers=vh).status_code == 403
    assert client.post("/api/v1/redteam/run?attack_id=PI-001", headers=vh).status_code == 403
    assert client.get("/api/v1/redteam/targets", headers=vh).status_code == 403
    # admin still works
    assert client.get("/api/v1/redteam/catalog", headers={"Authorization": f"Bearer {_token('admin')}"}).status_code == 200


def test_redteam_suite_report_round_trip() -> None:
    """Run suite and fetch saved report."""
    client = _client(seeded=["finance-agent"])
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.post("/api/v1/redteam/suite", headers=headers)
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    report = client.get(f"/api/v1/redteam/report/{run_id}", headers=headers)
    assert report.status_code == 200
    assert report.json()["total"] >= 25


def test_redteam_suite_is_target_aware() -> None:
    """F-44: with multiple seeded classes the suite iterates each, tags every row with its identity, and the
    report lists the evaluated targets — proving it is not the old fixed redteam-test/default identity."""
    client = _client(seeded=["finance-agent", "data-analyst"])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.post("/api/v1/redteam/suite", headers=headers).json()
    assert body["targets"] == ["data-analyst", "finance-agent"]  # _seeded_classes sorts for determinism
    assert body["total"] == len(ATTACKS) * 2
    assert {r["agent_class"] for r in body["results"]} == {"finance-agent", "data-analyst"}
    assert all("agent_class" in r and "namespace" in r for r in body["results"])


def test_redteam_suite_falls_back_when_no_seeded_classes() -> None:
    """No seeded agents -> synthetic fallback so the suite still runs (never the iterate-nothing empty report)."""
    client = _client(seeded=[])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.post("/api/v1/redteam/suite", headers=headers).json()
    assert body["targets"] == ["redteam-test"]
    assert body["total"] == len(ATTACKS)


def test_redteam_targets_lists_seeded_classes() -> None:
    """F-44: the target selector endpoint returns the namespace's real seeded classes."""
    client = _client(seeded=["finance-agent", "data-analyst"])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/targets?namespace=default", headers=headers).json()
    assert body["namespace"] == "default"
    assert body["targets"] == ["data-analyst", "finance-agent"]  # _seeded_classes sorts for determinism


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
