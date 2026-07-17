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
    import time

    import jwt

    from norviq.config import settings

    return jwt.encode(
        {"sub": "test", "role": role, "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


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


def test_redteam_suite_concurrent_run_rejected() -> None:
    """D1: a second suite run for a namespace already in-flight is rejected 409 with the in-flight run_id."""
    from norviq.api.routers import redteam as rt

    client = _client(seeded=["finance-agent"])
    headers = {"Authorization": f"Bearer {_token()}"}
    rt._INFLIGHT_SUITES["default"] = "run-already-going"
    try:
        resp = client.post("/api/v1/redteam/suite?target_namespace=default", headers=headers)
        assert resp.status_code == 409
        assert resp.json()["detail"]["run_id"] == "run-already-going"
        # a DIFFERENT namespace is not blocked by the default in-flight
        other = client.post("/api/v1/redteam/suite?target_namespace=payments", headers=headers)
        assert other.status_code == 200
    finally:
        rt._INFLIGHT_SUITES.pop("default", None)
    # once cleared, default runs again (and clears itself on completion)
    assert client.post("/api/v1/redteam/suite?target_namespace=default", headers=headers).status_code == 200
    assert "default" not in rt._INFLIGHT_SUITES  # released in finally


def test_redteam_seeded_targets_exclude_synthetic() -> None:
    """D2 run-writer: the suite/target selection is scoped to REAL classes — synthetic/probe identities
    (allowlist-probe-*, scorer, policy-tester, …) are excluded so a run never stores the full synthetic matrix."""
    seeded = ["finance-agent", "allowlist-probe-abc123", "scorer", "policy-tester", "data-analyst", "probe-xyz"]
    client = _client(seeded=seeded)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/targets?namespace=default", headers=headers).json()
    assert body["targets"] == ["data-analyst", "finance-agent"]  # only the two real classes, sorted
    # and a full-namespace suite run only evaluates those real classes
    run = client.post("/api/v1/redteam/suite?target_namespace=default", headers=headers).json()
    assert set(run["targets"]) == {"data-analyst", "finance-agent"}
    assert run["total"] == len(ATTACKS) * 2  # not len(ATTACKS) * 6


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
    """B1: the catalog is a list, each entry enriched with its ATLAS technique + OWASP control mapping."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.get("/api/v1/redteam/catalog", headers=headers)
    assert response.status_code == 200
    rows = response.json()
    assert isinstance(rows, list) and len(rows) == len(ATTACKS)
    by_id = {r["attack_id"]: r for r in rows}
    # every row carries an ATLAS technique; an OWASP attack also carries its control
    assert all(r["atlas_technique"].startswith("AML.T") for r in rows)
    assert by_id["PI-001"]["owasp_control"] == "LLM01:2025" and by_id["PI-001"]["owasp_control_name"]
    assert by_id["SQL-001"]["owasp_control"] is None  # SQL injection has no OWASP LLM control


def test_redteam_suite_includes_efficacy_rollup() -> None:
    """B3: the suite response carries the caught-vs-got-through efficacy roll-up (overall + per technique)."""
    client = _client(seeded=["finance-agent"])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.post("/api/v1/redteam/suite", headers=headers).json()
    eff = body["efficacy"]
    assert set(eff["overall"]) == {"total", "caught", "got_through", "proven_blocking_pct"}
    # FakeEvaluator always blocks → every block-expected attack is caught → 100% proven-blocking
    assert eff["overall"]["got_through"] == 0
    assert eff["overall"]["proven_blocking_pct"] == 100.0
    assert any(t["technique_id"].startswith("AML.T") for t in eff["by_technique"])


class _ResultsSession:
    """Fake session that returns a preset RedTeamRun (or None) for the results queries."""

    def __init__(self, row) -> None:
        self.row = row

    async def execute(self, stmt):
        row = self.row

        class _Scalars:
            def first(self_inner):
                return row

            def all(self_inner):
                return [row] if row else []

        # `.scalar()` backs the history-list COUNT query (D3 pagination total).
        return SimpleNamespace(scalars=lambda: _Scalars(), scalar=lambda: (1 if row else 0))

    async def close(self) -> None:
        return None


def _results_client(row) -> TestClient:
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    session = _ResultsSession(row)

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _sample_run():
    from datetime import datetime, timezone

    from norviq.api.db.models import RedTeamRun

    return RedTeamRun(
        id="run-abc", created_at=datetime(2026, 7, 6, tzinfo=timezone.utc), namespace="default",
        targets=["finance-agent"], total=29, passed=27, failed=2, pass_rate=93.1,
        results=[{"attack_id": "PI-001", "passed": True}],
        efficacy={"overall": {"total": 27, "caught": 27, "got_through": 0, "proven_blocking_pct": 100.0},
                  "by_technique": [], "by_owasp": [], "non_enforcement": 2, "excluded_synthetic": 0},
        created_by="admin",
    )


def test_redteam_results_latest_empty_state() -> None:
    """B2: honest empty state when no run has been persisted yet."""
    client = _results_client(None)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results/latest", headers=headers).json()
    assert body == {"has_run": False}


def test_redteam_results_latest_and_by_id() -> None:
    """B2/B3: the latest durable run is returned with its efficacy roll-up; by-id reads the same row."""
    client = _results_client(_sample_run())
    headers = {"Authorization": f"Bearer {_token()}"}
    latest = client.get("/api/v1/redteam/results/latest", headers=headers).json()
    assert latest["has_run"] is True
    assert latest["run_id"] == "run-abc"
    assert latest["efficacy"]["overall"]["proven_blocking_pct"] == 100.0
    assert latest["created_at"].startswith("2026-07-06")
    by_id = client.get("/api/v1/redteam/results/run-abc", headers=headers).json()
    assert by_id["run_id"] == "run-abc" and by_id["pass_rate"] == 93.1


def test_redteam_results_history_list() -> None:
    """B2/F1/D3: the history list returns run SUMMARIES ONLY (no per-attack rows), newest-first, bounded."""
    client = _results_client(_sample_run())
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results?limit=5", headers=headers).json()
    assert body["total"] == 1
    assert body["offset"] == 0 and body["limit"] == 5  # D3: bounded + paginated envelope
    run = body["runs"][0]
    assert run["run_id"] == "run-abc"
    assert run["proven_blocking_pct"] == 100.0
    assert "results" not in run  # D3: summary only — never per-attack detail in the history list


def test_redteam_by_id_flags_detail_pruned_run() -> None:
    """D3: a run whose per-attack detail was retention-pruned (results IS NULL) returns detail_pruned=true with
    an empty results list, but keeps its summary (efficacy)."""
    from datetime import datetime, timezone

    from norviq.api.db.models import RedTeamRun

    pruned = RedTeamRun(
        id="run-old", created_at=datetime(2026, 6, 1, tzinfo=timezone.utc), namespace="default",
        targets=["finance-agent"], total=29, passed=27, failed=2, pass_rate=93.1,
        results=None,  # detail-pruned
        efficacy={"overall": {"total": 27, "caught": 27, "got_through": 0, "proven_blocking_pct": 100.0},
                  "by_technique": [], "by_owasp": [], "non_enforcement": 2, "excluded_synthetic": 0},
        created_by="admin",
    )
    client = _results_client(pruned)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results/run-old", headers=headers).json()
    assert body["detail_pruned"] is True
    assert body["results"] == []
    assert body["efficacy"]["overall"]["proven_blocking_pct"] == 100.0  # summary intact


def test_redteam_results_are_admin_only() -> None:
    """The durable results endpoints are admin-only like the rest of the red-team router."""
    client = _results_client(None)
    vh = {"Authorization": f"Bearer {_token('viewer')}"}
    assert client.get("/api/v1/redteam/results/latest", headers=vh).status_code == 403
    assert client.get("/api/v1/redteam/results/anything", headers=vh).status_code == 403


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
