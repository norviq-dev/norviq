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
    """Returns the seeded agent classes for the distinct-agent_class query."""

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
    """The red-team router is admin-only — a viewer is 403 on catalog/suite/run/targets/report."""
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
    """A second suite run for a namespace already in-flight is rejected 409 with the in-flight run_id."""
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
    """Run-writer: the suite/target selection is scoped to REAL classes — synthetic/probe identities
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
    """With multiple seeded classes the suite iterates each, tags every row with its identity, and the
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
    """The target selector endpoint returns the namespace's real seeded classes."""
    client = _client(seeded=["finance-agent", "data-analyst"])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/targets?namespace=default", headers=headers).json()
    assert body["namespace"] == "default"
    assert body["targets"] == ["data-analyst", "finance-agent"]  # _seeded_classes sorts for determinism


def test_redteam_catalog() -> None:
    """The catalog is a list, each entry enriched with its ATLAS technique + OWASP control mapping."""
    app = create_app()
    app.state.evaluator = FakeEvaluator()
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    response = client.get("/api/v1/redteam/catalog", headers=headers)
    assert response.status_code == 200
    rows = response.json()
    assert isinstance(rows, list) and len(rows) == len(ATTACKS)
    by_id = {r["attack_id"]: r for r in rows}
    # Each row carries the techniques and controls the Compliance mapping lists its rule under.
    assert all(r["atlas_technique"] is None or r["atlas_technique"].startswith("AML.T") for r in rows)
    assert by_id["PI-001"]["owasp_control"] == "LLM01:2025" and by_id["PI-001"]["owasp_control_name"]
    # Compliance maps deny_sql_injection to LLM05:2025 Improper Output Handling. The old assertion
    # that SQL injection has no OWASP control encoded the category-name derivation, not the mapping.
    assert by_id["SQL-001"]["owasp_control"] == "LLM05:2025"


def test_redteam_suite_includes_efficacy_rollup() -> None:
    """The suite response carries the caught-vs-got-through efficacy roll-up (overall + per technique)."""
    client = _client(seeded=["finance-agent"])
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.post("/api/v1/redteam/suite", headers=headers).json()
    eff = body["efficacy"]
    assert set(eff["overall"]) == {
        "total", "caught", "would_block", "got_through", "proven_blocking_pct", "detected_pct",
    }
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

        # `.scalar()` backs the history-list COUNT query (pagination total).
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

    # The rows its summary describes: 27 caught, and two allow-expected attacks that were throttled
    # (non_enforcement, so not counted by the efficacy below, and not passes). This used to be ONE row,
    # `{"attack_id": "PI-001", "passed": True}`, under a summary of 29. The served pass figures are
    # derived from the rows now whenever a run has them, so the fixture has to be a run that can exist.
    caught = [{"attack_id": f"A-{i:02d}", "expected": "block", "actual": "block", "rule_id": "deny_sql_injection",
               "passed": True} for i in range(27)]
    throttled = [{"attack_id": aid, "expected": "allow", "actual": "block", "rule_id": "rate_limit_exceeded",
                  "passed": False} for aid in ("RL-001", "CE-002")]
    return RedTeamRun(
        id="run-abc", created_at=datetime(2026, 7, 6, tzinfo=timezone.utc), namespace="default",
        targets=["finance-agent"], total=29, passed=27, failed=2, pass_rate=93.1,
        results=caught + throttled,
        efficacy={"overall": {"total": 27, "caught": 27, "got_through": 0, "proven_blocking_pct": 100.0},
                  "by_technique": [], "by_owasp": [], "non_enforcement": 2, "excluded_synthetic": 0},
        created_by="admin",
    )


def test_redteam_results_latest_empty_state() -> None:
    """Honest empty state when no run has been persisted yet."""
    client = _results_client(None)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results/latest", headers=headers).json()
    assert body == {"has_run": False}


def test_redteam_results_latest_and_by_id() -> None:
    """The latest durable run is returned with its efficacy roll-up; by-id reads the same row."""
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
    """The history list returns run SUMMARIES ONLY (no per-attack rows), newest-first, bounded."""
    client = _results_client(_sample_run())
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results?limit=5", headers=headers).json()
    assert body["total"] == 1
    assert body["offset"] == 0 and body["limit"] == 5  # bounded + paginated envelope
    run = body["runs"][0]
    assert run["run_id"] == "run-abc"
    assert run["proven_blocking_pct"] == 100.0
    assert "results" not in run  # summary only — never per-attack detail in the history list


def test_redteam_by_id_flags_detail_pruned_run() -> None:
    """A run whose per-attack detail was retention-pruned (results IS NULL) returns detail_pruned=true with
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
    # `reason` joined the flat payload in F-034. Stated here rather than loosened to a subset check,
    # because an exact-shape assertion is what makes this a contract test — the next field to appear
    # should have to come here and be justified too.
    assert response.json() == {
        "decision": "block", "rule_id": "deny_sql_injection", "trust_score": 0.41, "reason": "",
    }


def test_evaluate_returns_the_authored_reason() -> None:
    """F-034: the engine REQUIRES a `reason` rule at author time — a policy without one is refused
    with a 422 — and then /evaluate dropped its value. The operator wrote the sentence, the product
    insisted on it, and the caller never saw it.

    It is the half a human reads: `deny_shell_execution` says which rule fired, "shell metacharacters
    are not permitted in ticket bodies" says why the author cared.
    """
    class _WithReason:
        async def evaluate(self, event):
            _ = event
            return PolicyDecision(
                decision="block", rule_id="deny_sql_injection", trust_score=0.41,
                reason="SQL metacharacters are not permitted in this field",
            )

    app = create_app()
    app.state.evaluator = _WithReason()
    client = TestClient(app)
    payload = {
        "tool_name": "execute_sql",
        "tool_params": {"query": "SELECT * FROM x"},
        "agent_identity": {
            "spiffe_id": "spiffe://norviq/ns/default/sa/customer-support",
            "namespace": "default", "agent_class": "customer-support",
        },
        "session_id": "redteam-test",
    }
    body = client.post(
        "/api/v1/evaluate", json=payload, headers={"Authorization": f"Bearer {_token()}"}
    ).json()
    assert body["reason"] == "SQL metacharacters are not permitted in this field"
    assert body["rule_id"] == "deny_sql_injection"  # rule_id still works; this is additive


# --- F-014: a scan that measures the wrong scope must refuse, not report ------------------------

def test_an_unknown_query_param_is_refused_not_ignored() -> None:
    """`namespace=` and `agent_class=` are the names an operator reaches for.

    FastAPI drops undeclared query params, so the suite ran against `default` — which on most
    installs has no baseline — and returned a pass_rate of 5.9% for a namespace that was actually at
    82.4%. The operator has no way to distinguish that from a real result, and acts on the number.
    """
    client = _client()
    headers = {"Authorization": f"Bearer {_token()}"}
    resp = client.post("/api/v1/redteam/suite?namespace=chatbot-lab", headers=headers)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "namespace" in detail
    # The error must name the parameters that DO work, since the failure is a plausible wrong name.
    assert "target_namespace" in detail and "target_agent" in detail


def test_a_misspelled_target_param_is_refused() -> None:
    client = _client()
    resp = client.post(
        "/api/v1/redteam/suite?target_namesapce=chatbot-lab",
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert resp.status_code == 422


def test_the_correct_params_still_work() -> None:
    """The guard must not reject the documented spelling — that would be a worse bug than the one
    it fixes, since it would make the endpoint unusable rather than merely misleading."""
    client = _client()
    resp = client.post(
        "/api/v1/redteam/suite?target_namespace=default&target_agent=support-agent",
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert resp.status_code == 200


def test_the_report_states_what_it_measured() -> None:
    """A pass_rate without its scope is how 5.9% got read as 'the controls are broken' when it meant
    'this scope is empty'. The two now travel together."""
    client = _client()
    body = client.post(
        "/api/v1/redteam/suite?target_namespace=default",
        headers={"Authorization": f"Bearer {_token()}"},
    ).json()
    scope = body["scope"]
    assert scope["namespace"] == "default"
    assert isinstance(scope["agent_classes"], list)
    # The honest distinction: "we tested and it is bad" vs "there was nothing here to test".
    assert "scope_empty" in scope and "policy_rules_loaded" in scope
    assert scope["scope_empty"] is not scope["policy_rules_loaded"]


def test_a_fallback_target_is_declared_as_such() -> None:
    """With no real agent class seeded, the synthetic `redteam-test` identity is scored — which is a
    fact about the measurement, not about the operator's deployment."""
    client = _client(seeded=[])
    body = client.post(
        "/api/v1/redteam/suite?target_namespace=default",
        headers={"Authorization": f"Bearer {_token()}"},
    ).json()
    assert body["scope"]["targets_are_fallback"] is True


# --- Every served row carries the verdict the scorecard counted -----------------------------------
#
# The console filtered "got through" with its own `!passed && applicable !== false`, while the
# scorecard above it counted `compute_efficacy`'s verdict. A throttled block passes (actual == expected)
# and is a got-through, so a kind run with 17 `block / rate_limit_exceeded` red-team rows showed
# "got through > 0" over a filter that listed none. The row now says what it was counted as.

class _ThrottlingEvaluator:
    """Every call refused by the rate limiter — what a suite driven hard enough sees."""

    async def evaluate(self, event) -> PolicyDecision:
        _ = event
        return PolicyDecision(decision="block", rule_id="rate_limit_exceeded", trust_score=0.5)


def test_a_throttled_suite_serves_the_got_through_rows_it_counted() -> None:
    app = create_app()
    app.state.evaluator = _ThrottlingEvaluator()
    session = _FakeSession(["finance-agent"])

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.post("/api/v1/redteam/suite", headers=headers).json()

    rows = body["results"]
    assert rows and all("outcome" in r for r in rows)
    got_through = [r for r in rows if r["outcome"] == "got_through"]
    assert len(got_through) == body["efficacy"]["overall"]["got_through"] > 0
    # `passed` used to be True on every one of them (actual block == expected block), which is what
    # let the table hide them and the "Suite pass-rate" count them. It agrees with the outcome now:
    # nothing in a suite the limiter refused end to end passed.
    assert not any(r["passed"] for r in got_through)
    assert (body["passed"], body["pass_rate"]) == (0, 0.0)

    # The in-process fallbacks serve the same verdicts — the cached report itself stays raw. The
    # by-id route reads the in-process cache only when the DB has no such run, hence the empty session.
    for c, path in (
        (client, f"/api/v1/redteam/report/{body['run_id']}"),
        (_results_client(None), f"/api/v1/redteam/results/{body['run_id']}"),
    ):
        again = c.get(path, headers=headers).json()["results"]
        assert [r["outcome"] for r in again] == [r["outcome"] for r in rows], path
    from norviq.api.routers import redteam as rt
    assert all("outcome" not in r for r in rt.REPORTS[body["run_id"]]["results"])


def test_results_latest_annotates_rows_stored_before_the_field_existed() -> None:
    """Computed on read: a durable run written without `outcome` on its rows gets one, and filtering
    on it reproduces the stored efficacy exactly."""
    from datetime import datetime, timezone

    from norviq.api.db.models import RedTeamRun
    from norviq.api.redteam_efficacy import compute_efficacy

    def row(aid, cls, expected, actual, rule_id, applicable=True):
        return {"attack_id": aid, "agent_class": cls, "namespace": "default", "expected": expected,
                "actual": actual, "rule_id": rule_id, "passed": actual == expected, "applicable": applicable,
                "atlas_technique": "AML.T0048", "atlas_technique_name": "T"}

    stored = [
        row("SQL-001", "finance-agent", "block", "block", "deny_sql_injection"),
        row("PI-001", "finance-agent", "block", "block", "rate_limit_exceeded"),
        row("PII-001", "finance-agent", "block", "audit", "pii_detection"),
        row("EA-001", "finance-agent", "block", "allow", "default_allow"),
        row("FIN-001", "finance-agent", "block", "allow", "default_allow", applicable=False),
        row("RL-001", "finance-agent", "allow", "block", "rate_limit_exceeded"),
        row("SH-001", "scorer", "block", "allow", "default_allow"),
    ]
    run = RedTeamRun(
        id="run-legacy", created_at=datetime(2026, 7, 6, tzinfo=timezone.utc), namespace="default",
        targets=["finance-agent"], total=len(stored), passed=2, failed=5, pass_rate=28.6,
        results=stored, efficacy=compute_efficacy(stored), created_by="admin",
    )
    client = _results_client(run)
    headers = {"Authorization": f"Bearer {_token()}"}
    body = client.get("/api/v1/redteam/results/latest", headers=headers).json()

    by_id = {r["attack_id"]: r["outcome"] for r in body["results"]}
    assert by_id == {
        "SQL-001": "caught", "PI-001": "got_through", "PII-001": "would_block", "EA-001": "got_through",
        "FIN-001": "not_enabled", "RL-001": "non_enforcement", "SH-001": "synthetic",
    }
    overall = body["efficacy"]["overall"]
    for outcome in ("caught", "would_block", "got_through"):
        assert sum(1 for o in by_id.values() if o == outcome) == overall[outcome], outcome
    # by-id serves the same rows the same way
    again = client.get("/api/v1/redteam/results/run-legacy", headers=headers).json()
    assert {r["attack_id"]: r["outcome"] for r in again["results"]} == by_id


def test_a_single_attack_run_carries_its_outcome() -> None:
    app = create_app()
    app.state.evaluator = _ThrottlingEvaluator()
    client = TestClient(app)
    body = client.post(
        "/api/v1/redteam/run?attack_id=PI-001&target_agent=finance-agent",
        headers={"Authorization": f"Bearer {_token()}"},
    ).json()
    # `passed` was True here, beside an outcome of got_through. A throttle met the block expectation
    # by accident; it is not a pass, and the row no longer says two things.
    assert body["passed"] is False and body["outcome"] == "got_through"


# --- The suite pass-rate counts what the scorecard counts -----------------------------------------
#
# "Suite pass-rate" on the console is `pass_rate` from the API, and `passed` was `actual == expected`.
# A throttled or faulted block met a block expectation, so it raised the pass rate while the scorecard
# beside it counted the same row as got_through.

class _MixedEvaluator:
    """Real blocks for SQL-*, throttles for PI-*, engine timeouts for EA-*, allow for everything else."""

    async def evaluate(self, event) -> PolicyDecision:
        aid = event.session_id.removeprefix("redteam-")
        if aid.startswith("SQL-"):
            return PolicyDecision(decision="block", rule_id="deny_sql_injection", trust_score=0.5)
        if aid.startswith("PI-"):
            return PolicyDecision(decision="block", rule_id="rate_limit_exceeded", trust_score=0.5)
        if aid.startswith("EA-"):
            return PolicyDecision(decision="block", rule_id="evaluator_timeout", trust_score=0.5)
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.5)


def test_suite_pass_rate_does_not_count_a_throttled_or_faulted_block() -> None:
    app = create_app()
    app.state.evaluator = _MixedEvaluator()
    session = _FakeSession(["finance-agent"])

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    body = TestClient(app).post("/api/v1/redteam/suite", headers={"Authorization": f"Bearer {_token()}"}).json()

    rows = body["results"]
    passed = sorted(r["attack_id"] for r in rows if r["passed"])
    # The three real blocks, and the two attacks that expect an allow and got one. Before: PI-001..003
    # and EA-001..003 as well, 11/34 = 32.4% against a scorecard of 3 caught.
    assert passed == ["CE-002", "RL-001", "SQL-001", "SQL-002", "SQL-003"]
    assert (body["passed"], body["failed"], body["pass_rate"]) == (5, len(rows) - 5, round(5 / len(rows) * 100, 1))
    assert not [r["attack_id"] for r in rows if r["passed"] and r["outcome"] == "got_through"]
    assert body["efficacy"]["overall"]["caught"] == 3


def test_a_run_stored_before_the_fix_serves_the_corrected_pass_rate() -> None:
    """Computed on read, like `outcome`: rows written with the old `passed` serve the new one, and
    the run's pass figures are derived from them. Only a detail-pruned run, which has no rows left,
    keeps the numbers it was written with."""
    from datetime import datetime, timezone

    from norviq.api.db.models import RedTeamRun

    def row(aid, expected, actual, rule_id):
        return {"attack_id": aid, "agent_class": "finance-agent", "namespace": "default", "expected": expected,
                "actual": actual, "rule_id": rule_id, "passed": actual == expected, "applicable": True,
                "atlas_technique": "AML.T0048", "atlas_technique_name": "T"}

    stored = [
        row("SQL-001", "block", "block", "deny_sql_injection"),
        row("PI-001", "block", "block", "rate_limit_exceeded"),
        row("EA-001", "block", "block", "evaluator_timeout"),
        row("CE-001", "block", "allow", "default_allow"),
    ]
    run = RedTeamRun(
        id="run-before", created_at=datetime(2026, 7, 6, tzinfo=timezone.utc), namespace="default",
        targets=["finance-agent"], total=4, passed=3, failed=1, pass_rate=75.0,
        results=stored, efficacy={}, created_by="admin",
    )
    client = _results_client(run)
    headers = {"Authorization": f"Bearer {_token()}"}
    for path in ("/api/v1/redteam/results/latest", "/api/v1/redteam/results/run-before"):
        body = client.get(path, headers=headers).json()
        assert {r["attack_id"]: r["passed"] for r in body["results"]} == {
            "SQL-001": True, "PI-001": False, "EA-001": False, "CE-001": False,
        }, path
        assert (body["total"], body["passed"], body["failed"], body["pass_rate"]) == (4, 1, 3, 25.0), path
    summary = client.get("/api/v1/redteam/results", headers=headers).json()["runs"][0]
    assert (summary["passed"], summary["failed"], summary["pass_rate"]) == (1, 3, 25.0)
