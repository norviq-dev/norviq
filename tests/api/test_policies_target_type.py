# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""GET /api/v1/policies must return a target_type per policy so the UI catalog can
group class / namespace / workload tiers (the seeded class policy was rendering nowhere)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.main import create_app
from norviq.api.routers.policies import _infer_target_type


def test_infer_target_type_for_each_shape() -> None:
    """Pure classifier: class vs namespace (baseline/cluster/namespace:) vs workload (kind:name)."""
    assert _infer_target_type("default", "customer-support") == "class"
    assert _infer_target_type("default", "__baseline__") == "namespace"
    assert _infer_target_type("__cluster__", "__baseline__") == "namespace"
    assert _infer_target_type("default", "namespace:default") == "namespace"
    assert _infer_target_type("default", "deployment:checkout") == "workload"
    assert _infer_target_type("default", "statefulset:ledger") == "workload"


class _StubLoader:
    """Minimal loader exposing the in-memory policy map list_policies reads."""

    def __init__(self, policies: dict[str, dict]) -> None:
        self._policies = policies

    def get_versions(self, namespace: str, agent_class: str):
        return []


def _client_with_policies(policies: dict[str, dict]) -> TestClient:
    app = create_app()
    app.state.loader = _StubLoader(policies)
    # list_policies now requires auth; inject an admin user via dependency override.
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default"}
    return TestClient(app)


def test_list_policies_returns_target_type_per_shape() -> None:
    """Endpoint tags each loaded policy with the correct tier and stays namespace-scoped."""
    client = _client_with_policies(
        {
            "default:customer-support": {"rego": "x" * 5504, "priority": 700},
            "default:namespace:default": {"rego": "y", "priority": 50},
            "default:deployment:checkout": {"rego": "z", "priority": 900},
            "default:__baseline__": {"rego": "b", "priority": 10},
            "other:summarizer": {"rego": "o", "priority": 100},  # different ns -> excluded
        }
    )
    resp = client.get("/api/v1/policies?namespace=default")
    assert resp.status_code == 200
    rows = {r["agent_class"]: r for r in resp.json()}

    assert rows["customer-support"]["target_type"] == "class"
    assert rows["namespace:default"]["target_type"] == "namespace"
    assert rows["deployment:checkout"]["target_type"] == "workload"
    assert rows["__baseline__"]["target_type"] == "namespace"
    # namespace filter: a policy from another namespace must not leak in.
    assert "summarizer" not in rows
    # existing fields preserved.
    assert rows["customer-support"]["priority"] == 700
    assert rows["customer-support"]["rego_length"] == 5504


class _VersionStub:
    """A minimal PolicyVersion-shaped object for the versions-endpoint test."""

    def __init__(self, version: int, rego_source: str, saved_by: str) -> None:
        self.version = version
        self.rego_source = rego_source
        self.saved_by = saved_by
        from datetime import datetime, timezone

        self.saved_at = datetime(2026, 7, 11, tzinfo=timezone.utc)


class _VersionLoader:
    def __init__(self, versions: list[_VersionStub]) -> None:
        self._versions = versions

    def get_versions(self, namespace: str, agent_class: str):
        return self._versions


def test_versions_endpoint_returns_per_version_rego() -> None:
    """Each version row carries its OWN rego_source so the console can inspect a
    historical version read-only."""
    app = create_app()
    app.state.loader = _VersionLoader(
        [
            _VersionStub(1, "package norviq.v1\n", "alice"),
            _VersionStub(2, "package norviq.v2\n", "bob"),
        ]
    )
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default"}
    client = TestClient(app)
    resp = client.get("/api/v1/policies/default/customer-support/versions")
    assert resp.status_code == 200
    rows = resp.json()
    assert [r["version"] for r in rows] == [1, 2]
    # the NEW field: each row's distinct rego is present (not the current policy's for every row).
    assert rows[0]["rego_source"] == "package norviq.v1\n"
    assert rows[1]["rego_source"] == "package norviq.v2\n"
    assert rows[0]["saved_by"] == "alice"


# --------------------------------------------------------------------------------------------------
# `matches` must be resolved against the tier the policy actually governs
# --------------------------------------------------------------------------------------------------

_AUDIT = {("payments", "report-gen"): 4200, ("payments", "billing-bot"): 300, ("other", "x"): 9}


def _matches(agent_class: str, ns: str = "payments", match_map=_AUDIT):
    from norviq.api.routers.policies import _matches_for

    return _matches_for(ns, agent_class, match_map)


def test_namespace_wide_scopes_count_the_whole_namespace_not_a_phantom_class() -> None:
    """`matches` drives the Catalog's health dot: >0 is "Loaded & enforcing", 0 is "Loaded — no
    matching workload". `__baseline__` / `namespace:<ns>` / the pack overlays / the guardrail are not
    agent classes and are not legal ServiceAccount names, so `audit_log.agent_class` can never hold
    one. Keyed on (namespace, agent_class) they read 0 forever — permanently marking the namespace
    FLOOR, which every class in the namespace falls back to, as governing nothing."""
    for scope in ("__baseline__", "namespace:payments", "__pack__", "__pack_override__", "__guardrail__"):
        count, basis = _matches(scope)
        assert count == 4500, scope  # 4200 + 300, every recorded call in the namespace
        assert basis == "namespace", scope


def test_a_cluster_baseline_counts_every_namespace() -> None:
    assert _matches("__baseline__", ns="__cluster__") == (4509, "cluster")


def test_a_compliance_overlay_counts_the_class_it_overlays() -> None:
    """`<class>__remediation__` is an ADDITIVE overlay on `<class>`, so it governs exactly what that
    class governs — but the literal key matches no audit row."""
    assert _matches("report-gen__remediation__") == (4200, "base_class")


def test_a_workload_target_is_unknown_not_zero() -> None:
    """Nothing in audit_log identifies a Deployment, so this scope genuinely cannot be measured.
    `None` says that; `0` would assert a measurement nobody took."""
    count, basis = _matches("deployment:checkout")
    assert count is None
    assert basis == "not_measurable"


def test_the_class_tier_is_unchanged() -> None:
    assert _matches("report-gen") == (4200, "agent_class")
    assert _matches("never-seen") == (0, "agent_class")  # a real class with no traffic IS a real 0


def test_a_failed_count_query_is_unknown_not_a_measured_zero() -> None:
    """`_policy_match_counts` is best-effort. When the read fails it returns None, and every policy
    must then report UNKNOWN — not 0, which would put the "nothing matches this" warning on every
    healthy control in the deployment on any DB blip."""
    count, basis = _matches("report-gen", match_map=None)
    assert count is None
    assert basis == "unavailable"


def test_list_policies_reports_the_resolved_count_per_tier() -> None:
    """End to end through the route, with the audit query stubbed."""
    import norviq.api.routers.policies as policies_router

    class _Result:
        @staticmethod
        def all():
            return [("payments", "report-gen", 4200)]

    class _Session:
        async def execute(self, _stmt):
            return _Result()

    def _fake_get_session():
        async def _gen():
            yield _Session()

        return _gen()

    original = policies_router.get_session
    policies_router.get_session = _fake_get_session
    try:
        client = _client_with_policies(
            {
                "payments:report-gen": {"rego": "c", "priority": 100},
                "payments:__baseline__": {"rego": "b", "priority": 10},
                "payments:report-gen__remediation__": {"rego": "r", "priority": 100},
                "payments:deployment:checkout": {"rego": "d", "priority": 900},
            }
        )
        rows = {r["agent_class"]: r for r in client.get("/api/v1/policies?namespace=payments").json()}
    finally:
        policies_router.get_session = original

    assert rows["report-gen"]["matches"] == 4200
    assert rows["__baseline__"]["matches"] == 4200  # was 0 → amber "no matching workload"
    assert rows["report-gen__remediation__"]["matches"] == 4200  # was 0
    assert rows["deployment:checkout"]["matches"] is None  # unknown, not a measured 0
    assert rows["deployment:checkout"]["matches_basis"] == "not_measurable"


def test_matches_counts_real_workload_traffic_only() -> None:
    """`matches > 0` paints a GREEN dot the Catalog labels "Loaded & enforcing", titled "enforcing on
    matching workloads". A Policy-Tester session, an e2e probe or a red-team run is not a workload —
    it is the console POSTing /evaluate under a throwaway identity, or the efficacy harness.

    This mattered little while every namespace-wide tier read a hardcoded 0. Now that those tiers sum
    the WHOLE namespace, an unfiltered count paints the namespace floor — the control every class in
    the namespace falls back to — green off nothing but Policy-Tester clicks. The fake session ignores
    WHERE, so the exclusion is asserted on the compiled statement, as the sibling routers' filters are.
    """
    import norviq.api.routers.policies as policies_router

    seen: list[str] = []

    class _Result:
        @staticmethod
        def all():
            return [("payments", "report-gen", 4200)]

    class _Session:
        async def execute(self, stmt):
            seen.append(stmt)
            return _Result()

    def _fake_get_session():
        async def _gen():
            yield _Session()

        return _gen()

    original = policies_router.get_session
    policies_router.get_session = _fake_get_session
    try:
        client = _client_with_policies({"payments:__baseline__": {"rego": "b", "priority": 10}})
        rows = client.get("/api/v1/policies?namespace=payments").json()
    finally:
        policies_router.get_session = original

    assert rows[0]["matches"] == 4200  # the tier resolution itself is unchanged
    # The class-name prefixes are bound parameters, so they only appear once the binds are inlined.
    sql = str(seen[0].compile(compile_kwargs={"literal_binds": True}))
    assert "'redteam'" in sql, "the match count does not exclude red-team rows"
    assert "policy-tester-%" in sql, "the match count does not exclude Policy-Tester identities"
    # ...and it is the ONE shared predicate, not a second hand-rolled copy.
    from sqlalchemy import func, select

    from norviq.api.db.models import AuditLogEntry
    from norviq.api.synthetic import audit_row_is_non_real

    shared = str(
        select(func.count())
        .select_from(AuditLogEntry)
        .where(~audit_row_is_non_real(AuditLogEntry))
        .compile(compile_kwargs={"literal_binds": True})
    )
    assert shared.split("WHERE", 1)[1].strip() in sql
