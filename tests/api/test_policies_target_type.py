# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F017 #3: GET /api/v1/policies must return a target_type per policy so the UI catalog can
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
    # list_policies now requires auth (A1); inject an admin user via dependency override.
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
    """MUT-VERSION: each version row carries its OWN rego_source so the console can inspect a
    historical version read-only (previously dropped — 'Load in Editor' showed current for every row)."""
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
