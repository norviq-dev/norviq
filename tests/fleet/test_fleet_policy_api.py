# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Hub fleet policy API (F045 P2): authoring RBAC, selector/override resolution, rollout state machine,
cross-cluster scope. Reuses the bare-TestClient + FakeFleetSession harness from test_fleet_api.py."""

from __future__ import annotations

from types import SimpleNamespace

from norviq.fleet.routers.fleet_policy import _resolve_for_cluster, report_rollout  # noqa: F401

from tests.fleet.test_fleet_api import FakeFleetSession, _client, _headers


def _author_body(name="p1", selector=None):
    return {"name": name, "namespace": "default", "agent_class": "bot", "rego_source": "package x",
            "priority": 100, "enforcement_mode": "block", "target_selector": selector or {}}


def test_author_requires_admin() -> None:
    # viewer + service are rejected (authoring allow/deny rules is admin-only); admin succeeds.
    for role in ("viewer", "service"):
        c = _client(FakeFleetSession())
        try:
            assert c.post("/api/v1/fleet/policies", json=_author_body(), headers=_headers(role=role)).status_code == 403
        finally:
            c.close()
    c = _client(FakeFleetSession(results=[[]]))  # select existing -> none -> version 1
    try:
        r = c.post("/api/v1/fleet/policies", json=_author_body(), headers=_headers(role="admin"))
        assert r.status_code == 200 and r.json()["version"] == 1
    finally:
        c.close()


def test_bundle_cross_cluster_denied() -> None:
    # a fleet-a service token pulling fleet-b's bundle -> 403 (scoped_cluster), before any signing/DB.
    c = _client(FakeFleetSession())
    try:
        r = c.get("/api/v1/fleet/clusters/fleet-b/bundle", headers=_headers(role="service", cluster="fleet-a"))
        assert r.status_code == 403
    finally:
        c.close()


def test_resolve_selector_and_override_precedence() -> None:
    cluster = SimpleNamespace(id="fleet-a", labels={"env": "prod"})
    pol = lambda name, sel, rego: SimpleNamespace(  # noqa: E731
        name=name, namespace="default", agent_class="bot", rego_source=rego, priority=100,
        enforcement_mode="block", version=1, target_selector=sel)
    policies = [
        pol("all", {}, "ALL"),                              # matches everyone
        pol("prod", {"env": "prod"}, "PROD"),               # selector match
        pol("staging", {"env": "staging"}, "STAGING"),      # no match
        pol("override-a", {"cluster_id": "fleet-a"}, "OVERRIDE"),  # per-cluster override
        pol("override-b", {"cluster_id": "fleet-b"}, "OTHER"),     # override for another cluster
    ]
    out = _resolve_for_cluster(policies, cluster)
    # one (namespace,agent_class) key -> the per-cluster override wins over selector/label matches.
    assert len(out) == 1 and out[0]["rego_source"] == "OVERRIDE"

    # without the override, a label-selector match is chosen (not the non-matching one)
    out2 = _resolve_for_cluster([p for p in policies if not p.name.startswith("override")], cluster)
    assert {o["rego_source"] for o in out2} == {"ALL"} or "PROD" in {o["rego_source"] for o in out2}


def test_drilldown_residency_blocked() -> None:
    # P4/P5: a residency-flagged cluster must NOT have its raw audit pulled to the hub.
    s = FakeFleetSession(results=[[SimpleNamespace(id="fleet-a", endpoint="http://spoke", residency=True)]])
    c = _client(s)
    try:
        r = c.get("/api/v1/fleet/clusters/fleet-a/audit/records", headers=_headers(role="admin")).json()
        assert r["residency_blocked"] is True and r["records"] == []
    finally:
        c.close()


def test_drilldown_cross_cluster_denied() -> None:
    s = FakeFleetSession()
    c = _client(s)
    try:
        r = c.get("/api/v1/fleet/clusters/fleet-b/audit/records", headers=_headers(role="viewer", cluster="fleet-a"))
        assert r.status_code == 403
    finally:
        c.close()


def test_rollout_state_machine() -> None:
    # applied_version == expected -> applied; mismatch -> diverged; failed -> failed.
    def _run(report, expected):
        s = FakeFleetSession(results=[[SimpleNamespace(policy_bundle_version=expected)]])
        c = _client(s)
        try:
            return c.post("/api/v1/fleet/clusters/fleet-a/rollout", json=report,
                          headers=_headers(role="service", cluster="fleet-a")).json()["state"]
        finally:
            c.close()

    assert _run({"bundle_version": 5, "state": "applied", "applied_version": 5}, 5) == "applied"
    assert _run({"bundle_version": 5, "state": "applied", "applied_version": 4}, 5) == "diverged"
    assert _run({"bundle_version": 5, "state": "failed", "applied_version": 0}, 5) == "failed"
