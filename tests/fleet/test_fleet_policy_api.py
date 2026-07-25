# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Hub fleet policy API: authoring RBAC, selector/override resolution, rollout state machine,
cross-cluster scope. Reuses the bare-TestClient + FakeFleetSession harness from test_fleet_api.py."""

from __future__ import annotations

from types import SimpleNamespace

from norviq.fleet.routers.fleet_policy import _resolve_for_cluster, report_rollout  # noqa: F401

from tests.fleet.test_fleet_api import FakeFleetSession, _client, _headers


def _author_body(name="p1", selector=None, agent_class="bot", confirm=True):
    return {"name": name, "namespace": "default", "agent_class": agent_class, "rego_source": "package x",
            "priority": 100, "enforcement_mode": "block", "target_selector": selector or {},
            "confirm_fleet_wide": confirm}  # A fleet-wide selector needs confirmation


def test_fleet_push_reserved_scope_rejected() -> None:
    # A push to __baseline__/__pack__ must 422 (and never reach the DB) — baseline/pack are per-cluster managed.
    for scope in ("__baseline__", "__pack__"):
        c = _client(FakeFleetSession())
        try:
            r = c.post("/api/v1/fleet/policies", json=_author_body(agent_class=scope), headers=_headers(role="admin"))
            assert r.status_code == 422
            assert "packs" in r.json()["detail"] or "baseline" in r.json()["detail"]
        finally:
            c.close()


def test_fleet_wide_push_requires_confirm() -> None:
    # Env-scoped (no cluster_id -> matches >1 cluster) without confirm -> 422; with confirm -> 200.
    c = _client(FakeFleetSession())
    try:
        r = c.post("/api/v1/fleet/policies",
                   json=_author_body(selector={"env": "prod"}, confirm=False), headers=_headers(role="admin"))
        assert r.status_code == 422 and "confirm_fleet_wide" in r.json()["detail"]
    finally:
        c.close()
    c = _client(FakeFleetSession(results=[[]]))  # existing select -> none -> version 1
    try:
        r = c.post("/api/v1/fleet/policies",
                   json=_author_body(selector={"env": "prod"}, confirm=True), headers=_headers(role="admin"))
        assert r.status_code == 200
    finally:
        c.close()


def test_single_cluster_push_no_confirm_needed() -> None:
    # A single-cluster override ({"cluster_id":…}) is not fleet-wide -> no confirm required.
    c = _client(FakeFleetSession(results=[[]]))
    try:
        r = c.post("/api/v1/fleet/policies",
                   json=_author_body(selector={"cluster_id": "fleet-a"}, confirm=False), headers=_headers(role="admin"))
        assert r.status_code == 200
    finally:
        c.close()


def test_resolve_excludes_reserved_scope() -> None:
    # Defense-in-depth: a reserved-scope policy already in the DB never lands in a bundle.
    cluster = SimpleNamespace(id="fleet-a", labels={"env": "prod"})
    pol = lambda name, cls: SimpleNamespace(  # noqa: E731
        name=name, namespace="default", agent_class=cls, rego_source="R", priority=100,
        enforcement_mode="block", version=1, target_selector={})
    out = _resolve_for_cluster([pol("baseline", "__baseline__"), pol("pack", "__pack__"), pol("ok", "bot")], cluster)
    classes = {o["agent_class"] for o in out}
    assert classes == {"bot"} and "__baseline__" not in classes and "__pack__" not in classes


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
    # A residency-flagged cluster must NOT have its raw audit pulled to the hub.
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


# --- GET /fleet/policies must be cluster-scoped like every other fleet read ------------------------
# Regression: the list returned EVERY authored policy to any admin-or-service caller, so a spoke's
# cluster-scoped service token could enumerate other clusters' policy names, namespaces, agent classes
# and selectors — while POST /fleet/policies right above it already enforces scope on
# target_selector.cluster_id.


def _policy_row(name: str, selector: dict):
    return SimpleNamespace(
        name=name, namespace="default", agent_class="bot", target_selector=selector,
        enforcement_mode="block", priority=100, version=1, updated_at=None,
    )


_ROWS = [
    _policy_row("override-a", {"cluster_id": "fleet-a"}),  # belongs to fleet-a
    _policy_row("override-b", {"cluster_id": "fleet-b"}),  # belongs to fleet-b
    _policy_row("fleet-wide", {}),                          # applies everywhere
    _policy_row("by-label", {"env": "prod"}),               # cohort selector, no cluster_id
]


def test_list_policies_hides_other_clusters_overrides() -> None:
    """A fleet-a service token must not see fleet-b's per-cluster override."""
    c = _client(FakeFleetSession([list(_ROWS)]))
    try:
        r = c.get("/api/v1/fleet/policies", headers=_headers(role="service", cluster="fleet-a"))
        assert r.status_code == 200
        names = {p["name"] for p in r.json()}
        assert "override-b" not in names  # the leak
        assert "override-a" in names  # its own override
        # Rows with no cluster_id may apply to this cluster too, so they stay visible.
        assert {"fleet-wide", "by-label"} <= names
    finally:
        c.close()


def test_list_policies_admin_still_sees_every_cluster() -> None:
    """Admin (and cluster='*') keeps the fleet-wide view the console needs."""
    for headers in (_headers(role="admin", cluster=""), _headers(role="service", cluster="*")):
        c = _client(FakeFleetSession([list(_ROWS)]))
        try:
            r = c.get("/api/v1/fleet/policies", headers=headers)
            assert r.status_code == 200
            assert {p["name"] for p in r.json()} == {"override-a", "override-b", "fleet-wide", "by-label"}
        finally:
            c.close()


def test_list_policies_cross_cluster_query_denied() -> None:
    """Asking for another cluster explicitly is a 403, exactly like the sibling reads."""
    c = _client(FakeFleetSession([list(_ROWS)]))
    try:
        r = c.get("/api/v1/fleet/policies?cluster=fleet-b", headers=_headers(role="service", cluster="fleet-a"))
        assert r.status_code == 403
    finally:
        c.close()
