# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SSRF-01 (CRITICAL) regression: GET /fleet/clusters/{id}/audit/records used to be reachable by any
cluster-scoped service/viewer token (no require_admin) and dialed cluster.endpoint — a value a spoke
self-reports on heartbeat — with a minted ADMIN bearer attached, with no host-range check. Locks in
both fixes: the route is now admin-only, and a cluster whose endpoint fails the SSRF guard is never
dialed (so the minted admin bearer is never sent anywhere)."""

from __future__ import annotations

from types import SimpleNamespace

from tests.fleet.test_fleet_api import FakeFleetSession, _client, _headers


def test_drilldown_now_requires_admin_not_just_cluster_scope() -> None:
    # Previously scoped_cluster alone gated this route, so a correctly-scoped service/viewer token
    # could reach it. It must now be admin-only, rejecting service/viewer even with a matching scope.
    for role in ("service", "viewer"):
        s = FakeFleetSession()
        c = _client(s)
        try:
            r = c.get("/api/v1/fleet/clusters/fleet-a/audit/records",
                      headers=_headers(role=role, cluster="fleet-a"))
            assert r.status_code == 403, f"role={role} should be rejected: {r.status_code} {r.text}"
        finally:
            c.close()


def test_drilldown_blocks_ssrf_endpoint_before_dialing() -> None:
    # A spoke-reported endpoint pointing at the cloud metadata address must be rejected by the SSRF
    # guard BEFORE the outbound httpx call — the FakeFleetSession has no network stub, so if the
    # guard did not short-circuit first, this would attempt (and fail/hang on) a real connection.
    s = FakeFleetSession(results=[[SimpleNamespace(
        id="fleet-a", endpoint="http://169.254.169.254/latest/meta-data/", residency=False,
    )]])
    c = _client(s)
    try:
        r = c.get("/api/v1/fleet/clusters/fleet-a/audit/records", headers=_headers(role="admin"))
        assert r.status_code == 200
        body = r.json()
        assert body["records"] == []
        assert "ssrf" in body["error"].lower()
    finally:
        c.close()


def test_drilldown_admin_with_no_endpoint_short_circuits_before_ssrf_check() -> None:
    # Sanity: an empty endpoint still hits the pre-existing "no endpoint registered" branch, not the
    # SSRF-guard branch (both return a soft error rather than a 5xx).
    s = FakeFleetSession(results=[[SimpleNamespace(id="fleet-a", endpoint="", residency=False)]])
    c = _client(s)
    try:
        r = c.get("/api/v1/fleet/clusters/fleet-a/audit/records", headers=_headers(role="admin"))
        assert r.status_code == 200
        assert r.json()["error"] == "no endpoint registered"
    finally:
        c.close()
