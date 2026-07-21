# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""POST /fleet/clusters/join-token (hub-side mint, admin-only) took an
unvalidated `hub_url` straight from the request body and embedded it into a signed join token that an
enrolling spoke later dials. A malicious/careless hub_url must be rejected at MINT TIME, before it is
ever signed into a token or written to the join-token row."""

from __future__ import annotations

from norviq.config import settings

from tests.fleet.test_bundle_sign_verify import _gen_rsa_pem
from tests.fleet.test_fleet_api import FakeFleetSession, _client, _headers


class _AddCapableFleetSession(FakeFleetSession):
    """FakeFleetSession plus a no-op `.add` — the mint route session.add()s a UsedJoinToken row on
    the success path (only reached once a hub_url passes the SSRF guard)."""

    def add(self, _obj):
        pass


def test_mint_join_token_rejects_ssrf_hub_url() -> None:
    original = settings.fleet_signing_key
    settings.fleet_signing_key = _gen_rsa_pem()
    try:
        c = _client(FakeFleetSession())
        try:
            r = c.post(
                "/api/v1/fleet/clusters/join-token",
                json={"cluster_id": "fleet-a", "hub_url": "http://169.254.169.254/"},
                headers=_headers(role="admin"),
            )
            assert r.status_code == 400, r.text
            assert "ssrf" in r.json()["detail"].lower()
        finally:
            c.close()
    finally:
        settings.fleet_signing_key = original


def test_mint_join_token_allows_safe_hub_url() -> None:
    original = settings.fleet_signing_key
    settings.fleet_signing_key = _gen_rsa_pem()
    try:
        c = _client(_AddCapableFleetSession())
        try:
            r = c.post(
                "/api/v1/fleet/clusters/join-token",
                json={"cluster_id": "fleet-a", "hub_url": "https://8.8.8.8:8443"},
                headers=_headers(role="admin"),
            )
            assert r.status_code == 200, r.text
            assert r.json()["cluster_id"] == "fleet-a"
        finally:
            c.close()
    finally:
        settings.fleet_signing_key = original
