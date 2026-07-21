# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The shared spoke->hub service bearer is OIDC-preferring — it uses OIDC client-credentials when
`fleet_oidc_token_url` is set (so a hardened hub with legacy_hs256_enabled=false accepts the enrollment claim),
falls back to a self-minted HS256 service token only when legacy HS256 is enabled, else returns ""."""

from __future__ import annotations

import jwt
import pytest

from norviq.config import settings
from norviq.fleet.oidc_cc import fleet_service_bearer


class _OidcResp:
    status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"access_token": "OIDC_ACCESS_TOKEN", "expires_in": 300}


class _OidcClient:
    async def post(self, url, data=None):
        assert data["grant_type"] == "client_credentials"
        return _OidcResp()


@pytest.mark.asyncio
async def test_bearer_uses_oidc_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(settings, "fleet_oidc_token_url", "https://idp.example/token")
    monkeypatch.setattr(settings, "fleet_oidc_client_id", "cid")
    monkeypatch.setattr(settings, "fleet_oidc_client_secret", "secret")
    monkeypatch.setattr(settings, "oidc_audience", "")
    tok = await fleet_service_bearer("cluster-a", _OidcClient(), sub="norviq-join", ttl_minutes=2)
    assert tok == "OIDC_ACCESS_TOKEN"


@pytest.mark.asyncio
async def test_bearer_falls_back_to_hs256_when_no_oidc(monkeypatch) -> None:
    monkeypatch.setattr(settings, "fleet_oidc_token_url", "")
    monkeypatch.setattr(settings, "legacy_hs256_enabled", True)
    tok = await fleet_service_bearer("cluster-a", None, sub="norviq-join")
    claims = jwt.decode(tok, settings.api_secret_key, algorithms=["HS256"], options={"verify_aud": False})
    assert claims["role"] == "service" and claims["cluster"] == "cluster-a" and claims["sub"] == "norviq-join"


@pytest.mark.asyncio
async def test_bearer_empty_when_oidc_off_and_legacy_off(monkeypatch) -> None:
    monkeypatch.setattr(settings, "fleet_oidc_token_url", "")
    monkeypatch.setattr(settings, "legacy_hs256_enabled", False)
    assert await fleet_service_bearer("cluster-a", None) == ""
