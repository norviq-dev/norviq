# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async OIDC client-credentials token cache (Python has no x/oauth2 equivalent). Mirrors the Go
webhook controller's pattern: fetch a client-credentials access token, cache it, refresh ~60s early."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from norviq.config import settings


class ClientCredentialsToken:
    """Caches a client-credentials access token; refreshes ~60s before expiry."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client
        self._token: str | None = None
        self._expiry: float = 0.0  # monotonic deadline

    async def bearer(self) -> str:
        """Return a valid access token, fetching/refreshing as needed."""
        if self._token and time.monotonic() < self._expiry - 60:
            return self._token
        data = {
            "grant_type": "client_credentials",
            "client_id": settings.fleet_oidc_client_id,
            "client_secret": settings.fleet_oidc_client_secret,
        }
        if settings.oidc_audience:
            data["audience"] = settings.oidc_audience  # so the hub's verify_aud passes
        resp = await self._client.post(settings.fleet_oidc_token_url, data=data)
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._expiry = time.monotonic() + float(body.get("expires_in", 300))
        return self._token


async def fleet_service_bearer(cluster_id: str, client: httpx.AsyncClient, *, sub: str = "norviq-fleet",
                               ttl_minutes: int = 60) -> str:
    """The spoke->hub SERVICE bearer, OIDC-preferring — the canonical acquisition shared by the relay's
    self-mint and the enrollment claim. R5: when the hub runs OIDC-only (``legacy_hs256_enabled=false``) an
    HS256-only enrollment token 401s; using OIDC client-credentials here (when ``fleet_oidc_token_url`` is set) makes
    the claim work. Falls back to a self-minted HS256 service token ONLY when legacy HS256 is enabled; otherwise ""."""
    if settings.fleet_oidc_token_url:
        return await ClientCredentialsToken(client).bearer()
    if settings.legacy_hs256_enabled:
        now = datetime.now(timezone.utc)
        claims = {"sub": sub, "role": "service", "cluster": cluster_id,
                  "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=ttl_minutes)).timestamp())}
        return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")
    return ""
