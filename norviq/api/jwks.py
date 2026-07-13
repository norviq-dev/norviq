# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""JWKS client for OIDC RS256/ES256 token validation (IDENTITY epic A1).

Fetches the IdP's JSON Web Key Set, caches keys by ``kid`` with a TTL, and refreshes on an
unknown ``kid`` (bounded, to avoid a DoS via forced refetch). Fail-closed: a fetch failure or
unknown key raises ``JWTError`` so the caller rejects the token rather than falling back to the
legacy HS256 path.
"""

from __future__ import annotations

import time

import httpx
import structlog
from jwt import PyJWTError as JWTError

from norviq.config import settings

log = structlog.get_logger()


class JwksClient:
    """Caches an IdP's JWKS keyed by ``kid`` with TTL + bounded unknown-kid refresh."""

    def __init__(
        self,
        jwks_url: str | None = None,
        ttl_s: int | None = None,
        min_refresh_s: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """``http_client`` is the unit-test seam (inject a fake; no live IdP required)."""
        self._jwks_url = jwks_url if jwks_url is not None else settings.oidc_jwks_url
        self._ttl_s = ttl_s if ttl_s is not None else settings.oidc_jwks_cache_ttl_s
        self._min_refresh_s = min_refresh_s if min_refresh_s is not None else settings.oidc_jwks_min_refresh_s
        self._client = http_client
        self._keys: dict[str, dict] = {}
        self._fetched_at = 0.0
        self._last_forced = 0.0

    async def get_key(self, kid: str) -> dict:
        """Return the JWK dict for ``kid``, fetching/refreshing the JWKS as needed (fail-closed)."""
        now = time.monotonic()
        if kid in self._keys and (now - self._fetched_at) < self._ttl_s:
            return self._keys[kid]
        await self._refresh()
        if kid in self._keys:
            return self._keys[kid]
        # Unknown kid: allow exactly one forced refetch, rate-limited to bound outbound fetches.
        now = time.monotonic()
        if (now - self._last_forced) > self._min_refresh_s:
            self._last_forced = now
            await self._refresh(force=True)
            if kid in self._keys:
                return self._keys[kid]
        log.warning("nrvq.auth.jwks_unknown_kid", kid=kid, code="NRVQ-AUTH-14003")
        raise JWTError(f"unknown JWKS kid: {kid}")

    async def _refresh(self, force: bool = False) -> None:
        """Fetch the JWKS and rebuild the kid->key map. Raises JWTError on fetch failure."""
        client = self._client or httpx.AsyncClient(timeout=5.0)
        owns = self._client is None
        try:
            resp = await client.get(self._jwks_url)
            resp.raise_for_status()
            keys = {k["kid"]: k for k in resp.json().get("keys", []) if "kid" in k}
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.error("nrvq.auth.jwks_fetch_failed", url=self._jwks_url, error=str(exc), code="NRVQ-AUTH-14004")
            raise JWTError("JWKS fetch failed") from exc
        finally:
            if owns:
                await client.aclose()
        self._keys = keys
        self._fetched_at = time.monotonic()
        log.info("nrvq.auth.jwks_refreshed", count=len(keys), forced=force, code="NRVQ-AUTH-14002")


_jwks_client: JwksClient | None = None


def get_jwks_client() -> JwksClient:
    """Lazy module-level JWKS client (override in tests for the synthetic-JWKS seam)."""
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = JwksClient()
    return _jwks_client
