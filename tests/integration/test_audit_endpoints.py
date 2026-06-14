# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for audit + health endpoints — guards the P-15/P-16 async-session bug.

These hit the REAL FastAPI app through a live local API (the real get_session lifecycle, NOT a
monkeypatched session). With the async-generator bug (`session = await get_session()`) every
audit read endpoint returns 500 and /readyz always reports db=false. This suite fails against the
buggy code and passes once get_session is consumed correctly (Depends / generator drive).

Why this is needed: the unit tests in tests/api/test_api.py monkeypatched get_session into a plain
async function, so `await get_session()` "worked" there and masked the bug on the real ASGI path.
This suite refuses to be fooled — it exercises the real dependency.
"""

from __future__ import annotations

import httpx
import pytest


@pytest.mark.asyncio
async def test_healthz_200(api_client: httpx.AsyncClient) -> None:
    assert (await api_client.get("/healthz")).status_code == 200


@pytest.mark.asyncio
async def test_readyz_reports_db_true(api_client: httpx.AsyncClient) -> None:
    """/readyz must run the real SELECT 1 and report db=true (the bug always reported db=false)."""
    resp = await api_client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json().get("db") is True, f"db probe not real: {resp.text[:200]}"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/audit/stats",
        "/api/v1/audit/records",
        "/api/v1/audit/top-blocked",
        "/api/v1/audit/volume",
    ],
)
@pytest.mark.asyncio
async def test_audit_endpoints_200_not_500(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], path: str
) -> None:
    """Audit read endpoints must return 200, not 500 (P-15 async-generator session bug)."""
    resp = await api_client.get(path, headers=auth_headers)
    assert resp.status_code == 200, f"{path} -> {resp.status_code} (P-15 async-session bug?): {resp.text[:200]}"


@pytest.mark.asyncio
async def test_audit_records_namespace_filter_200(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    """Namespace-filtered records must also work (exercises the same session path with a WHERE)."""
    resp = await api_client.get("/api/v1/audit/records?namespace=default&limit=5", headers=auth_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
