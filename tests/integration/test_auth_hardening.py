# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Remediation A1/A3: data endpoints require auth, are namespace-scoped, and policy writes are admin-only.

Hits the real local API. These guard the customer-eval P0s (unauth audit/policy/graph exposure,
viewer privilege-escalation, unauthenticated /ws/audit).
"""

from __future__ import annotations

import asyncio
import time

import httpx
import jwt
import pytest
import websockets
import websockets.exceptions  # websockets>=15 does not auto-import the submodule

from norviq.config import settings


def _viewer_headers() -> dict[str, str]:
    token = jwt.encode(
        {"sub": "viewer", "role": "viewer", "namespace": "default", "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


_PROTECTED = [
    "/api/v1/audit/records",
    "/api/v1/audit/stats",
    "/api/v1/audit/top-blocked",
    "/api/v1/audit/volume",
    "/api/v1/policies",
    "/api/v1/policies/default/customer-support",
    "/api/v1/policies/default/customer-support/versions",
    "/api/v1/graph/",
    "/api/v1/graph/summary",
]


@pytest.mark.parametrize("path", _PROTECTED)
@pytest.mark.asyncio
async def test_data_endpoint_requires_auth(api_client: httpx.AsyncClient, path: str) -> None:
    """No token → 401 (was leaking data with no auth)."""
    resp = await api_client.get(path)
    assert resp.status_code == 401, f"{path} returned {resp.status_code}, expected 401"


@pytest.mark.asyncio
async def test_viewer_cannot_read_other_namespace(api_client: httpx.AsyncClient) -> None:
    """A default-scoped viewer token must not read another namespace's audit data (403)."""
    resp = await api_client.get("/api/v1/audit/records?namespace=payments&limit=5", headers=_viewer_headers())
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_write_or_delete_policy(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    """Policy writes are admin-only; a viewer token must get 403 (was 200 — privilege escalation)."""
    rego = (
        "package norviq.strict\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "x" }\n'
        'rule_id = "r" { input.tool_name == "x" }\n'
        'reason = "y" { input.tool_name == "x" }\n'
    )
    body = {"namespace": "authtest", "agent_class": "v", "rego_source": rego}
    # viewer create -> 403
    assert (await api_client.post("/api/v1/policies", headers=_viewer_headers(), json=body)).status_code == 403
    # admin create -> 200, then viewer delete -> 403
    assert (await api_client.post("/api/v1/policies", headers=auth_headers, json=body)).status_code == 200
    assert (await api_client.delete("/api/v1/policies/authtest/v", headers=_viewer_headers())).status_code == 403
    await api_client.delete("/api/v1/policies/authtest/v", headers=auth_headers)  # admin cleanup


@pytest.mark.asyncio
async def test_ws_audit_rejects_missing_token(api_client: httpx.AsyncClient, api_url: str) -> None:
    """/ws/audit must reject a handshake with no token (was accepting before any check)."""
    ws_url = api_url.replace("https://", "wss://").replace("http://", "ws://") + "/ws/audit?namespace=default"
    with pytest.raises((websockets.exceptions.InvalidStatus, websockets.exceptions.ConnectionClosed, OSError, asyncio.TimeoutError)):
        async with websockets.connect(ws_url, open_timeout=5) as ws:
            await asyncio.wait_for(ws.recv(), timeout=3)
