# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""GET /api/v1/deployments derives workloads from observed agents.

Hits the real local API (the real auth + Redis scan), not a stub.
"""

from __future__ import annotations

import httpx
import pytest

_AGENT = {
    "spiffe_id": "spiffe://norviq/ns/default/sa/customer-support",
    "namespace": "default",
    "agent_class": "customer-support",
}


@pytest.mark.asyncio
async def test_deployments_requires_auth(api_client: httpx.AsyncClient) -> None:
    """No token → 401 (it must not be an open endpoint)."""
    resp = await api_client.get("/api/v1/deployments?namespace=default")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_deployments_returns_derived_rows(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    """Allow path: after an agent is observed, it surfaces as a {name,namespace,agent_class} row."""
    ev = await api_client.post(
        "/api/v1/evaluate",
        headers=auth_headers,
        json={"tool_name": "search_kb", "tool_params": {"q": "hi"}, "agent_identity": _AGENT, "session_id": "dep"},
    )
    assert ev.status_code == 200
    resp = await api_client.get("/api/v1/deployments?namespace=default", headers=auth_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert isinstance(rows, list)
    by_class = {r["agent_class"]: r for r in rows}
    assert "customer-support" in by_class, f"agent not derived into deployments: {rows}"
    row = by_class["customer-support"]
    assert row["namespace"] == "default"
    assert set(row.keys()) >= {"name", "namespace", "agent_class"}


@pytest.mark.asyncio
async def test_deployments_empty_for_unknown_namespace(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    """Edge: a namespace with no agents returns [] (200, not 404/500) so the UI fallback kicks in."""
    resp = await api_client.get("/api/v1/deployments?namespace=zzz-no-such-ns", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []
