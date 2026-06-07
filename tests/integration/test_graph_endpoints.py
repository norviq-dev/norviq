# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for /api/v1/asset-graph and /api/v1/attack-paths."""

from __future__ import annotations

import httpx
import pytest


@pytest.mark.asyncio
async def test_api_is_running(api_client):
    """Sanity check — fails loudly if API isn't running."""
    resp = await api_client.get("/healthz")
    assert resp.status_code == 200, "API not running on local — start with .\\scripts\\dev.ps1 api"


class TestAssetGraphEndpoint:
    @pytest.mark.asyncio
    async def test_returns_200_with_auth(self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
        resp = await api_client.get("/api/v1/asset-graph", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "nodes" in data and "edges" in data
        assert isinstance(data["nodes"], list)
        assert isinstance(data["edges"], list)

    @pytest.mark.asyncio
    async def test_401_without_auth(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/api/v1/asset-graph")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_namespace_returns_empty_shape(
        self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]
    ) -> None:
        resp = await api_client.get("/api/v1/asset-graph?namespace=nonexistent", headers=auth_headers)
        assert resp.status_code == 200
        payload = resp.json()
        assert isinstance(payload.get("nodes"), list)
        assert isinstance(payload.get("edges"), list)

    @pytest.mark.asyncio
    async def test_range_param_validated(self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
        for r in ["1h", "6h", "24h", "7d", "30d", "invalid"]:
            resp = await api_client.get(f"/api/v1/asset-graph?range={r}", headers=auth_headers)
            assert resp.status_code == 200


class TestAttackPathsEndpoint:
    @pytest.mark.asyncio
    async def test_returns_200(self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
        resp = await api_client.get("/api/v1/attack-paths", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "paths" in data and "nodes" in data
        assert isinstance(data["paths"], list)
        assert isinstance(data["nodes"], list)

    @pytest.mark.asyncio
    async def test_401_without_auth(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/api/v1/attack-paths")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_severity_filter(self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
        resp = await api_client.get("/api/v1/attack-paths?severity=critical", headers=auth_headers)
        assert resp.status_code == 200
        for path in resp.json()["paths"]:
            assert path["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_paths_sorted_by_risk_desc(self, api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
        resp = await api_client.get("/api/v1/attack-paths", headers=auth_headers)
        assert resp.status_code == 200
        paths = resp.json()["paths"]
        for i in range(len(paths) - 1):
            assert paths[i]["risk_score"] >= paths[i + 1]["risk_score"]


@pytest.mark.asyncio
async def test_attack_paths_no_connection_leak(api_client, auth_headers):
    """Hit endpoint 30 times — connection pool must not exhaust.

    Day 9 bug: AsyncSession not released, exhausted pool after 15 calls.
    """
    for i in range(30):
        resp = await api_client.get("/api/v1/attack-paths", headers=auth_headers)
        assert resp.status_code == 200, f"Failed on call {i}: status={resp.status_code}, body={resp.text[:200]}"


@pytest.mark.asyncio
async def test_asset_graph_no_connection_leak(api_client, auth_headers):
    """Same regression test for asset-graph endpoint."""
    for i in range(30):
        resp = await api_client.get("/api/v1/asset-graph", headers=auth_headers)
        assert resp.status_code == 200, f"Failed on call {i}"
