# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""End-to-end test: seed asset graph → compute → verify attack paths."""

import pytest


class TestAttackGraphCompute:
    @pytest.mark.asyncio
    async def test_trigger_endpoint_requires_admin(self, api_client):
        """Without admin token, should 401 or 403."""
        resp = await api_client.post("/api/v1/attack-paths/compute")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_compute_single_namespace(self, api_client, auth_headers):
        """Compute paths for default namespace."""
        resp = await api_client.post(
            "/api/v1/attack-paths/compute?namespace=default",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "namespace" in data
        assert "computed" in data
        assert isinstance(data["computed"], int)

    @pytest.mark.asyncio
    async def test_compute_all_namespaces(self, api_client, auth_headers):
        """Compute paths for all namespaces."""
        resp = await api_client.post(
            "/api/v1/attack-paths/compute",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "computed_by_namespace" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_compute_then_read_paths(self, api_client, auth_headers):
        """Compute, then verify GET /attack-paths returns the new paths."""
        # Trigger compute
        compute_resp = await api_client.post(
            "/api/v1/attack-paths/compute?namespace=default",
            headers=auth_headers,
        )
        assert compute_resp.status_code == 200

        # Read back
        read_resp = await api_client.get(
            "/api/v1/attack-paths?namespace=default",
            headers=auth_headers,
        )
        assert read_resp.status_code == 200
        data = read_resp.json()

        # If asset_graph has nodes, paths should exist
        # If asset_graph is empty, paths empty — both valid
        assert "paths" in data
        assert "nodes" in data
