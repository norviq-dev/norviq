# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""GET /api/v1/mitre/coverage serves the ATLAS technique→policy map cross-referenced
with the rego loaded for the namespace (the page was a 'coming soon' stub)."""

from __future__ import annotations

import httpx
import pytest


@pytest.mark.asyncio
async def test_mitre_coverage_requires_auth(api_client: httpx.AsyncClient) -> None:
    resp = await api_client.get("/api/v1/mitre/coverage?namespace=default")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mitre_coverage_returns_atlas_mapping(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str]
) -> None:
    resp = await api_client.get("/api/v1/mitre/coverage?namespace=default", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1
    assert 0 <= body["covered"] <= body["total"]

    techs = {t["technique_id"]: t for t in body["techniques"]}
    # A known ENFORCEABLE technique from policies/mitre_mapping.json. Deliberately not AML.T0048
    # ("External Harms"), which that mapping scopes out_of_scope with policies: [] — it is an
    # impact/governance concern, not a tool-call vector a runtime PEP enforces, so asserting a
    # policy mapping on it encoded a technique id that can never carry one.
    assert "AML.T0051" in techs, f"ATLAS mapping not served: {list(techs)[:5]}"
    t = techs["AML.T0051"]
    assert "llm01_prompt_injection" in t["policies"]
    # covered flag must be consistent with covered_policies (real cross-reference, not hardcoded)
    assert isinstance(t["covered"], bool)
    assert t["covered"] == (len(t["covered_policies"]) > 0)
