# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for the Attack Graph threats endpoints (feat/attack-graph). Runs against a LIVE
kind API (never AKS). Seeds a kill-chain asset-graph snapshot per namespace, then asserts:

  * GET /threats/attack-paths is namespace-isolated (a scoped read of ns_a never sees ns_b).
  * POST /threats/intent-coverage denies the paths whose chokepoint the generated policy blocks.
  * POST /threats/intent-draft returns enforcement="draft" and creates NO enforcing `policies` row for
    the class — the security-critical "generation is dry-run, Apply never enforces on its own" guarantee.
"""

from __future__ import annotations

import json
import uuid

import asyncpg
import httpx
import pytest


async def _seed_chain(conn: asyncpg.Connection, namespace: str, agent_class: str, chokepoint: str) -> None:
    """Seed one asset_graph snapshot: agent(cls) --calls--> tool(chokepoint) --reaches--> data(sensitive)."""
    graph_json = {
        "nodes": [
            {"id": "agent:svc", "type": "agent", "name": "svc",
             "properties": {"namespace": namespace, "agent_class": agent_class,
                            "agent_classes": [agent_class], "trust_score": 0.3}},
            {"id": f"tool:{chokepoint}", "type": "tool", "name": chokepoint,
             "properties": {"namespace": namespace, "risk_level": "high"}},
            {"id": "data:ledger", "type": "data", "name": "ledger",
             "properties": {"namespace": namespace, "sensitivity": "critical"}},
        ],
        "edges": [
            {"source": "agent:svc", "target": f"tool:{chokepoint}", "type": "calls", "target_name": chokepoint},
            {"source": f"tool:{chokepoint}", "target": "data:ledger", "type": "accesses"},
        ],
    }
    await conn.execute(
        "INSERT INTO asset_graph (id, built_at, node_count, edge_count, graph_json, namespace) "
        "VALUES ($1, now(), 3, 2, $2::jsonb, $3)",
        uuid.uuid4(), json.dumps(graph_json), namespace,
    )


@pytest.mark.asyncio
async def test_threats_isolation_coverage_and_dry_run_not_enforce(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], pg_url: str
) -> None:
    suffix = uuid.uuid4().hex[:8]
    ns_a, ns_b = f"thr-a-{suffix}", f"thr-b-{suffix}"
    cls = f"cls-{suffix}"
    conn = await asyncpg.connect(pg_url.split("?")[0])
    try:
        await _seed_chain(conn, ns_a, cls, "send_email")
        await _seed_chain(conn, ns_b, cls, "send_email")

        # 1) namespace isolation — a scoped read of ns_a never returns ns_b's path.
        ra = await api_client.get(f"/api/v1/threats/attack-paths?ns={ns_a}&range=24h", headers=auth_headers)
        assert ra.status_code == 200, ra.text
        a_paths = ra.json()["paths"]
        assert a_paths, "ns_a must have a derived kill-chain"
        assert all(p["ns"] == ns_a for p in a_paths), "ns_a read must not leak another namespace"
        assert all(p["cls"] == cls for p in a_paths)

        # 2) intent-suggest — the class's observed tools, with the send_email chokepoint flagged.
        rs = await api_client.get(f"/api/v1/threats/intent-suggest?ns={ns_a}&cls={cls}", headers=auth_headers)
        assert rs.status_code == 200, rs.text
        tools = rs.json()["tools"]
        assert any(t["name"] == "send_email" for t in tools), f"send_email must be an observed tool: {tools}"
        assert any(t["name"] == "send_email" and t["tag"] in ("chokepoint", "egress") for t in tools)

        # 3) coverage — an allowlist that OMITS send_email denies the send_email chokepoint path (default-deny).
        rc = await api_client.post(
            "/api/v1/threats/intent-coverage",
            headers=auth_headers,
            json={"ns": ns_a, "cls": cls, "allow_tools": ["search_kb"],
                  "intent": {"egress": False, "readonly": False, "scope": False, "rate": False}},
        )
        assert rc.status_code == 200, rc.text
        cov = rc.json()
        assert cov["total"] >= 1 and cov["covered_count"] >= 1, f"non-allowlisted send_email must be denied: {cov}"
        assert 'default decision = "block"' in cov["rego"] and "allow_names" in cov["rego"]

        # 4) intent draft — DURABLE (intent_drafts table) + NO enforcing policy row for the class.
        pol_before = await conn.fetchval(
            "SELECT count(*) FROM policies WHERE namespace = $1 AND agent_class = $2", ns_a, cls
        )
        rd = await api_client.post(
            "/api/v1/threats/intent-draft",
            headers=auth_headers,
            json={"ns": ns_a, "cls": cls, "allow_tools": ["search_kb"],
                  "intent": {"egress": False, "readonly": True, "scope": False, "rate": False}},
        )
        assert rd.status_code == 200, rd.text
        draft = rd.json()
        assert draft["enforcement"] == "draft"
        assert draft["deeplink"].startswith("/policies/catalog?intent_draft=")
        assert draft["priority"] >= 1  # pinned to the baseline priority for tighten-only
        pol_after = await conn.fetchval(
            "SELECT count(*) FROM policies WHERE namespace = $1 AND agent_class = $2", ns_a, cls
        )
        assert pol_after == pol_before, "intent-draft MUST NOT create an enforcing policy row (dry-run only)"
        drafts = await conn.fetchval(
            "SELECT count(*) FROM intent_drafts WHERE namespace = $1 AND agent_class = $2", ns_a, cls
        )
        assert drafts >= 1, "the draft must be PERSISTED durably in intent_drafts (non-enforcing store)"
    finally:
        await conn.execute("DELETE FROM asset_graph WHERE namespace = ANY($1::text[])", [ns_a, ns_b])
        await conn.execute("DELETE FROM intent_drafts WHERE namespace = ANY($1::text[])", [ns_a, ns_b])
        await conn.close()
