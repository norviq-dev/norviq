# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration test: attack-paths must be namespace-isolated (P0 tenant isolation).

Before the fix, GET /attack-paths ignored the namespace param (no WHERE on a table with no
namespace column), so every namespace saw every other namespace's paths (the gap analysis
observed default/payments/nonexistent all returning the same 13 paths). This seeds two distinct
namespaces directly in the DB and asserts the API returns each namespace's paths ONLY — disjoint
sets — and empty for a namespace with no paths. Requires the namespace column (applied by
ensure_schema_compatibility on startup); it is the permanent regression guard for the WHERE filter.
"""

from __future__ import annotations

import json
import uuid

import asyncpg
import httpx
import pytest


async def _seed(conn: asyncpg.Connection, namespace: str) -> str:
    """Insert one asset_graph + one attack_path for a namespace; return the path_id."""
    graph_id = uuid.uuid4()
    await conn.execute(
        "INSERT INTO asset_graph (id, built_at, node_count, edge_count, graph_json, namespace) "
        "VALUES ($1, now(), 0, 0, $2::jsonb, $3)",
        graph_id,
        json.dumps({"nodes": [], "edges": []}),
        namespace,
    )
    path_id = str(uuid.uuid4())
    path_json = {
        "path_id": path_id,
        "source_id": f"agent::{namespace}",
        "target_id": f"data::{namespace}",
        "steps": [{"step_num": 1, "node_id": f"agent::{namespace}", "action": "traverse", "policy_check": "no_policy"}],
        "severity": "high",
        "risk_score": 9.0,
        "mitre_techniques": [],
        "blocked_by_policy": False,
    }
    await conn.execute(
        "INSERT INTO attack_paths "
        "(id, graph_id, namespace, source_node, target_node, path_json, risk_score, computed_at) "
        "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, now())",
        uuid.UUID(path_id),
        graph_id,
        namespace,
        f"agent::{namespace}",
        f"data::{namespace}",
        json.dumps(path_json),
        9.0,
    )
    return path_id


@pytest.mark.asyncio
async def test_attack_paths_namespace_isolation(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], pg_url: str
) -> None:
    suffix = uuid.uuid4().hex[:8]
    ns_a, ns_b, ns_none = f"isotest-a-{suffix}", f"isotest-b-{suffix}", f"isotest-none-{suffix}"
    conn = await asyncpg.connect(pg_url.split("?")[0])
    try:
        pid_a = await _seed(conn, ns_a)
        pid_b = await _seed(conn, ns_b)

        async def paths_for(ns: str) -> set[str]:
            resp = await api_client.get(f"/api/v1/attack-paths?namespace={ns}", headers=auth_headers)
            assert resp.status_code == 200, resp.text
            return {p["path_id"] for p in resp.json()["paths"]}

        a_ids = await paths_for(ns_a)
        b_ids = await paths_for(ns_b)
        none_ids = await paths_for(ns_none)

        assert pid_a in a_ids, "namespace A must see its own path"
        assert pid_b not in a_ids, "namespace A must NOT see namespace B's path (cross-tenant leak)"
        assert pid_b in b_ids and pid_a not in b_ids, "namespace B must see only its own path"
        assert a_ids.isdisjoint(b_ids), "namespaces must be disjoint"
        assert none_ids == set(), "namespace with no paths must be empty"
    finally:
        await conn.execute("DELETE FROM attack_paths WHERE namespace = ANY($1::text[])", [ns_a, ns_b])
        await conn.execute("DELETE FROM asset_graph WHERE namespace = ANY($1::text[])", [ns_a, ns_b])
        await conn.close()
