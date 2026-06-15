# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests: /agents and /policies must be namespace-scoped (P0-D).

The UI threads the selected namespace into these endpoints, but the backend ignored it —
every namespace saw the global set (policies 15/15, agents global). These assert that an
explicit ?namespace= scopes the result: each namespace sees only its own, sets are disjoint,
and a nonexistent namespace is empty. Fail-before (no filter → cross-namespace) / pass-after.
"""

from __future__ import annotations

import uuid

import asyncpg
import httpx
import pytest


@pytest.mark.asyncio
async def test_agents_namespace_scoping(api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
    suffix = uuid.uuid4().hex[:8]
    ns_a, ns_b, ns_none = f"agtest-a-{suffix}", f"agtest-b-{suffix}", f"agtest-none-{suffix}"
    sp_a = f"spiffe://norviq/ns/{ns_a}/sa/probe"
    sp_b = f"spiffe://norviq/ns/{ns_b}/sa/probe"

    # An evaluate call sets trust:{spiffe_id} synchronously (evaluator._trust), which is what
    # /agents lists — so this seeds one agent per namespace.
    for ns, sp in ((ns_a, sp_a), (ns_b, sp_b)):
        body = {
            "tool_name": "search_kb",
            "tool_params": {"q": "probe"},
            "agent_identity": {"spiffe_id": sp, "namespace": ns, "agent_class": "probe"},
            "session_id": "agtest",
            "trust_score": 0.8,
        }
        r = await api_client.post("/api/v1/evaluate", json=body, headers=auth_headers)
        assert r.status_code == 200, r.text

    async def spiffes(ns: str) -> set[str]:
        r = await api_client.get(f"/api/v1/agents?namespace={ns}", headers=auth_headers)
        assert r.status_code == 200, r.text
        return {a["spiffe_id"] for a in r.json()}

    a, b, none = await spiffes(ns_a), await spiffes(ns_b), await spiffes(ns_none)
    assert sp_a in a and sp_b not in a, "ns A must see only its own agent"
    assert sp_b in b and sp_a not in b, "ns B must see only its own agent"
    assert a.isdisjoint(b), "agent namespaces must be disjoint"
    assert none == set(), "nonexistent namespace must be empty"


@pytest.mark.asyncio
async def test_policies_namespace_scoping(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], pg_url: str
) -> None:
    suffix = uuid.uuid4().hex[:8]
    ns, ns_none = f"poltest-{suffix}", f"poltest-none-{suffix}"
    rego = (
        "package norviq.x\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "danger" }\n'
        'rule_id = "r"\n'
        'reason = "x"\n'
    )
    try:
        r = await api_client.post(
            "/api/v1/policies",
            json={"namespace": ns, "agent_class": "probe", "rego_source": rego},
            headers=auth_headers,
        )
        assert r.status_code == 200, r.text

        scoped = (await api_client.get(f"/api/v1/policies?namespace={ns}", headers=auth_headers)).json()
        assert all(p["namespace"] == ns for p in scoped), "scoped list must contain only the requested ns"
        assert (ns, "probe") in {(p["namespace"], p["agent_class"]) for p in scoped}

        default_list = (await api_client.get("/api/v1/policies?namespace=default", headers=auth_headers)).json()
        assert all(p["namespace"] == "default" for p in default_list)
        assert (ns, "probe") not in {(p["namespace"], p["agent_class"]) for p in default_list}

        none_list = (await api_client.get(f"/api/v1/policies?namespace={ns_none}", headers=auth_headers)).json()
        assert none_list == [], "nonexistent namespace must be empty"
    finally:
        await api_client.delete(f"/api/v1/policies/{ns}/probe", headers=auth_headers)
        conn = await asyncpg.connect(pg_url.split("?")[0])
        try:
            await conn.execute(
                "DELETE FROM policy_versions WHERE policy_id IN (SELECT id FROM policies WHERE namespace = $1)", ns
            )
            await conn.execute("DELETE FROM policies WHERE namespace = $1", ns)
        finally:
            await conn.close()
