# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration test: the API /evaluate path must emit audit records (P0 "see enforcement").

Before the fix, only the sidecar called emitter.emit — the API /evaluate handler never did, so
the audit endpoints returned 200 but showed no data on the API deployment. This calls /evaluate
and asserts the call lands in /audit/records (fire-and-forget, so we poll briefly) with the right
namespace, tool_name, and decision. A unique namespace makes the record unambiguous and confirms
audit data is tenant-scoped. Fail-before (no emission → record never appears) / pass-after.
"""

from __future__ import annotations

import asyncio
import uuid

import asyncpg
import httpx
import pytest


@pytest.mark.asyncio
async def test_evaluate_emits_audit_record(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], pg_url: str
) -> None:
    ns = f"emittest-{uuid.uuid4().hex[:8]}"
    tool = "search_kb"
    body = {
        "tool_name": tool,
        "tool_params": {"query": "emit-probe"},
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{ns}/sa/probe", "namespace": ns, "agent_class": "probe"},
        "session_id": "emit-probe",
        "trust_score": 0.85,
    }
    try:
        resp = await api_client.post("/api/v1/evaluate", json=body, headers=auth_headers)
        assert resp.status_code == 200, resp.text
        decision = resp.json()["decision"]

        # Emission is fire-and-forget — poll briefly for the background write to land.
        found = None
        for _ in range(20):  # up to ~5s
            r = await api_client.get(f"/api/v1/audit/records?namespace={ns}&limit=10", headers=auth_headers)
            assert r.status_code == 200, r.text
            records = r.json()
            if records:
                found = records[0]
                break
            await asyncio.sleep(0.25)

        assert found is not None, "/evaluate did not produce an audit record (emission not wired?)"
        assert found["namespace"] == ns, "audit record must carry the request namespace (tenant-scoped)"
        assert found["tool_name"] == tool
        assert found["decision"] == decision
    finally:
        conn = await asyncpg.connect(pg_url.split("?")[0])
        try:
            await conn.execute("DELETE FROM audit_log WHERE namespace = $1", ns)
        finally:
            await conn.close()
