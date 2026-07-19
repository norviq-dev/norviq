# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F017 #6: Attack-graph "Simulate" derives blocked/allowed from a REAL evaluation of the
selected path's steps (not the precomputed blocked_by_policy flag). This guards the backend
decision the UI calls — allow on a safe step, block on a dangerous one, with provenance.

Each test uses a fresh spiffe (unique pod) so trust history from other tests cannot drift the
allow-path decision into an escalate.
"""

from __future__ import annotations

import uuid

import httpx
import pytest


def _agent() -> dict:
    pod = uuid.uuid4().hex[:8]
    return {
        "spiffe_id": f"spiffe://norviq/ns/default/sa/customer-support-{pod}",
        "namespace": "default",
        "agent_class": "customer-support",
    }


async def _simulate_step(api_client: httpx.AsyncClient, auth_headers: dict[str, str], tool: str, params: dict) -> dict:
    resp = await api_client.post(
        "/api/v1/evaluate",
        headers=auth_headers,
        json={"tool_name": tool, "tool_params": params, "agent_identity": _agent(), "session_id": "simulate"},
    )
    assert resp.status_code == 200, resp.text[:200]
    return resp.json()


@pytest.mark.asyncio
async def test_simulate_safe_step_allows(api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
    body = await _simulate_step(api_client, auth_headers, "search_kb", {"query": "hello"})
    assert body["decision"] == "allow"
    assert body["rule_id"] == "default_allow"  # provenance: a real allow, not a fail-closed default


@pytest.mark.asyncio
async def test_simulate_dangerous_step_blocks(api_client: httpx.AsyncClient, auth_headers: dict[str, str]) -> None:
    body = await _simulate_step(api_client, auth_headers, "execute_sql", {"query": "DROP TABLE users"})
    assert body["decision"] == "block"
    assert body["rule_id"] == "deny_sql_injection"  # the real rule fired, not evaluator_error/timeout
