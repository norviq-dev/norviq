# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""/ws/audit streams live decisions to the Audit Log, scoped by namespace.

Real path: open a websocket against the live API, trigger an evaluation, and assert the emitted
decision arrives — and that a subscriber scoped to a different namespace does NOT receive it.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import websockets

_AGENT = {
    "spiffe_id": "spiffe://norviq/ns/default/sa/customer-support",
    "namespace": "default",
    "agent_class": "customer-support",
}


def _ws_url(api_url: str, namespace: str, token: str) -> str:
    base = api_url.replace("https://", "wss://").replace("http://", "ws://")
    # /ws/audit now authenticates before accept(); the token rides as a query param.
    return f"{base}/ws/audit?namespace={namespace}&token={token}"


@pytest.mark.asyncio
async def test_ws_audit_broadcasts_emitted_decision(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], auth_token: str, api_url: str
) -> None:
    async with websockets.connect(_ws_url(api_url, "default", auth_token), open_timeout=5) as ws:
        ev = await api_client.post(
            "/api/v1/evaluate",
            headers=auth_headers,
            json={"tool_name": "search_kb", "tool_params": {"q": "live"}, "agent_identity": _AGENT, "session_id": "ws"},
        )
        assert ev.status_code == 200
        rec = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        assert rec["namespace"] == "default"
        assert rec["tool_name"] == "search_kb"
        assert rec["decision"] in {"allow", "block", "escalate", "audit"}
        assert "rule_id" in rec


@pytest.mark.asyncio
async def test_ws_audit_scopes_by_namespace(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], auth_token: str, api_url: str
) -> None:
    """A subscriber scoped to another namespace must not receive a default-ns decision."""
    async with websockets.connect(_ws_url(api_url, "isolated-ns", auth_token), open_timeout=5) as ws:
        ev = await api_client.post(
            "/api/v1/evaluate",
            headers=auth_headers,
            json={"tool_name": "search_kb", "tool_params": {"q": "scoped"}, "agent_identity": _AGENT, "session_id": "ws2"},
        )
        assert ev.status_code == 200
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(ws.recv(), timeout=2)
