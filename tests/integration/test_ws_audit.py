# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""/ws/audit streams live decisions to the Audit Log, scoped by namespace.

Real path: open a websocket against the live API, trigger an evaluation, and assert the emitted
decision arrives — and that a subscriber scoped to a different namespace does NOT receive it.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import httpx
import pytest
import websockets

_AGENT = {
    "spiffe_id": "spiffe://norviq/ns/default/sa/customer-support",
    "namespace": "default",
    "agent_class": "customer-support",
}


# Budgets, env-tunable so a slow link can loosen without editing the test. Generous enough for a
# remote cluster, still bounded so a genuinely dead broadcast path fails rather than hanging.
WS_OPEN_TIMEOUT_S = float(os.environ.get("NRVQ_TEST_WS_OPEN_TIMEOUT_S", "20"))
WS_RECV_DEADLINE_S = float(os.environ.get("NRVQ_TEST_WS_RECV_TIMEOUT_S", "30"))


def _ws_url(api_url: str, namespace: str, token: str) -> str:
    base = api_url.replace("https://", "wss://").replace("http://", "ws://")
    # /ws/audit now authenticates before accept(); the token rides as a query param.
    return f"{base}/ws/audit?namespace={namespace}&token={token}"


async def _await_own_record(ws, session_id: str, deadline_s: float) -> dict:
    """Read until OUR decision arrives, or the deadline expires.

    Two brittle assumptions used to live in one line of `await asyncio.wait_for(ws.recv(), timeout=5)`.

    1. That 5 seconds is always enough. It is not against a remote cluster: the two failures observed
       were `TimeoutError`, never an assertion, and the same test passed on other runs — the broadcast
       arrives, just later than a laptop-tuned budget allows.
    2. That the FIRST message on the socket is ours. `/ws/audit` is namespace-scoped, not
       session-scoped, so any other traffic in `default` — a red-team run, a browser suite, another
       agent — is delivered here too. On a quiet local cluster that is invisible; on a live one it is a
       coin flip, and it would have failed as a confusing assertion error about `tool_name`.

    Draining until the record matching our own session_id shows up fixes both, and is STRICTER than
    what it replaces: the test now proves that this specific decision was broadcast, rather than that
    some decision was.
    """
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline_s
    seen = 0
    while True:
        remaining = end - loop.time()
        if remaining <= 0:
            raise AssertionError(
                f"no broadcast for session_id={session_id!r} within {deadline_s}s "
                f"({seen} other record(s) arrived on the socket)"
            )
        rec = json.loads(await asyncio.wait_for(ws.recv(), timeout=remaining))
        if rec.get("session_id") == session_id:
            return rec
        seen += 1


@pytest.mark.asyncio
async def test_ws_audit_broadcasts_emitted_decision(
    api_client: httpx.AsyncClient, auth_headers: dict[str, str], auth_token: str, api_url: str
) -> None:
    # Unique per run, so our own record is identifiable among other live traffic on the namespace.
    session_id = f"ws-{uuid.uuid4().hex[:12]}"
    async with websockets.connect(_ws_url(api_url, "default", auth_token), open_timeout=WS_OPEN_TIMEOUT_S) as ws:
        ev = await api_client.post(
            "/api/v1/evaluate",
            headers=auth_headers,
            json={"tool_name": "search_kb", "tool_params": {"q": "live"},
                  "agent_identity": _AGENT, "session_id": session_id},
        )
        assert ev.status_code == 200
        rec = await _await_own_record(ws, session_id, WS_RECV_DEADLINE_S)
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
