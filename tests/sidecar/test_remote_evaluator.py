# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SIDE-2: thin-proxy RemoteEvaluator — maps the central /evaluate response and fails CLOSED."""

from __future__ import annotations

import httpx
import pytest

from norviq.engine.identity import AgentIdentity
from norviq.sdk.core.events import ToolCallEvent
from norviq.sidecar.remote_evaluator import RemoteEvaluator


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="execute_sql",
        tool_params={"query": "drop table users"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/customer-support",
            namespace="default",
            agent_class="customer-support",
        ),
        session_id="s",
        framework="sidecar",
    )


@pytest.mark.asyncio
async def test_remote_evaluator_maps_block_decision() -> None:
    """A central 'block' response is mapped to a PolicyDecision that drops the call."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"decision": "block", "rule_id": "deny_sql_injection", "trust_score": 0.5})

    ev = RemoteEvaluator(api_url="http://norviq-api:8080", api_token="tok")
    ev._client = httpx.AsyncClient(
        base_url="http://norviq-api:8080",
        headers={"Authorization": "Bearer tok"},
        transport=httpx.MockTransport(handler),
    )
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "deny_sql_injection"
    assert not decision.is_allowed()
    assert captured["path"] == "/api/v1/evaluate"
    assert captured["auth"] == "Bearer tok"
    await ev.close()


@pytest.mark.asyncio
async def test_remote_evaluator_maps_allow_decision() -> None:
    """A central 'allow' response forwards the call."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "allow", "rule_id": "default_allow", "trust_score": 0.9})

    ev = RemoteEvaluator()
    ev._client = httpx.AsyncClient(base_url="http://norviq-api:8080", transport=httpx.MockTransport(handler))
    decision = await ev.evaluate(_event())
    assert decision.is_allowed()
    await ev.close()


@pytest.mark.asyncio
async def test_remote_evaluator_fails_closed_on_error() -> None:
    """Any network/non-2xx error must BLOCK (never forward) — fail closed."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="engine down")

    ev = RemoteEvaluator()
    ev._client = httpx.AsyncClient(base_url="http://norviq-api:8080", transport=httpx.MockTransport(handler))
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "thin_proxy_fail_closed"
    assert not decision.is_allowed()
    await ev.close()


@pytest.mark.asyncio
async def test_remote_evaluator_fails_closed_on_connect_error() -> None:
    """A transport/connection error must also BLOCK."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    ev = RemoteEvaluator()
    ev._client = httpx.AsyncClient(base_url="http://norviq-api:8080", transport=httpx.MockTransport(handler))
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "thin_proxy_fail_closed"
    await ev.close()
