# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for PolicyEngineClient."""

from __future__ import annotations

import httpx

from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def make_event() -> ToolCallEvent:
    """Build a valid ToolCallEvent."""
    return ToolCallEvent(
        tool_name="search",
        tool_params={"q": "hello"},
        agent_identity=AgentIdentity(spiffe_id="spiffe://cluster/ns/default/sa/agent", namespace="default"),
    )


def make_client(transport: httpx.AsyncBaseTransport) -> PolicyEngineClient:
    """Create client with mock transport."""
    client = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20)
    client._client = httpx.AsyncClient(transport=transport, base_url="http://engine.local", timeout=0.02)
    return client


async def test_evaluate_success_returns_policy_decision() -> None:
    """Client should parse and return policy decision on success."""

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "allow", "policy_id": "P-1", "event_id": "evt-1"})

    client = make_client(httpx.MockTransport(handler))
    decision = await client.evaluate(make_event())
    assert decision.decision == "allow"
    assert decision.policy_id == "P-1"
    await client.close()


async def test_evaluate_block_returns_blocked_decision() -> None:
    """Client should preserve block decisions from engine."""

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "block", "reason": "denied", "event_id": "evt-2"})

    client = make_client(httpx.MockTransport(handler))
    decision = await client.evaluate(make_event())
    assert decision.is_blocked() is True
    assert decision.reason == "denied"
    await client.close()


async def test_evaluate_timeout_returns_fallback() -> None:
    """Client should return fallback decision on timeout."""

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = make_client(httpx.MockTransport(handler))
    decision = await client.evaluate(make_event())
    assert decision.decision in ("audit", "block")
    assert "Engine unavailable" in decision.reason
    await client.close()


async def test_evaluate_http_500_returns_fallback() -> None:
    """Client should return fallback decision on HTTP errors."""

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    client = make_client(httpx.MockTransport(handler))
    decision = await client.evaluate(make_event())
    assert decision.decision in ("audit", "block")
    assert "Engine unavailable" in decision.reason
    await client.close()


async def test_evaluate_connection_error_returns_fallback() -> None:
    """Client should return fallback decision on connection errors."""

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("cannot connect", request=request)

    client = make_client(httpx.MockTransport(handler))
    decision = await client.evaluate(make_event())
    assert decision.decision in ("audit", "block")
    assert "Engine unavailable" in decision.reason
    await client.close()


async def test_close_releases_connections() -> None:
    """close should release underlying client pool."""
    client = make_client(httpx.MockTransport(lambda _: httpx.Response(200, json={"decision": "allow"})))
    assert client._client is not None
    await client.close()
    assert client._client is None


async def test_circuit_breaker_short_circuits_after_failures() -> None:
    """Client should short-circuit calls while circuit is open."""
    call_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("down", request=request)

    client = make_client(httpx.MockTransport(handler))
    await client.evaluate(make_event())
    before = call_count
    await client.evaluate(make_event())
    assert call_count == before
    await client.close()
