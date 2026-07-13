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


async def test_evaluate_posts_api_v1_path_with_bearer_token() -> None:
    """Client must hit the real central-API route (/api/v1/evaluate) and present its token.

    Regression: the client used to post /v1/evaluate with no Authorization header — a
    guaranteed 404/401 against norviq-api, so every SDK call fell back to the fallback mode.
    """
    seen: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"decision": "allow", "rule_id": "ok", "trust_score": 0.9})

    client = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20, token="svc-token-123")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://engine.local",
        headers={"Authorization": "Bearer svc-token-123"},
        timeout=0.02,
    )
    decision = await client.evaluate(make_event())
    assert decision.decision == "allow"
    assert seen["path"] == "/api/v1/evaluate"
    assert seen["auth"] == "Bearer svc-token-123"
    await client.close()


async def test_get_client_builds_auth_header_from_token() -> None:
    """The lazily-built real client carries the bearer header (not just the mock)."""
    client = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20, token="svc-token-123")
    built = await client._get_client()
    assert built.headers.get("Authorization") == "Bearer svc-token-123"
    await client.close()

    no_token = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20, token="")
    built2 = await no_token._get_client()
    assert "Authorization" not in built2.headers
    await no_token.close()


def test_get_client_is_per_event_loop() -> None:
    """Each event loop must get its OWN pooled client; the same loop reuses its client.

    Regression: one shared httpx.AsyncClient was created on the first loop and reused from
    every later loop — the loop-bound pool then crashed cross-loop ('bound to a different
    event loop') and healthy traffic turned into fail-closed fallback blocks (found live in
    the kind E2E via the LangChain sync path).
    """
    import asyncio

    client = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20, token="")

    async def grab_twice() -> tuple:
        a = await client._get_client()
        b = await client._get_client()
        return a, b

    a1, b1 = asyncio.run(grab_twice())
    assert a1 is b1  # same loop -> same pooled client
    a2, _ = asyncio.run(grab_twice())
    assert a2 is not a1  # different loop -> different client


def test_run_sync_uses_one_stable_background_loop() -> None:
    """_run_sync must execute every call on the SAME background loop (loop-bound resources stay valid)."""
    import asyncio

    from norviq.sdk.core.wrapping import _run_sync

    async def which_loop() -> int:
        return id(asyncio.get_running_loop())

    first = _run_sync(which_loop())
    second = _run_sync(which_loop())
    assert first == second

    async def call_from_async_context() -> int:
        # caller HAS a running loop; _run_sync must still work and use the same bg loop
        return await asyncio.get_running_loop().run_in_executor(None, lambda: _run_sync(which_loop()))

    third = asyncio.run(call_from_async_context())
    assert third == first
