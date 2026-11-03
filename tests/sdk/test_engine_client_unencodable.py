# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A request this process cannot encode is blocked; an engine that cannot be reached keeps its fallback.

The two used to share one path: a tool_params tree nested past what pydantic's serialiser handles
(~255 levels) raised inside the POST, fell to the unknown-error handler, and took the OUTAGE fallback
— so with sdk_fallback_mode=allow, a call the engine never saw was allowed, at the caller's choice.
"""

from __future__ import annotations

import httpx
import pytest

from norviq.config import settings
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def _event(params: dict) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="delete_all", tool_params=params,
        agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/a/sa/b", namespace="a", agent_class="c"),
        session_id="s", framework="mcp",
    )


def _deep(n: int) -> list:
    value: list = []
    for _ in range(n):
        value = [value]
    return value


def _client(handler) -> PolicyEngineClient:
    """As tests/sdk/test_engine_client.py builds one: the pooled client replaced by a mock transport."""
    client = PolicyEngineClient(base_url="http://engine.test", timeout_ms=50)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler),  # noqa: SLF001
                                       base_url="http://engine.test", timeout=0.05)
    return client


@pytest.fixture()
def fallback_allow(monkeypatch):
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow")


@pytest.mark.parametrize("params", [{"b": _deep(300)}, {"b": _deep(1000)}])
async def test_an_unencodable_request_is_blocked_even_with_fallback_allow(fallback_allow, params):
    sent: list = []

    def handler(request):
        sent.append(request)
        return httpx.Response(200, json={"decision": "allow"})

    decision = await _client(handler).evaluate(_event(params))
    assert decision.decision == "block"
    assert decision.rule_id == "engine_request_unencodable"
    assert sent == [], "nothing that could not be encoded was sent"


async def test_an_unreachable_engine_still_takes_the_configured_fallback(fallback_allow):
    """The outage path is unchanged: allow stays allow when the engine does not answer."""
    def handler(request):
        raise httpx.ConnectError("down", request=request)

    decision = await _client(handler).evaluate(_event({"q": 1}))
    assert decision.decision == "allow" and decision.rule_id == "engine_unavailable_fallback"


async def test_a_deep_but_reasonable_request_is_sent_and_decided(fallback_allow):
    seen: list = []

    def handler(request):
        seen.append(request.content)
        return httpx.Response(200, json={"decision": "block", "rule_id": "policy"})

    decision = await _client(handler).evaluate(_event({"b": _deep(100)}))
    assert decision.rule_id == "policy" and len(seen) == 1


@pytest.mark.parametrize("params", [{"amount": float("inf")}, {"amount": float("-inf")},
                                    {"nested": [{"amount": float("nan")}]}])
async def test_a_non_finite_number_is_blocked_rather_than_sent_as_null(fallback_allow, params):
    """pydantic's JSON mode writes inf and nan as null; the engine would decide on null."""
    sent: list = []

    def handler(request):
        sent.append(request.content)
        return httpx.Response(200, json={"decision": "allow"})

    decision = await _client(handler).evaluate(_event(params))
    assert decision.decision == "block" and decision.rule_id == "engine_request_unencodable"
    assert sent == []


async def test_a_self_referential_call_is_blocked_promptly(fallback_allow):
    """`_non_finite` had no cycle guard: a params dict containing itself spun forever on the event
    loop. It is visited once; the encoder then refuses the cycle, and the call is blocked."""
    import asyncio

    event = _event({"a": 1})
    event.tool_params["self"] = event.tool_params  # the event is frozen; its dict is not
    decision = await asyncio.wait_for(_client(lambda r: httpx.Response(200, json={"decision": "allow"}))
                                      .evaluate(event), 2)
    assert decision.decision == "block" and decision.rule_id == "engine_request_unencodable"


async def test_a_shared_sub_object_is_walked_once(fallback_allow):
    import asyncio

    shared: list = [1.5] * 1000
    params = {f"k{i}": shared for i in range(5000)}
    decision = await asyncio.wait_for(_client(lambda r: httpx.Response(200, json={"decision": "allow",
                                                                                   "rule_id": "p"}))
                                      .evaluate(_event(params)), 10)
    assert decision.rule_id == "p"


async def test_a_non_finite_number_in_the_mcp_context_is_blocked(fallback_allow):
    event = _event({"q": 1})
    event.mcp["weird"] = float("inf")
    decision = await _client(lambda r: httpx.Response(200, json={"decision": "allow"})).evaluate(event)
    assert decision.rule_id == "engine_request_unencodable"
