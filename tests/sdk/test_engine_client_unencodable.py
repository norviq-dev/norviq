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
