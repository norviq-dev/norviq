# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Thin-proxy RemoteEvaluator — maps the central /evaluate response and honours the outage posture.

The posture used to be fail-CLOSED and is now fail-OPEN by default (`config.sdk_fallback_mode`), so a
Norviq outage no longer takes the customer's agents down with it. Both directions are pinned here:
the default lets traffic through and marks it, and an operator who asks for fail-closed still gets it.
"""

from __future__ import annotations

import httpx
import pytest

from norviq.config import settings
from norviq.engine.identity import AgentIdentity
from norviq.sdk.core.events import ToolCallEvent
from norviq.sidecar.remote_evaluator import RemoteEvaluator


@pytest.fixture
def fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in strict posture: no call proceeds unjudged, even during an outage."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "block", raising=False)


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


def _evaluator(handler) -> RemoteEvaluator:  # noqa: ANN001 - httpx handler callable
    ev = RemoteEvaluator()
    ev._client = httpx.AsyncClient(base_url="http://norviq-api:8080", transport=httpx.MockTransport(handler))
    return ev


def _down(_: httpx.Request) -> httpx.Response:
    return httpx.Response(503, text="engine down")


def _refused(_: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused")


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [_down, _refused], ids=["5xx", "connect_error"])
async def test_outage_lets_traffic_through_under_the_default_posture(handler) -> None:  # noqa: ANN001
    """The shipped default is fail-OPEN, and the call is MARKED so the gap is countable.

    This asserted `block` / `thin_proxy_fail_closed` until the default changed. The reasoning behind
    the old default — never let a call proceed unjudged — was sound in isolation and wrong in context:
    it made Norviq a single point of failure for every agent in the cluster, so our unavailability
    became the customer's incident.

    The verdict flipping is only acceptable because `thin_proxy_fail_open` names it. An allow that
    looked like any other allow would be a silent governance hole rather than a stated trade-off.
    """
    assert settings.sdk_fallback_mode == "allow"  # the shipped default
    ev = _evaluator(handler)
    decision = await ev.evaluate(_event())
    assert decision.decision == "allow"
    assert decision.rule_id == "thin_proxy_fail_open"
    await ev.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [_down, _refused], ids=["5xx", "connect_error"])
async def test_outage_still_blocks_when_the_operator_asks_for_it(handler, fail_closed: None) -> None:  # noqa: ANN001
    """Fail-closed is still fully supported — it is now opt-in rather than the default."""
    ev = _evaluator(handler)
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "thin_proxy_fail_closed"
    assert not decision.is_allowed()
    await ev.close()
