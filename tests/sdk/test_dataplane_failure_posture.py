# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The data plane must distinguish "the engine refused me" from "the engine isn't answering".

Both used to funnel into ``sdk_fallback_mode``, which made the availability knob unsafe: an operator
setting ``fallback=allow`` so agents keep working through an outage would ALSO turn every 401/403
into an allow, so an expired credential became a silent, total governance bypass — and a 4xx an
attacker can *provoke* (malform a param into a 422) became a bypass on demand.

The boundary these tests pin: **4xx always blocks** (the engine answered, with a refusal), while
5xx/timeout/connect errors — genuinely no answer — honour the operator's configured posture.
"""

from __future__ import annotations

import httpx
import pytest

from norviq.config import settings
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="search_kb",
        tool_params={"q": "refund window"},
        agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/agent", namespace="default"),
    )


def _client(transport: httpx.AsyncBaseTransport) -> PolicyEngineClient:
    client = PolicyEngineClient(base_url="http://engine.local", timeout_ms=20)
    client._client = httpx.AsyncClient(transport=transport, base_url="http://engine.local", timeout=0.02)
    return client


def _status_transport(status: int) -> httpx.MockTransport:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": "nope"})

    return httpx.MockTransport(handler)


@pytest.fixture
def fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the SDK in the most permissive posture an operator can choose (now also the default)."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow", raising=False)


@pytest.fixture
def fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The opt-in strict posture: no call proceeds unjudged, even during an outage."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "block", raising=False)


# --- 4xx: the engine answered, and refused. Never fail open. ---------------------------------------


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 429])
async def test_4xx_always_blocks_even_when_configured_to_fail_open(status: int, fail_open: None) -> None:
    """The regression that matters: fallback=allow must NOT turn a refusal into an allow."""
    client = _client(_status_transport(status))
    decision = await client.evaluate(_event())
    assert decision.decision == "block", f"HTTP {status} failed open — governance bypass"
    assert decision.rule_id == "engine_rejected_request"
    await client.close()


async def test_4xx_reason_does_not_claim_an_outage(fail_open: None) -> None:
    """Diagnostic honesty: a 401 sent operators to stare at healthy engine pods."""
    client = _client(_status_transport(401))
    decision = await client.evaluate(_event())
    assert "401" in decision.reason
    assert "unavailable" not in decision.reason.lower()  # the old, misleading wording
    await client.close()


# --- 5xx / no answer: the operator's posture applies ------------------------------------------------


async def test_5xx_honours_fail_open_posture(fail_open: None) -> None:
    """A real engine outage is exactly what the availability knob is for."""
    client = _client(_status_transport(503))
    decision = await client.evaluate(_event())
    assert decision.decision == "allow"
    await client.close()


async def test_connect_error_honours_fail_open_posture(fail_open: None) -> None:
    """Engine unreachable — no answer at all — also honours the posture."""

    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = _client(httpx.MockTransport(handler))
    decision = await client.evaluate(_event())
    assert decision.decision == "allow"
    await client.close()


@pytest.mark.parametrize("status", [500, 502, 503])
async def test_5xx_allows_under_the_default_posture(status: int) -> None:
    """The shipped default is now fail-OPEN, and this pins it deliberately.

    It used to be `block`, on the reasoning that no call should ever proceed unjudged. The cost was
    that a Norviq outage became the customer's outage: every agent in the cluster stops working
    because OUR engine is down. A security control whose failure mode is a production incident gets
    taken out of the request path, which protects nobody.

    The trade is real and is accepted knowingly — for the duration of an outage, calls proceed
    without a decision. What makes it acceptable is that it is *countable*, which the next test pins.
    """
    assert settings.sdk_fallback_mode == "allow"  # the shipped default
    client = _client(_status_transport(status))
    decision = await client.evaluate(_event())
    assert decision.decision == "allow"
    await client.close()


@pytest.mark.parametrize("status", [500, 502, 503])
async def test_5xx_still_blocks_when_the_operator_asks_for_it(status: int, fail_closed: None) -> None:
    """Fail-closed is still fully supported — it is now opt-in rather than the default."""
    client = _client(_status_transport(status))
    decision = await client.evaluate(_event())
    assert decision.decision == "block"
    await client.close()


@pytest.mark.parametrize("mode", ["allow", "block"])
async def test_the_fallback_is_attributable_in_both_postures(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole argument for defaulting to fail-open is that an operator can SEE it.

    `rule_id` was left at its "" default here, which made a fail-open fallback indistinguishable in
    the audit trail from a policy that genuinely allowed the call — nobody could count how many calls
    went unjudged, or for how long. With the default flipped, that anonymity would be the difference
    between a documented trade-off and a silent governance hole.

    Asserted in the block posture too: an operator staring at blocked agents needs to know the cause
    was an engine outage and not their own policy.
    """
    monkeypatch.setattr(settings, "sdk_fallback_mode", mode, raising=False)
    client = _client(_status_transport(503))
    decision = await client.evaluate(_event())
    assert decision.decision == mode
    assert decision.rule_id == "engine_unavailable_fallback"
    assert decision.rule_id != "engine_rejected_request"  # that one is the 4xx path, never this
    await client.close()


async def test_typod_fallback_mode_fails_safe_instead_of_crashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """PolicyDecision constrains `decision` to a Literal, so an unrecognised mode used to raise a
    ValidationError inside the fallback handler — the one path that runs only while the engine is
    already down. It must degrade to block, not crash the data plane mid-outage."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "opne", raising=False)  # typo for "open"
    client = _client(_status_transport(503))
    decision = await client.evaluate(_event())
    assert decision.decision == "block"
    await client.close()


async def test_4xx_blocks_under_the_default_posture_too() -> None:
    """Same verdict as before the fix under the default — only the reason/rule_id got more precise."""
    client = _client(_status_transport(403))
    decision = await client.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "engine_rejected_request"
    await client.close()
