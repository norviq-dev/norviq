# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The injected sidecar must ride out a transient blip instead of blocking a live agent.

The thin proxy used to make exactly one POST: any dropped connection — a rolling ``norviq-api``
restart, an expired conntrack entry, one 503 from a terminating pod — failed closed immediately and
the agent's tool call died. The SDK client has always retried with backoff; label-injection is the
zero-code-change path and must be no less resilient.

Retries cover transport errors and 5xx only. A 4xx is the engine answering with a refusal, so
retrying just delays the same block. Exhausting the retries still fails closed.
"""

from __future__ import annotations

import httpx
import pytest

from norviq.config import settings
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sidecar.remote_evaluator import RemoteEvaluator


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="search_kb",
        tool_params={"q": "hi"},
        agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/agent", namespace="default"),
    )


def _evaluator(handler, monkeypatch: pytest.MonkeyPatch) -> RemoteEvaluator:
    """Build an evaluator with a mock transport and instant backoff (keeps the suite fast)."""
    monkeypatch.setattr(settings, "sdk_retry_backoff_base_ms", 0, raising=False)
    ev = RemoteEvaluator(api_url="http://norviq-api:8080", api_token="t")
    ev._backoff_base_ms = 0
    ev._client = httpx.AsyncClient(base_url="http://norviq-api:8080", transport=httpx.MockTransport(handler))
    return ev


async def test_transient_connect_error_is_retried_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The rolling-restart case: first attempt drops, the retry lands, the agent is never blocked."""
    calls = {"n": 0}

    async def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json={"decision": "allow", "rule_id": "ok"})

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "allow", "a single blip still blocked a live agent"
    assert calls["n"] == 2
    await ev.close()


async def test_transient_503_is_retried_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A terminating pod's 503 is transient — retry rather than drop the call."""
    calls = {"n": 0}

    async def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"detail": "shutting down"})
        return httpx.Response(200, json={"decision": "allow", "rule_id": "ok"})

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "allow"
    assert calls["n"] == 2
    await ev.close()


async def test_4xx_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A refusal is not transient — hammering the engine with retries just delays the same block."""
    calls = {"n": 0}

    async def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403, json={"detail": "forbidden"})

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert calls["n"] == 1, "a 4xx must not be retried"
    await ev.close()


async def test_persistent_failure_still_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retry is a resilience layer, not a change of posture: a real outage still blocks."""
    calls = {"n": 0}

    async def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("connection refused")

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "block"
    assert decision.rule_id == "thin_proxy_fail_closed"
    assert calls["n"] == settings.sdk_retry_max_attempts + 1
    await ev.close()


async def test_fail_open_posture_allows_only_a_genuine_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the posture set to allow, an unreachable engine forwards — auditable as fail-open."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow", raising=False)

    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "allow"
    assert decision.rule_id == "thin_proxy_fail_open"  # never conflated with a real policy allow
    await ev.close()


async def test_fail_open_posture_still_blocks_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bypass this guards: an expired sidecar token must not be forwarded as an allow."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow", raising=False)

    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "token expired"})

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "block", "an expired token failed open — governance bypass"
    assert "not an outage" in decision.reason
    await ev.close()


async def test_success_on_first_attempt_makes_no_extra_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hot path is unchanged — no added latency when the engine is healthy."""
    calls = {"n": 0}

    async def handler(_: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"decision": "allow", "rule_id": "ok"})

    ev = _evaluator(handler, monkeypatch)
    decision = await ev.evaluate(_event())
    assert decision.decision == "allow"
    assert calls["n"] == 1
    await ev.close()
