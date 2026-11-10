# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A request the sidecar cannot encode is blocked; an engine it cannot reach keeps its fallback.

The sidecar encodes with the SDK client's encoder, so the two refuse the same requests, nesting past
the SDK's limit included.

Every case runs with the fallback set to ``allow`` and the engine stub blocks everything, so a forward
can only come from the fallback.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from norviq.config import settings
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sidecar.http_fallback import create_http_fallback
from norviq.sidecar.proxy import SidecarProxy
from norviq.sidecar.remote_evaluator import RemoteEvaluator

UNENCODABLE = "thin_proxy_request_unencodable"
IDENTITY = AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/agent", namespace="default", agent_class="support")


def _deep(n: int) -> str:
    return "[" * n + "]" * n


# The params as the two entry points receive them: JSON text, parsed by json.loads.
UNENCODABLE_PARAMS = {
    "nan": '{"amount": NaN}',
    "infinity": '{"amount": Infinity}',
    "negative_infinity": '{"amount": -Infinity}',
    "nested_nan": '{"rows": [{"amount": 1}, {"amount": NaN}]}',
    "overflowing_literal": '{"amount": 1e999}',
    "lone_surrogate": '{"to": "\\ud800"}',
    "lone_surrogate_key": '{"\\udfff": 1}',
    "deep_nesting": '{"x": ' + _deep(300) + "}",
}


@pytest.fixture
def fallback_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow", raising=False)


@pytest.fixture
def fallback_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sdk_fallback_mode", "block", raising=False)


class _Engine:
    """A deny-all engine that records every request it receives."""

    def __init__(self, response: httpx.Response | None = None, error: Exception | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._response = response
        self._error = error

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        if self._response is not None:
            return self._response
        return httpx.Response(200, json={"decision": "block", "rule_id": "deny_all", "trust_score": 0.1})


def _evaluator(engine: _Engine) -> RemoteEvaluator:
    ev = RemoteEvaluator(api_url="http://norviq-api:8080", api_token="t")
    ev._backoff_base_ms = 0  # noqa: SLF001 — keep the retry tests fast
    ev._client = httpx.AsyncClient(
        base_url="http://norviq-api:8080",  # noqa: SLF001
        transport=httpx.MockTransport(engine),
    )
    return ev


def _event(params: dict, tool_name: str = "issue_refund") -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool_name, tool_params=params, agent_identity=IDENTITY, session_id="s", framework="sidecar"
    )


class _Resolver:
    async def resolve(self) -> AgentIdentity:
        return IDENTITY


# ---------------------------------------------------------------------------------------------------
# The evaluator itself
# ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("raw", UNENCODABLE_PARAMS.values(), ids=UNENCODABLE_PARAMS.keys())
@pytest.mark.parametrize("posture", ["fallback_allow", "fallback_block"])
async def test_an_unencodable_call_is_blocked_without_asking_the_engine(raw: str, posture: str, request) -> None:
    request.getfixturevalue(posture)
    engine = _Engine()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event(json.loads(raw)))
    assert decision.decision == "block", f"forwarded under {settings.sdk_fallback_mode}"
    assert decision.rule_id == UNENCODABLE
    assert "not an engine outage" in decision.reason
    assert engine.requests == []
    await ev.close()


@pytest.mark.parametrize("field", ["tool_name", "session_id"])
async def test_a_lone_surrogate_outside_the_params_is_blocked_too(fallback_allow, field: str) -> None:
    """The whole body is encoded, not only tool_params: both strings come from the caller."""
    engine = _Engine()
    ev = _evaluator(engine)
    values = {"tool_name": "issue_refund", "session_id": "s", field: json.loads('"\\ud800"')}
    event = ToolCallEvent(tool_params={"a": 1}, agent_identity=IDENTITY, framework="sidecar", **values)
    decision = await ev.evaluate(event)
    assert decision.decision == "block" and decision.rule_id == UNENCODABLE
    assert engine.requests == []
    await ev.close()


@pytest.mark.parametrize(("count", "blocked"), [(1_000, False), (100_001, True)])
async def test_the_container_cap_is_the_sdk_client_s(fallback_allow, count: int, blocked: bool) -> None:
    """Size is bounded where the SDK bounds it: past 100 000 containers the call is not sent."""
    engine = _Engine()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event({"b": [[] for _ in range(count)]}))
    assert (decision.rule_id == UNENCODABLE) is blocked
    assert len(engine.requests) == (0 if blocked else 1)
    await ev.close()


async def test_a_normal_call_still_reaches_the_engine(fallback_allow) -> None:
    engine = _Engine()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event(json.loads('{"amount": 25.0, "rows": [[1, 2], {"k": null}]}')))
    assert decision.decision == "block" and decision.rule_id == "deny_all"
    assert len(engine.requests) == 1
    assert engine.requests[0].headers["content-type"] == "application/json"
    await ev.close()


async def test_nesting_the_sdk_client_sends_is_sent(fallback_allow) -> None:
    """The nesting bound is the SDK's (255 levels inside tool_params), not a tighter one."""
    engine = _Engine()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event(json.loads('{"x": ' + _deep(200) + "}")))
    assert decision.rule_id == "deny_all"
    assert len(engine.requests) == 1
    await ev.close()


async def test_the_request_document_is_unchanged_for_a_normal_call(fallback_allow) -> None:
    """Moving the encoding must not change what the engine receives: same fields, same values, same
    JSON types, as `post(json=payload)` produced from the payload the sidecar used to build."""
    engine = _Engine()
    ev = _evaluator(engine)
    params = json.loads(
        '{"i": 12345678901234567890123, "f": -0.0, "g": 1e16, "s": "h\\u00e9 \\ud83d\\ude00",'
        ' "n": null, "b": [true, false], "o": {"a": [1, 2.5, "x"]}, "e": {}}'
    )
    event = ToolCallEvent(
        tool_name="t",
        tool_params=params,
        session_id="s",
        call_depth=3,
        framework="",
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/a/sa/b", namespace="a", agent_class="c", workload="w"
        ),
    )
    await ev.evaluate(event)
    previous = {
        "tool_name": event.tool_name,
        "tool_params": event.tool_params,
        "agent_identity": event.agent_identity.model_dump(),
        "session_id": event.session_id,
        "call_depth": event.call_depth,
        "framework": event.framework or "sidecar",
    }
    expected = httpx.Request("POST", "http://x", json=previous).content

    def typed(value):
        if isinstance(value, dict):
            return {k: typed(v) for k, v in value.items()}
        if isinstance(value, list):
            return [typed(v) for v in value]
        return type(value).__name__, repr(value)

    assert typed(json.loads(engine.requests[0].content)) == typed(json.loads(expected))
    await ev.close()


# ---------------------------------------------------------------------------------------------------
# Controls: an outage still follows the configured posture
# ---------------------------------------------------------------------------------------------------

OUTAGES = {
    "connect_error": lambda: _Engine(error=httpx.ConnectError("connection refused")),
    "503": lambda: _Engine(response=httpx.Response(503, text="engine down")),
}


@pytest.mark.parametrize("outage", OUTAGES.values(), ids=OUTAGES.keys())
async def test_an_outage_still_follows_fallback_allow(fallback_allow, outage) -> None:
    engine = outage()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event({"amount": 25}))
    assert decision.decision == "allow" and decision.rule_id == "thin_proxy_fail_open"
    assert len(engine.requests) == settings.sdk_retry_max_attempts + 1
    await ev.close()


@pytest.mark.parametrize("outage", OUTAGES.values(), ids=OUTAGES.keys())
async def test_an_outage_still_follows_fallback_block(fallback_block, outage) -> None:
    engine = outage()
    ev = _evaluator(engine)
    decision = await ev.evaluate(_event({"amount": 25}))
    assert decision.decision == "block" and decision.rule_id == "thin_proxy_fail_closed"
    assert len(engine.requests) == settings.sdk_retry_max_attempts + 1
    await ev.close()


MALFORMED_200 = {
    "not_json": lambda: httpx.Response(200, text="<html>ok</html>"),
    "not_an_object": lambda: httpx.Response(200, json=[1]),
    "unknown_decision": lambda: httpx.Response(200, json={"decision": "maybe"}),
}


@pytest.mark.parametrize("body", MALFORMED_200.values(), ids=MALFORMED_200.keys())
@pytest.mark.parametrize("mode", ["allow", "block"])
async def test_a_malformed_answer_is_handled_as_the_sdk_client_handles_it(monkeypatch, body, mode) -> None:
    """A 200 that is not a decision follows the fallback posture in both clients. Pinned as parity:
    if one of them is changed to treat it differently, this fails until the other is changed too."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", mode, raising=False)
    ev = _evaluator(_Engine(response=body()))
    sidecar = await ev.evaluate(_event({"amount": 25}))
    sdk = PolicyEngineClient(base_url="http://engine.test", timeout_ms=50)
    sdk._client = httpx.AsyncClient(
        base_url="http://engine.test",  # noqa: SLF001
        transport=httpx.MockTransport(lambda r: body()),
    )
    reference = await sdk.evaluate(_event({"amount": 25}))
    assert sidecar.decision == reference.decision == mode
    await ev.close()


# ---------------------------------------------------------------------------------------------------
# Both entry points, end to end
# ---------------------------------------------------------------------------------------------------


def _line(params_json: str) -> str:
    return '{"tool_name": "issue_refund", "session_id": "s", "tool_params": ' + params_json + "}"


@pytest.mark.parametrize("raw", UNENCODABLE_PARAMS.values(), ids=UNENCODABLE_PARAMS.keys())
async def test_the_unix_socket_entry_point_drops_an_unencodable_call(fallback_allow, raw: str) -> None:
    engine = _Engine()
    proxy = SidecarProxy(socket_path="/nonexistent/norviq.sock")
    proxy._interceptor = ToolInterceptor(_evaluator(engine), _Resolver())  # noqa: SLF001
    response = json.loads(await proxy._process_request(_line(raw)))  # noqa: SLF001
    assert response["action"] == "drop"
    assert response["decision"]["rule_id"] == UNENCODABLE
    assert engine.requests == []


async def test_the_unix_socket_entry_point_still_asks_the_engine(fallback_allow) -> None:
    engine = _Engine()
    proxy = SidecarProxy(socket_path="/nonexistent/norviq.sock")
    proxy._interceptor = ToolInterceptor(_evaluator(engine), _Resolver())  # noqa: SLF001
    response = json.loads(await proxy._process_request(_line('{"amount": 25}')))  # noqa: SLF001
    assert response["action"] == "drop" and response["decision"]["rule_id"] == "deny_all"
    assert len(engine.requests) == 1


def _http_client(engine: _Engine) -> TestClient:
    app = create_http_fallback(ToolInterceptor(_evaluator(engine), _Resolver()), None, _Resolver())
    # The pod-local app is a loopback caller (see test_http_fallback_nondict.py).
    return TestClient(app, client=("127.0.0.1", 50000))


@pytest.mark.parametrize("raw", UNENCODABLE_PARAMS.values(), ids=UNENCODABLE_PARAMS.keys())
def test_the_http_entry_point_drops_an_unencodable_call(fallback_allow, raw: str) -> None:
    engine = _Engine()
    response = _http_client(engine).post(
        "/v1/evaluate", content=_line(raw), headers={"content-type": "application/json"}
    )
    assert response.status_code == 200
    assert response.json()["action"] == "drop"
    assert response.json()["decision"]["rule_id"] == UNENCODABLE
    assert engine.requests == []


def test_the_http_entry_point_still_asks_the_engine(fallback_allow) -> None:
    engine = _Engine()
    response = _http_client(engine).post(
        "/v1/evaluate", content=_line('{"amount": 25}'), headers={"content-type": "application/json"}
    )
    assert response.json()["action"] == "drop" and response.json()["decision"]["rule_id"] == "deny_all"
    assert len(engine.requests) == 1
