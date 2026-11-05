# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The sidecar HTTP fallback must not evaluate for callers it cannot identify.

It had no caller check, and the standalone engine Deployment serves it on a ClusterIP Service, so any
pod in the cluster could submit tool calls and have them evaluated, audited and scored under the
ENGINE's own identity. Now: loopback (the pod-local app) is unchanged; an off-pod caller is refused
unless sidecar_remote_callers=token, and then needs a valid, unrevoked service JWT and is evaluated as
the identity bound in it.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import jwt
import pytest

from norviq.api import session_revocation as sr
from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sidecar.http_fallback import create_http_fallback

POD_IDENTITY = AgentIdentity(spiffe_id="spiffe://norviq/ns/norviq/sa/engine", namespace="norviq")


class _RecordingEval:
    def __init__(self) -> None:
        self.events: list = []

    async def evaluate(self, event) -> PolicyDecision:
        self.events.append(event)
        return PolicyDecision(decision="allow")


class _Resolver:
    async def resolve(self) -> AgentIdentity:
        return POD_IDENTITY


def _service_token(**claims) -> str:
    base = {"sub": "svc", "role": "service", "namespace": "team-a", "agent_class": "support-agent",
            "spiffe_id": "spiffe://norviq/ns/team-a/sa/support", "exp": int(time.time()) + 600}
    base.update(claims)
    return jwt.encode(base, settings.api_secret_key, algorithm="HS256")


def _post(evaluator, peer: str, headers: dict | None = None, body: dict | None = None) -> httpx.Response:
    app = create_http_fallback(ToolInterceptor(evaluator, _Resolver()), None, _Resolver())

    async def go():
        transport = httpx.ASGITransport(app=app, client=(peer, 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://engine") as c:
            return await c.post("/v1/evaluate", json=body or {"tool_name": "search_kb", "tool_params": {}},
                                headers=headers or {})
    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    sr._mirror.clear()
    yield
    sr._mirror.clear()


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1"])
def test_the_pod_local_app_is_evaluated_as_the_pod(peer: str) -> None:
    ev = _RecordingEval()
    r = _post(ev, peer)
    assert r.status_code == 200 and r.json()["action"] == "forward"
    assert ev.events and ev.events[0].agent_identity.spiffe_id == POD_IDENTITY.spiffe_id


def test_an_off_pod_caller_is_refused_by_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "deny")
    ev = _RecordingEval()
    r = _post(ev, "10.244.0.17", headers={"Authorization": f"Bearer {_service_token()}"})
    assert r.status_code == 403 and r.json()["action"] == "drop"
    assert ev.events == [], "a refused caller was evaluated anyway"


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer "}, {"Authorization": "Basic abc"},
                                     {"Authorization": "Bearer not.a.jwt"}],
                         ids=["none", "empty", "wrong-scheme", "garbage"])
def test_token_mode_refuses_an_off_pod_caller_without_a_valid_token(monkeypatch, headers) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "token")
    ev = _RecordingEval()
    r = _post(ev, "10.244.0.17", headers=headers)
    assert r.status_code == 401 and r.json()["action"] == "drop"
    assert ev.events == []


def test_token_mode_refuses_a_token_signed_with_another_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "token")
    forged = jwt.encode({"sub": "x", "role": "admin", "exp": int(time.time()) + 600}, "f" * 48, algorithm="HS256")
    ev = _RecordingEval()
    assert _post(ev, "10.244.0.17", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    assert ev.events == []


def test_token_mode_refuses_a_logged_out_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "token")
    tok = _service_token()
    asyncio.run(sr.revoke(None, tok, int(time.time()) + 600))
    ev = _RecordingEval()
    assert _post(ev, "10.244.0.17", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert ev.events == []


def test_token_mode_evaluates_the_caller_as_the_identity_in_its_token(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "token")
    ev = _RecordingEval()
    r = _post(ev, "10.244.0.17", headers={"Authorization": f"Bearer {_service_token()}"})
    assert r.status_code == 200
    got = ev.events[0].agent_identity
    assert (got.namespace, got.agent_class, got.spiffe_id) == (
        "team-a", "support-agent", "spiffe://norviq/ns/team-a/sa/support")
    assert got.spiffe_id != POD_IDENTITY.spiffe_id, "evaluated as the engine, not the caller"


def test_token_mode_does_not_let_the_body_claim_another_identity(monkeypatch) -> None:
    monkeypatch.setattr(settings, "sidecar_remote_callers", "token")
    ev = _RecordingEval()
    spoof = {"tool_name": "search_kb", "tool_params": {},
             "agent_identity": {"spiffe_id": "spiffe://norviq/ns/team-b/sa/admin", "namespace": "team-b",
                                "agent_class": "admin-bot"}}
    r = _post(ev, "10.244.0.17", headers={"Authorization": f"Bearer {_service_token()}"}, body=spoof)
    assert r.status_code == 403 and ev.events == []
