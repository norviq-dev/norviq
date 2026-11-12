# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Only callers allowed to run synthetic traffic can tag it.

A synthetic `framework` (SYNTHETIC_FRAMEWORKS: redteam, probe, ...) makes the engine write no agent registry
row, trust, history, profile or graph state for the call, and takes its row out of every real-traffic
view. /evaluate took the value from the request body, so a workload's own credential could tag its own
real calls. The tag is now bound to the caller like `agent_class` is: an operator credential keeps it,
anyone else is recorded as real traffic with the tag kept as `claimed_framework`.

Driven through the real route and the real OPAEvaluator (OPA and Redis stubbed), so the assertions are on
what the engine actually wrote, not on what the route meant to pass it.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from norviq.api import auth as auth_mod
from norviq.api.main import create_app
from norviq.api.synthetic import is_non_real_row, is_non_real_traffic
from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.trust import TrustScore

_NS = "my-team"
_SVID = f"spiffe://norviq/ns/{_NS}/sa/default"
_CLASS = "customer-support"

# The engine's per-identity writers, by coroutine name (evaluator._persist_behavior).
_WRITERS = {
    "_safe_set_trust", "_safe_register_agent", "_safe_record_graph", "_safe_record_history", "_safe_update_profile",
}


def _token(role: str, namespace: str = _NS, **claims: str) -> str:
    body = {"sub": f"{role}-test", "role": role, "namespace": namespace, "exp": int(time.time()) + 3600, **claims}
    return jwt.encode(body, settings.api_secret_key, algorithm="HS256")


def _workload_token() -> str:
    """What the injector mints for a sidecar: role=service, bound to its class and SVID."""
    return _token("service", agent_class=_CLASS, spiffe_id=_SVID)


class _Cache:
    def __init__(self) -> None:
        self.trust: dict[str, TrustScore] = {}

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        return self.trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        self.trust[spiffe_id] = score

    async def get_eval(self, *_a):
        return None

    async def set_eval(self, *_a) -> None:
        return None

    async def incr_call_count(self, *_a) -> int:
        return 1

    async def get_ns_settings(self, _ns: str):
        return None


class _Emitter:
    def __init__(self) -> None:
        self.rows: list[tuple] = []

    def emit(self, event, decision, payload=None) -> None:
        self.rows.append((event, decision, payload))


class _Hub:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def publish(self, record: dict) -> None:
        self.records.append(record)


class _Harness(SimpleNamespace):
    client: TestClient
    cache: _Cache
    queued: list
    seen: list
    emitter: _Emitter
    hub: _Hub


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> _Harness:
    cache = _Cache()
    engine = OPAEvaluator(cache)  # type: ignore[arg-type]
    queued: list[str] = []
    seen: list = []

    def _capture(coro) -> None:
        queued.append(coro.cr_code.co_name)
        coro.close()

    async def _trust(*_a, **_k) -> TrustResult:
        return TrustResult(score=0.9, category="high", signals={}, weights={}, dominant_signal="", recommendation="allow")

    async def _no_candidates(*_a, **_k) -> list:
        return []

    async def _opa(*_a, **_k) -> dict:
        return {"decision": "block", "rule_id": "deny_drop_table", "reason": "test"}

    monkeypatch.setattr(engine, "_queue_background", _capture)
    monkeypatch.setattr(engine, "_compute_trust", _trust)
    monkeypatch.setattr(engine, "_collect_candidates", _no_candidates)
    monkeypatch.setattr(engine, "_evaluate_opa", _opa)

    real_evaluate = engine.evaluate

    async def _evaluate(event):
        seen.append(event)
        return await real_evaluate(event)

    monkeypatch.setattr(engine, "evaluate", _evaluate)

    app = create_app()
    emitter, hub = _Emitter(), _Hub()
    app.state.evaluator = engine
    app.state.emitter = emitter
    app.state.audit_hub = hub
    return _Harness(client=TestClient(app), cache=cache, queued=queued, seen=seen, emitter=emitter, hub=hub)


def _post(h: _Harness, token: str, framework: str, svid: str = _SVID, agent_class: str = _CLASS) -> dict:
    body = {
        "tool_name": "drop_table",
        "tool_params": {},
        "agent_identity": {"spiffe_id": svid, "namespace": _NS, "agent_class": agent_class},
        "session_id": "s",
        "framework": framework,
    }
    resp = h.client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _row(event, payload) -> SimpleNamespace:
    """The audit row the emitter would write for this event (the fields the classifiers read)."""
    return SimpleNamespace(
        framework=event.framework, agent_class=event.agent_identity.agent_class,
        agent_id=event.agent_identity.spiffe_id, payload=payload,
    )


def test_a_workload_token_cannot_tag_its_own_calls_synthetic(harness: _Harness) -> None:
    """The workload's own call, tagged "redteam", is still that workload's behaviour: it registers, its
    history and profile (which drive trust) are written, it is drawn into the graph, and its row counts
    as real traffic. The claimed tag survives on the audit record."""
    decision = _post(harness, _workload_token(), "redteam")
    assert decision["decision"] == "block"

    (event,) = harness.seen
    assert event.framework == "", "the engine was handed the caller's synthetic tag"
    assert _WRITERS <= set(harness.queued), harness.queued
    assert _SVID in harness.cache.trust, "the trust key is the agent's roster entry"

    (emitted, _decision, payload) = harness.emitter.rows[0]
    assert emitted.framework == ""
    assert (payload or {}).get("claimed_framework") == "redteam"
    assert not is_non_real_row(_row(emitted, payload)), "the row must count as real traffic"

    (live,) = harness.hub.records
    assert live["non_real"] is False and live.get("claimed_framework") == "redteam"


@pytest.mark.parametrize("tag", ["attack-graph", "probe", "red-team", "policy-tester", " RedTeam "])
def test_every_synthetic_tag_is_bound_not_only_redteam(harness: _Harness, tag: str) -> None:
    _post(harness, _workload_token(), tag)
    assert harness.seen[0].framework == ""
    assert _WRITERS <= set(harness.queued), harness.queued


def test_a_non_synthetic_framework_from_a_workload_is_unchanged(harness: _Harness) -> None:
    """Control: the sidecar's own source label passes straight through and nothing is claimed."""
    _post(harness, _workload_token(), "sidecar")
    assert harness.seen[0].framework == "sidecar"
    (_e, _d, payload) = harness.emitter.rows[0]
    assert "claimed_framework" not in (payload or {})
    assert harness.hub.records[0].get("claimed_framework") is None


def test_an_admin_red_team_call_still_counts_as_synthetic(harness: _Harness) -> None:
    """`norviq redteam run` posts with the admin token `norviq login` mints. Its calls stay synthetic:
    no per-identity state, and the row is excluded from real traffic."""
    _post(harness, _token("admin", namespace="*"), "redteam", svid=f"spiffe://norviq/ns/{_NS}/sa/{_CLASS}")
    assert harness.seen[0].framework == "redteam"
    assert not (_WRITERS & set(harness.queued)), harness.queued
    assert harness.cache.trust == {}
    (emitted, _d, payload) = harness.emitter.rows[0]
    assert emitted.framework == "redteam" and "claimed_framework" not in (payload or {})
    assert is_non_real_row(_row(emitted, payload))


def test_a_console_viewer_s_simulate_still_counts_as_synthetic(harness: _Harness) -> None:
    """The graph page's Simulate runs as the signed-in user, and a viewer may use it. It evaluates as the
    path's REAL workload identity, so if its tag were dropped it would write that agent's state."""
    _post(harness, _token("viewer"), "attack-graph")
    assert harness.seen[0].framework == "attack-graph"
    assert not (_WRITERS & set(harness.queued)), harness.queued


def test_the_console_red_team_runner_still_counts_as_synthetic(harness: _Harness) -> None:
    """The console runner evaluates in process, not through /evaluate, and its calls stay synthetic."""
    from norviq.redteam.attacks import ATTACKS

    resp = harness.client.post(
        f"/api/v1/redteam/run?attack_id={ATTACKS[0].id}&target_agent={_CLASS}&target_namespace={_NS}",
        headers={"Authorization": f"Bearer {_token('admin', namespace='*')}"},
    )
    assert resp.status_code == 200, resp.text
    assert harness.seen[0].framework == "redteam"
    assert not (_WRITERS & set(harness.queued)), harness.queued
    (emitted, _d, _p) = harness.emitter.rows[0]
    assert is_non_real_traffic(emitted.framework, emitted.agent_identity.agent_class, emitted.agent_identity.spiffe_id)


@pytest.mark.parametrize(
    ("user", "allowed"),
    [
        ({"role": "admin", "namespace": "*"}, True),
        ({"role": "viewer", "namespace": "team-a"}, True),
        ({"role": "Admin"}, True),
        # Machine principals: sidecar / SDK / controller / fleet relay, and an agent's service key.
        ({"role": "service", "namespace": "team-a"}, False),
        ({"role": "service", "namespace": "", "agent_class": "x", "spiffe_id": _SVID}, False),
        # Any agent-identity claim makes it a workload credential, whatever the role says.
        ({"role": "viewer", "namespace": "team-a", "agent_class": "x"}, False),
        ({"role": "admin", "spiffe_id": _SVID}, False),
        ({"role": "viewer", "workload": "billing"}, False),
        ({"role": ""}, False),
        ({}, False),
    ],
)
def test_who_may_tag_synthetic(user: dict, allowed: bool) -> None:
    # Read through the module so the route tests above still run, and fail on behaviour, on a tree
    # without these helpers.
    assert auth_mod.may_tag_synthetic(user) is allowed
    expected = ("redteam", "") if allowed else ("", "redteam")
    assert auth_mod.bind_framework(user, "redteam") == expected
    # A non-synthetic value is never touched, for anyone.
    assert auth_mod.bind_framework(user, "langchain") == ("langchain", "")
    assert auth_mod.bind_framework(user, None) == ("", "")


def test_the_audit_api_returns_the_claimed_tag() -> None:
    """The record a caller reads back carries the claim, and the classifier still calls the row real."""
    from datetime import datetime, timezone

    from norviq.api.routers.audit import _to_dict

    row = SimpleNamespace(
        id="1", event_id="e", tool_name="issue_refund", decision="allow", agent_id=_SVID, namespace=_NS,
        rule_id="r", reason="", agent_class=_CLASS, session_id="s", trust_score=0.9, latency_ms=1.0,
        framework="", timestamp_utc=datetime.now(timezone.utc), payload={"claimed_framework": "redteam"},
    )
    out = _to_dict(row)
    assert out.get("claimed_framework") == "redteam" and out["non_real"] is False
    row.payload = None
    assert _to_dict(row).get("claimed_framework") is None
