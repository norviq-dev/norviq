# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team attack simulator."""

from __future__ import annotations

import json as json_mod
import os
import uuid
from pathlib import Path

import httpx
import pytest

from norviq.api.routers.evaluate import EvaluateRequest
from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.redteam.attacks import ATTACKS, AttackCategory, get_attack_by_id
from norviq.redteam.simulator import AttackSimulator, SuiteReport, _request_payload
from norviq.sdk.core.events import ToolCallEvent


class FakeResponse:
    """Async response test double."""

    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self._status = status

    def raise_for_status(self) -> None:
        """Raise HTTP status error for non-2xx."""
        if self._status >= 400:
            req = httpx.Request("POST", "http://localhost")
            resp = httpx.Response(self._status, request=req, json=self._payload)
            raise httpx.HTTPStatusError("boom", request=req, response=resp)

    def json(self) -> dict:
        """Return JSON payload."""
        return self._payload


@pytest.mark.asyncio
async def test_run_returns_passed_when_expected_decision_matches(monkeypatch) -> None:
    """Mark result as passed when decision matches."""
    attack = get_attack_by_id("PI-001")
    assert attack is not None

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        assert url.endswith("/api/v1/evaluate")
        assert json["tool_name"] == attack.tool_name
        return FakeResponse({"decision": "block", "rule_id": "llm01_prompt_injection", "trust_score": 0.7})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack, "customer-support", "default")
    await sim.close()
    assert result.passed is True
    assert result.actual_decision == "block"


@pytest.mark.asyncio
async def test_run_parses_nested_sidecar_decision_shape(monkeypatch) -> None:
    """Parse sidecar-style nested decision response."""
    attack = get_attack_by_id("PI-001")
    assert attack is not None

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        return FakeResponse({"action": "drop", "decision": {"decision": "block", "rule_id": "llm01_prompt_injection"}, "trust_score": 0.7})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack)
    await sim.close()
    assert result.actual_decision == "block"
    assert result.actual_rule == "llm01_prompt_injection"


@pytest.mark.asyncio
async def test_run_returns_error_on_http_failure(monkeypatch) -> None:
    """Capture API failures in result error field."""
    attack = get_attack_by_id("SQL-001")
    assert attack is not None

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        return FakeResponse({"detail": "down"}, status=500)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack)
    await sim.close()
    assert result.passed is False
    assert result.error is not None


@pytest.mark.asyncio
async def test_run_suite_filters_by_category(monkeypatch) -> None:
    """Run only selected category attacks."""
    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        return FakeResponse({"decision": "block", "rule_id": "deny_sql_injection", "trust_score": 0.8})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    report = await sim.run_suite(categories=[AttackCategory.SQL_INJECTION])
    await sim.close()
    assert report.total > 0
    assert set(report.by_category.keys()) == {"sql_injection"}


@pytest.mark.asyncio
async def test_rate_limit_attack_is_evaluated_once_like_the_console(monkeypatch) -> None:
    """RL-001 is one call with a static `allow` expectation, exactly as the console's suite runs it.

    This test used to assert the opposite: that RL-001 was replayed `evaluator_rate_limit_per_window
    + 1` times and came back `block`, against a fake server minting `llm10_unbounded_consumption`, a
    rule no policy in the tree defines. The real limiter mints `rate_limit_exceeded`, and RL-001
    expects `allow`, so the replay could only do one of two things. Under the shipped read exemption
    `search_kb` is never counted and the 61 calls measured nothing. With the exemption off the 61st
    call is throttled, RL-001 fails because the limiter WORKED, and the SPIFFE id's window is left
    over its ceiling for every attack after it (the live-engine tests below).
    """
    attack = get_attack_by_id("RL-001")
    assert attack is not None
    calls = {"count": 0}

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        calls["count"] += 1
        return FakeResponse({"decision": "allow", "rule_id": "default_allow", "trust_score": 0.8})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack)
    await sim.close()
    assert calls["count"] == 1
    assert result.passed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rule_id",
    ["rate_limit_exceeded", "evaluator_timeout", "evaluator_error", "evaluator_fallback", "policy_load_pending"],
)
async def test_a_throttled_or_faulted_block_is_never_a_pass(monkeypatch, rule_id: str) -> None:
    """A block no policy made is a miss, whatever `expected_decision` says.

    `passed` was `actual == expected`, so a fail-closed `evaluator_timeout` or a throttle scored a
    block-expected attack as PASS. The console's verdict (`redteam_efficacy._row_outcome`) has
    counted these as got_through since c243307; the CLI asks the same resolver.
    """
    attack = get_attack_by_id("EA-001")
    assert attack is not None and attack.expected_decision == "block"

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        return FakeResponse({"decision": "block", "rule_id": rule_id, "trust_score": 0.8})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack)
    await sim.close()
    assert result.actual_decision == "block"
    assert result.actual_rule == rule_id
    assert result.passed is False


# ---- against the real engine and its real limiter ---------------------------------------------
#
# The transport below does what POST /api/v1/evaluate does with the body (EvaluateRequest, then a
# ToolCallEvent from its dump minus `trust_score`, `evaluator.evaluate`, a flat response), so these
# runs exercise the real `_maybe_rate_limit`: a Redis counter keyed on the SPIFFE id, fixed window,
# counting only calls whose decision resolved to `allow` and whose tool is not read-exempt.


def _route_event(body: dict) -> ToolCallEvent:
    """The event /api/v1/evaluate builds from a body (routers/evaluate.py::evaluate_tool_call).

    Through EvaluateRequest, not straight into ToolCallEvent: a field the request model does not
    declare is dropped there, and that is exactly the kind of loss these tests have to see.
    """
    req = EvaluateRequest.model_validate(body)
    return ToolCallEvent.model_validate({**req.model_dump(exclude={"trust_score"}), "agent_identity": req.agent_identity})


async def _cli_simulator(engine: OPAEvaluator, posts: dict[str, int] | None = None) -> AttackSimulator:
    """An AttackSimulator whose /api/v1/evaluate is `engine`, reached the way the route reaches it."""

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json_mod.loads(request.content)
        if posts is not None:
            posts[body["session_id"]] = posts.get(body["session_id"], 0) + 1
        decision = await engine.evaluate(_route_event(body))
        return httpx.Response(
            200,
            json={"decision": decision.decision, "rule_id": decision.rule_id, "trust_score": decision.trust_score},
        )

    sim = AttackSimulator("http://norviq.test")
    await sim.close()
    sim._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return sim


@pytest.fixture
async def live_engine(seeded_loader) -> OPAEvaluator:
    """OPAEvaluator on real Redis with comprehensive.rego as the cluster baseline."""
    url = os.getenv("NRVQ_REDIS_URL")
    if not url:
        pytest.fail("NRVQ_REDIS_URL must be set for the live-engine simulator tests")
    cache = RedisCache(url=url)
    await cache.connect()
    engine = OPAEvaluator(cache)
    engine.bind_loader(seeded_loader)
    yield engine
    await engine.close()
    await cache.close()


async def _live_suite(engine: OPAEvaluator) -> tuple[SuiteReport, dict[str, int]]:
    """Run the whole suite through the engine under a fresh identity; return it and the POSTs per attack.

    Fresh namespace AND agent: the counter key is the SPIFFE id, and a namespace another test left
    a `rate_limit` or monitor posture on in the Redis mirror would change what the limiter does.
    """
    posts: dict[str, int] = {}
    sim = await _cli_simulator(engine, posts)
    suffix = uuid.uuid4().hex[:10]
    report = await sim.run_suite(f"rt-agent-{suffix}", f"rt-ns-{suffix}")
    await sim.close()
    return report, posts


@pytest.mark.asyncio
async def test_live_rate_limit_attack_does_not_throttle_the_attacks_after_it(live_engine, monkeypatch) -> None:
    """RL-001 must not spend the identity's window that every later attack is evaluated under.

    Read exemption OFF is the configuration that makes the old flood count: with it on, RL-001's
    `search_kb` is exempt and the replay was inert. Measured before the fix, in this configuration:
    RL-001 failed on its own 61st call, CE-002 (expects allow) failed on `rate_limit_exceeded`, and
    seven attacks the baseline does not block (CE-001, FIN-001, PHI-001, OT-001, MCP-01..03) PASSED
    on `rate_limit_exceeded` — 32/34 reported against 27/34 real.
    """
    monkeypatch.setattr(settings, "evaluator_rate_limit_read_exempt", False)
    report, posts = await _live_suite(live_engine)
    by_id = {r.attack_id: r for r in report.results}
    assert [r.attack_id for r in report.results if r.actual_rule == "rate_limit_exceeded"] == []
    assert (by_id["CE-002"].passed, by_id["CE-002"].actual_rule) == (True, "default_allow")
    assert (by_id["RL-001"].passed, by_id["RL-001"].actual_rule) == (True, "default_allow")
    assert posts["redteam-RL-001"] == 1


@pytest.mark.asyncio
async def test_live_throttled_miss_is_reported_as_a_failure(live_engine, monkeypatch) -> None:
    """When the limiter does refuse an attack, the report must not call it blocked.

    Independent of RL-001: a ceiling of 3 (the per-namespace `rate_limit` knob does the same) is
    exceeded by the suite's own misses, because only an allow is counted. Measured before the fix
    at this ceiling: PHI-001, OT-001 and MCP-01..03 were throttled and PASSED.
    """
    monkeypatch.setattr(settings, "evaluator_rate_limit_per_window", 3)
    report, _ = await _live_suite(live_engine)
    throttled = [r for r in report.results if r.actual_rule == "rate_limit_exceeded"]
    assert throttled, "the limiter never engaged, so this run proves nothing"
    assert [(r.attack_id, r.passed) for r in throttled] == [(r.attack_id, False) for r in throttled]
    assert report.passed == sum(r.passed for r in report.results)


@pytest.mark.asyncio
async def test_run_by_id_returns_not_found_error() -> None:
    """Handle unknown attack ID with deterministic error."""
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run_by_id("DOES-NOT-EXIST")
    await sim.close()
    assert result.actual_decision == "error"
    assert "not found" in (result.error or "")


# ---- the CLI and the console make the same call ------------------------------------------------
#
# The console's suite builds a ToolCallEvent per attack (routers/redteam.py::_build_event); the CLI
# posts a body to /api/v1/evaluate. They had separate builders, and the CLI's sent neither
# `call_depth` nor `mcp`.

_GUARDRAIL = Path(__file__).resolve().parents[2] / "policies" / "templates" / "mcp_integration_guardrail.rego"
_EVENT_FIELDS_ONLY = {"event_id", "timestamp_utc"}  # minted per event, so never equal across two builds


def test_the_cli_request_is_the_console_event_for_every_attack() -> None:
    """What the engine is handed must not depend on which runner asked.

    Before the fix: CE-001 arrived at depth 0 instead of 12, and MCP-01..03 with `mcp: {}` instead of
    their forged Gate-A context.
    """
    from norviq.api.routers.redteam import _build_event

    drifted = [
        attack.id
        for attack in ATTACKS
        if _route_event(_request_payload(attack, "billing-agent", "payments")).model_dump(exclude=_EVENT_FIELDS_ONLY)
        != _build_event(attack, "billing-agent", "payments").model_dump(exclude=_EVENT_FIELDS_ONLY)
    ]
    assert drifted == []


@pytest.mark.asyncio
async def test_live_ce001_and_mcp_attacks_decide_the_same_through_both_runners(live_engine, seeded_loader) -> None:
    """The four attacks the drift affected, through the real engine with the MCP guardrail loaded.

    CE-001 and MCP-01 must also come back as blocks, or "the same" could be two allows. MCP-02 and
    MCP-03 are allowed by design either way (the server id and pin status they forge are trusted by the
    guardrail; see attacks.py), so for them the request test above is the one that discriminates.
    Measured before the fix through the CLI: CE-001 allow/default_allow and MCP-01 allow/default_allow,
    against block/chain_depth_limit and block/mcp_unregistered_server through the console.
    """
    from norviq.api.routers.redteam import _build_event

    suffix = uuid.uuid4().hex[:10]
    ns = f"rt-ns-{suffix}"
    seeded_loader._policies[f"{ns}:__guardrail__"] = {"rego": _GUARDRAIL.read_text(encoding="utf-8"), "priority": 100}
    sim = await _cli_simulator(live_engine)
    via: dict[str, dict[str, tuple[str, str]]] = {"cli": {}, "console": {}}
    for attack_id in ("CE-001", "MCP-01", "MCP-02", "MCP-03"):
        attack = get_attack_by_id(attack_id)
        assert attack is not None
        # Separate classes, so neither path can be served the other's cached decision.
        cli = await sim.run(attack, f"cli-{suffix}", ns)
        via["cli"][attack_id] = (cli.actual_decision, cli.actual_rule)
        console = await live_engine.evaluate(_build_event(attack, f"console-{suffix}", ns))
        via["console"][attack_id] = (console.decision, console.rule_id)
    await sim.close()
    assert via["cli"] == via["console"]
    assert via["console"]["CE-001"] == ("block", "chain_depth_limit")
    assert via["console"]["MCP-01"] == ("block", "mcp_unregistered_server")
