# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team attack simulator."""

from __future__ import annotations

import json as json_mod
import os
import uuid

import httpx
import pytest

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.redteam.attacks import AttackCategory, get_attack_by_id
from norviq.redteam.simulator import AttackSimulator, SuiteReport
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
# The transport below does what POST /api/v1/evaluate does with the body (ToolCallEvent from the
# payload minus `trust_score`, `evaluator.evaluate`, a flat response), so these runs exercise the
# real `_maybe_rate_limit`: a Redis counter keyed on the SPIFFE id, fixed window, counting only calls
# whose decision resolved to `allow` and whose tool is not read-exempt.


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

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json_mod.loads(request.content)
        posts[body["session_id"]] = posts.get(body["session_id"], 0) + 1
        body.pop("trust_score", None)
        decision = await engine.evaluate(ToolCallEvent.model_validate(body))
        return httpx.Response(
            200,
            json={"decision": decision.decision, "rule_id": decision.rule_id, "trust_score": decision.trust_score},
        )

    sim = AttackSimulator("http://norviq.test")
    await sim.close()
    sim._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
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
