# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team attack simulator."""

from __future__ import annotations

import httpx
import pytest

from norviq.config import settings
from norviq.redteam.attacks import AttackCategory, get_attack_by_id
from norviq.redteam.simulator import AttackSimulator


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
async def test_rate_limit_attack_replays_until_threshold(monkeypatch) -> None:
    """Replay unbounded-consumption attacks to exceed threshold."""
    attack = get_attack_by_id("RL-001")
    assert attack is not None
    calls = {"count": 0}

    async def fake_post(self, url: str, json: dict):  # noqa: ARG001
        calls["count"] += 1
        decision = "block" if calls["count"] > settings.evaluator_rate_limit_per_window else "allow"
        return FakeResponse({"decision": decision, "rule_id": "llm10_unbounded_consumption", "trust_score": 0.8})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run(attack)
    await sim.close()
    assert calls["count"] > settings.evaluator_rate_limit_per_window
    assert result.actual_decision == "block"


@pytest.mark.asyncio
async def test_run_by_id_returns_not_found_error() -> None:
    """Handle unknown attack ID with deterministic error."""
    sim = AttackSimulator("http://localhost:8080")
    result = await sim.run_by_id("DOES-NOT-EXIST")
    await sim.close()
    assert result.actual_decision == "error"
    assert "not found" in (result.error or "")
