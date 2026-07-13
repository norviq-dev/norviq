# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from __future__ import annotations

from datetime import datetime, timezone
import time

from norviq.engine.trust.calculator import TrustCalculator
from norviq.engine.trust.models import TrustInput


class _RedisStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}

    async def setex(self, key: str, ttl: int, value: str) -> None:
        _ = ttl
        self.last = (key, ttl, value)
        self.values[key] = value

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def hgetall(self, key: str) -> dict[str, str]:
        return self.hashes.get(key, {})

    def pipeline(self, transaction: bool = False):
        _ = transaction
        return _PipelineStub(self)


class _PipelineStub:
    def __init__(self, client: _RedisStub) -> None:
        self.client = client
        self.ops: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        _ = exc_type, exc, tb
        return False

    async def hgetall(self, key: str) -> None:
        self.ops.append(("hgetall", key))

    async def get(self, key: str) -> None:
        self.ops.append(("get", key))

    async def execute(self):
        results: list[object] = []
        for op, key in self.ops:
            if op == "hgetall":
                results.append(await self.client.hgetall(key))
            else:
                results.append(await self.client.get(key))
        return results


class _CacheStub:
    def __init__(self) -> None:
        self.client = _RedisStub()

    def _client(self) -> _RedisStub:
        return self.client


class _HistoryStub:
    async def get_history(self, spiffe_id: str) -> list[dict]:
        _ = spiffe_id
        return []

    async def record(self, spiffe_id: str, entry: dict) -> None:
        _ = spiffe_id, entry


class _ProfileStub:
    async def get_profile(self, spiffe_id: str, agent_class: str) -> dict:
        _ = spiffe_id, agent_class
        return {"known_tools": ["search_kb"], "baseline_rpm": 20}

    async def update_profile(
        self,
        spiffe_id: str,
        tool_name: str,
        param_entropy: float,
        observed_rpm: float,
        decision: str,
    ) -> None:
        _ = spiffe_id, tool_name, param_entropy, observed_rpm, decision


async def test_calculator_returns_high_for_clean_agent() -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())
    result = await calc.calculate(
        TrustInput(
            spiffe_id="spiffe://norviq/ns/default/sa/chatbot",
            namespace="default",
            agent_class="support",
            tool_name="search_kb",
            tool_params={"q": "hello"},
            session_id="s-1",
            chain_depth=0,
            timestamp=datetime.now(timezone.utc),
        )
    )
    assert result.score > 0.7
    assert result.category == "high"
    assert set(result.signals) == set(calc.WEIGHTS)


async def test_calculator_returns_frozen_for_frozen_input() -> None:
    cache = _CacheStub()
    cache.client.values["agent_frozen:spiffe://norviq/ns/default/sa/chatbot"] = "1"
    calc = TrustCalculator(cache, _HistoryStub(), _ProfileStub())
    result = await calc.calculate(
        TrustInput(
            spiffe_id="spiffe://norviq/ns/default/sa/chatbot",
            namespace="default",
            agent_class="support",
            tool_name="search_kb",
            tool_params={"q": "hello"},
            session_id="s-1",
            chain_depth=0,
            timestamp=datetime.now(timezone.utc),
        )
    )
    assert result.score == 0.0
    assert result.category == "frozen"
    assert result.recommendation == "freeze"


def test_weighted_sum_matches_manual_calculation() -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())
    signals = {
        "violation_rate": 0.8,
        "tool_novelty": 1.0,
        "scope_drift": 1.0,
        "param_entropy": 0.7,
        "time_decay": 0.6,
        "chain_depth": 1.0,
        "session_velocity": 0.8,
    }
    expected = round(0.25 * 0.8 + 0.20 * 1.0 + 0.15 * 1.0 + 0.15 * 0.7 + 0.10 * 0.6 + 0.10 * 1.0 + 0.05 * 0.8, 4)
    assert calc._weighted_sum(signals) == expected


async def test_trust_recovers_after_old_violations_age_out() -> None:
    class _RecoveringHistory:
        def __init__(self) -> None:
            self.phase = 0

        async def get_history(self, spiffe_id: str) -> list[dict]:
            _ = spiffe_id
            if self.phase == 0:
                return [{"decision": "block", "timestamp": "2026-01-01T00:00:00+00:00"}] + [{"decision": "allow"}] * 9
            return [{"decision": "allow"}] * 20

    history = _RecoveringHistory()
    calc = TrustCalculator(_CacheStub(), history, _ProfileStub())  # type: ignore[arg-type]
    low = await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "search_kb", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    history.phase = 1
    recovered = await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "search_kb", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    assert recovered.score >= 0.7
    assert recovered.score >= low.score


async def test_no_auto_freeze_when_signals_are_zero(monkeypatch) -> None:
    """Category low not frozen when score is computed 0 (not auto freeze)."""
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())

    async def _zeros(*_: object, **__: object) -> dict[str, float]:
        return {name: 0.0 for name in calc.WEIGHTS}

    monkeypatch.setattr(calc, "_compute_signals", _zeros)
    result = await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "search_kb", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    assert result.score == 0.0
    assert result.category == "low"


def test_dominant_signal_uses_weighted_contribution() -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())
    signals = {
        "violation_rate": 0.4,
        "tool_novelty": 0.6,
        "scope_drift": 0.5,
        "param_entropy": 0.7,
        "time_decay": 0.8,
        "chain_depth": 0.9,
        "session_velocity": 0.0,
    }
    assert calc._find_dominant_signal(signals) == "violation_rate"


def test_weights_sum_to_one() -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())
    assert round(sum(calc.WEIGHTS.values()), 6) == 1.0


async def test_calculate_completes_under_five_ms_with_mocks() -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())
    start = time.perf_counter()
    await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "search_kb", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 5


async def test_redis_failures_produce_conservative_low_score(monkeypatch) -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())

    async def _history_fail(*_: object, **__: object):
        raise RuntimeError("history unavailable")

    def _profile_fail(*_: object, **__: object):
        raise RuntimeError("profile unavailable")

    monkeypatch.setattr(calc._history, "get_history", _history_fail)
    monkeypatch.setattr(calc._profile, "get_profile", _profile_fail)
    result = await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "danger", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    assert result.category == "low"
    assert result.score < 0.4


async def test_freeze_check_failure_fails_closed(monkeypatch) -> None:
    calc = TrustCalculator(_CacheStub(), _HistoryStub(), _ProfileStub())

    async def _freeze_fail(*_: object, **__: object):
        raise RuntimeError("redis down")

    monkeypatch.setattr(calc._cache._client(), "get", _freeze_fail)
    result = await calc.calculate(
        TrustInput("spiffe://a", "default", "support", "search_kb", {"q": "x"}, "s", 0, datetime.now(timezone.utc))
    )
    assert result.category == "frozen"
    assert result.recommendation == "freeze"
