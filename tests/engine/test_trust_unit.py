# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Focused unit tests for trust calculator boundaries."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from norviq.engine.trust.calculator import TrustCalculator
from norviq.engine.trust.history import AgentHistoryStore
from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.profile import AgentProfileStore


class _RedisClientStub:
    async def get(self, key: str):
        return None

    async def setex(self, key: str, ttl: int, value: str) -> None:
        return None

    class _PipelineCtx:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> bool:
            return False

        async def hgetall(self, key: str) -> None:
            return None

        async def get(self, key: str) -> None:
            return None

        async def execute(self):
            return {}, {}, None

    def pipeline(self, transaction: bool = False):
        return self._PipelineCtx()


class _CacheStub:
    def _client(self):
        return _RedisClientStub()


@pytest.fixture
def calculator() -> TrustCalculator:
    cache = _CacheStub()
    history = AgentHistoryStore(cache)  # type: ignore[arg-type]
    profile = AgentProfileStore(cache)  # type: ignore[arg-type]
    return TrustCalculator(cache, history, profile)  # type: ignore[arg-type]


def test_trust_categorization_boundaries(calculator: TrustCalculator) -> None:
    assert calculator._categorize(0.0, is_manually_frozen=False) == "low"
    assert calculator._categorize(0.39, is_manually_frozen=False) == "low"
    assert calculator._categorize(0.40, is_manually_frozen=False) == "medium"
    assert calculator._categorize(0.70, is_manually_frozen=False) == "high"
    assert calculator._categorize(0.99, is_manually_frozen=True) == "frozen"


def test_weighted_sum_uses_declared_weights(calculator: TrustCalculator) -> None:
    signals = {
        "violation_rate": 1.0,
        "tool_novelty": 0.0,
        "scope_drift": 1.0,
        "param_entropy": 0.0,
        "time_decay": 1.0,
        "chain_depth": 0.0,
        "session_velocity": 1.0,
    }
    score = calculator._weighted_sum(signals)
    assert score == pytest.approx(0.55, rel=1e-3)


@pytest.mark.asyncio
async def test_calculate_does_not_auto_freeze_at_zero_score(calculator: TrustCalculator, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_signals(input_data: TrustInput, history: list[dict], profile: dict) -> dict[str, float]:
        return {name: 0.0 for name in calculator.WEIGHTS}

    monkeypatch.setattr(calculator, "_safe_history", lambda spiffe_id: asyncio.sleep(0, result=[]))
    monkeypatch.setattr(
        calculator,
        "_safe_profile_and_frozen",
        lambda input_data: asyncio.sleep(0, result=({"known_tools": []}, False)),
    )
    monkeypatch.setattr(calculator, "_compute_signals", _fake_signals)

    result = await calculator.calculate(
        TrustInput(
            spiffe_id="spiffe://norviq/ns/default/sa/test",
            namespace="default",
            agent_class="test",
            tool_name="sample",
            tool_params={},
            session_id="s1",
            chain_depth=0,
            timestamp=datetime.now(timezone.utc),
        )
    )
    assert result.score == 0.0
    assert result.category == "low"
