# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Trust calculator orchestrating seven behavioral signals."""

from __future__ import annotations
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import json

import structlog

from norviq.engine.cache import RedisCache
from norviq.engine.trust.history import AgentHistoryStore
from norviq.engine.trust.models import TrustInput, TrustResult
from norviq.engine.trust.profile import AgentProfileStore
from norviq.engine.trust.signals import (
    ChainDepthSignal,
    ParamEntropySignal,
    ScopeDriftSignal,
    SessionVelocitySignal,
    TimeDecaySignal,
    ToolNoveltySignal,
    ViolationRateSignal,
)

log = structlog.get_logger()


class TrustCalculator:
    """Compute weighted trust score from seven anomaly signals."""

    WEIGHTS = {
        "violation_rate": 0.25,
        "tool_novelty": 0.20,
        "scope_drift": 0.15,
        "param_entropy": 0.15,
        "time_decay": 0.10,
        "chain_depth": 0.10,
        "session_velocity": 0.05,
    }

    def __init__(self, cache: RedisCache, history: AgentHistoryStore, profile: AgentProfileStore) -> None:
        """Bind cache and data stores for trust calculations."""
        self._cache = cache
        self._history = history
        self._profile = profile
        self._signals = {
            "violation_rate": ViolationRateSignal(),
            "tool_novelty": ToolNoveltySignal(),
            "scope_drift": ScopeDriftSignal(),
            "param_entropy": ParamEntropySignal(),
            "time_decay": TimeDecaySignal(),
            "chain_depth": ChainDepthSignal(),
            "session_velocity": SessionVelocitySignal(),
        }
        self._tasks: set[asyncio.Task[None]] = set()

    async def calculate(self, input_data: TrustInput) -> TrustResult:
        """Calculate trust score and persist short-lived breakdown."""
        log.debug("nrvq.engine.trust.started", spiffe_id=input_data.spiffe_id, code="NRVQ-ENG-2040")
        history, profile_and_frozen = await asyncio.gather(
            self._safe_history(input_data.spiffe_id),
            self._safe_profile_and_frozen(input_data),
        )
        profile, is_frozen = profile_and_frozen
        signals = await self._compute_signals(input_data, history, profile)
        score = 0.0 if is_frozen else self._weighted_sum(signals)
        category = self._categorize(score, is_manually_frozen=is_frozen)
        result = TrustResult(
            score=score,
            category=category,
            signals=signals,
            weights=self.WEIGHTS.copy(),
            dominant_signal=self._find_dominant_signal(signals),
            recommendation=self._recommend(score, category),
        )
        task = asyncio.create_task(self._persist(input_data.spiffe_id, result))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        log.info("nrvq.engine.trust.completed", spiffe_id=input_data.spiffe_id, score=score, code="NRVQ-ENG-2041")
        return result

    async def _compute_signals(self, input_data: TrustInput, history: list[dict], profile: dict) -> dict[str, float]:
        """Compute every signal with safe fallback."""
        values: dict[str, float] = {}
        for name, signal in self._signals.items():
            try:
                value = await signal.compute(input_data, history, profile)
                values[name] = max(0.0, min(1.0, float(value)))
            except Exception as exc:  # pragma: no cover
                log.warning("nrvq.engine.trust.signal_failed", signal=name, error=str(exc), code="NRVQ-ENG-2042")
                values[name] = 0.5
        return values

    async def _safe_history(self, spiffe_id: str) -> list[dict]:
        """Fetch history while preserving calculator availability."""
        try:
            return await self._history.get_history(spiffe_id)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.history_failed", error=str(exc), code="NRVQ-ENG-2043")
            now = datetime.now(timezone.utc).isoformat()
            return [{"decision": "block", "timestamp": now}] * 20

    async def _safe_profile_and_frozen(self, input_data: TrustInput) -> tuple[dict, bool]:
        """Fetch profile/class constraints and frozen flag in one round trip."""
        defaults = {
            "known_tools": [],
            "allowed_tools": [],
            "blocked_tools": [],
            "baseline_rpm": 10.0,
            "param_entropy_baseline": {},
            "agent_class": input_data.agent_class,
        }
        conservative = {
            **defaults,
            "blocked_tools": [input_data.tool_name],
            "baseline_rpm": 1.0,
            "param_entropy_baseline": {input_data.tool_name: {"mean": 1.0, "std": 0.2}},
        }
        try:
            if not all(
                hasattr(self._profile, attr) for attr in ("_key", "_decode_profile", "_decode_class_constraints")
            ):
                profile = await self._safe_profile_only(input_data, conservative)
                frozen = await self._safe_frozen_only(input_data.spiffe_id)
                return profile, frozen
            client = self._cache._client()
            profile_key = self._profile._key(input_data.spiffe_id)
            class_key = f"agent_class:{input_data.agent_class}" if input_data.agent_class else ""
            frozen_key = f"agent_frozen:{input_data.spiffe_id}"
            async with client.pipeline(transaction=False) as pipe:
                await pipe.hgetall(profile_key)
                if class_key:
                    await pipe.hgetall(class_key)
                else:
                    await pipe.hgetall("__none__")
                await pipe.get(frozen_key)
                profile_row, class_row, frozen_raw = await pipe.execute()
            profile = {
                **defaults,
                **self._profile._decode_profile(profile_row),
                **self._profile._decode_class_constraints(class_row),
            }
            return profile, bool(frozen_raw)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.profile_failed", error=str(exc), code="NRVQ-ENG-2044")
            return conservative, await self._safe_frozen_only(input_data.spiffe_id)

    async def _safe_profile_only(self, input_data: TrustInput, defaults: dict) -> dict:
        """Fallback profile fetch for test doubles and compatibility."""
        try:
            profile = await self._profile.get_profile(input_data.spiffe_id, input_data.agent_class)
            return {
                "known_tools": [],
                "allowed_tools": [],
                "blocked_tools": [],
                "baseline_rpm": 10.0,
                "param_entropy_baseline": {},
                "agent_class": input_data.agent_class,
                **profile,
            }
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.profile_failed", error=str(exc), code="NRVQ-ENG-2044")
            return defaults

    async def _safe_frozen_only(self, spiffe_id: str) -> bool:
        """Return true when admin freeze is set; fail closed on Redis errors."""
        try:
            return bool(await self._cache._client().get(f"agent_frozen:{spiffe_id}"))
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.freeze_check_failed", error=str(exc), code="NRVQ-ENG-2050")
            return True

    async def _persist(self, spiffe_id: str, result: TrustResult) -> None:
        """Persist trust breakdown in background task."""
        try:
            await self._cache._client().setex(f"trustcalc:{spiffe_id}", 30, json.dumps(asdict(result)))
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.cache_failed", error=str(exc), code="NRVQ-ENG-2049")

    def _weighted_sum(self, signals: dict[str, float]) -> float:
        """Return weighted trust score for all signals."""
        return round(sum(self.WEIGHTS[name] * signals.get(name, 0.0) for name in self.WEIGHTS), 4)

    def _categorize(self, score: float, is_manually_frozen: bool = False) -> str:
        """Map score into trust tiers."""
        if is_manually_frozen:
            return "frozen"
        # Spec guardrail: computed score never auto-freezes; frozen is admin-only.
        if score == 0.0:
            return "low"
        return "high" if score >= 0.7 else "medium" if score >= 0.4 else "low"

    def _find_dominant_signal(self, signals: dict[str, float]) -> str:
        """Return signal that reduced trust the most."""
        return max(signals, key=lambda name: self.WEIGHTS.get(name, 0.0) * (1.0 - signals[name]), default="violation_rate")

    def _recommend(self, score: float, category: str) -> str:
        """Return enforcement recommendation from score."""
        if category == "frozen":
            return "freeze"
        return "escalate" if score < 0.4 else "allow"
