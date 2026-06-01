# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Violation-rate trust signal."""

from __future__ import annotations

from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class ViolationRateSignal(BaseSignal):
    """Score trust by rolling block decision percentage."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from violation-rate buckets."""
        _ = input_data, profile
        if not history:
            return 1.0
        blocked = sum(1 for entry in history if entry.get("decision") == "block")
        rate = blocked / len(history)
        if rate == 0:
            return 1.0
        if rate <= 0.02:
            return 0.8
        if rate <= 0.05:
            return 0.6
        if rate <= 0.10:
            return 0.4
        return 0.2 if rate <= 0.20 else 0.0
