# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Time-decay trust signal."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class TimeDecaySignal(BaseSignal):
    """Score trust by time since last block."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from violation recency."""
        _ = profile, input_data
        blocked = [entry for entry in history if entry.get("decision") == "block"]
        if not blocked:
            return 1.0
        latest = max(self._to_dt(entry.get("timestamp")) for entry in blocked)
        age_hours = (datetime.now(timezone.utc) - latest).total_seconds() / 3600
        if age_hours >= 24:
            return 1.0
        if age_hours >= 12:
            return 0.8
        if age_hours >= 6:
            return 0.6
        if age_hours >= 1:
            return 0.4
        return 0.2 if age_hours >= (10 / 60) else 0.1

    def _to_dt(self, value: object) -> datetime:
        """Normalize history timestamps to aware UTC datetimes."""
        if isinstance(value, str):
            value = datetime.fromisoformat(value)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)
