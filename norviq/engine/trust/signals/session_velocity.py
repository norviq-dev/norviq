# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Session velocity trust signal."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class SessionVelocitySignal(BaseSignal):
    """Score trust by calls/minute against baseline."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from baseline ratio buckets."""
        baseline = float(profile.get("baseline_rpm", 10) or 10)
        window_start = input_data.timestamp - timedelta(seconds=60)
        recent = [entry for entry in history if self._in_window(entry, window_start)]
        ratio = (len(recent) + 1) / baseline
        if ratio <= 1.0:
            return 1.0
        if ratio <= 2.0:
            return 0.8
        return 0.5 if ratio <= 3.0 else 0.3

    def _in_window(self, entry: dict[str, Any], window_start: datetime) -> bool:
        """Return true when entry timestamp is within rolling minute."""
        raw = entry.get("timestamp")
        if isinstance(raw, str):
            raw = datetime.fromisoformat(raw)
        if isinstance(raw, datetime):
            ts = raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
            return ts >= window_start
        return True
