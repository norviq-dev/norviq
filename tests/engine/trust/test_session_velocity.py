# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timedelta, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.session_velocity import SessionVelocitySignal


async def test_session_velocity_detects_three_x_burst() -> None:
    signal = SessionVelocitySignal()
    now = datetime.now(timezone.utc)
    history = [{"timestamp": (now - timedelta(seconds=10)).isoformat()} for _ in range(29)]
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "tool", {}, "s", 0, now),
        history,
        {"baseline_rpm": 10},
    )
    assert value == 0.5
