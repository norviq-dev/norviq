# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timedelta, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.time_decay import TimeDecaySignal


async def test_time_decay_reflects_recent_violation() -> None:
    signal = TimeDecaySignal()
    ts = datetime.now(timezone.utc) - timedelta(minutes=5)
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "tool", {}, "s", 0, datetime.now(timezone.utc)),
        [{"decision": "block", "timestamp": ts.isoformat()}],
        {},
    )
    assert value == 0.1
