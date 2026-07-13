# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.violation_rate import ViolationRateSignal


async def test_violation_rate_drops_at_ten_percent() -> None:
    signal = ViolationRateSignal()
    history = [{"decision": "allow"}] * 9 + [{"decision": "block"}]
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "tool", {}, "s", 0, datetime.now(timezone.utc)), history, {}
    )
    assert value == 0.4
