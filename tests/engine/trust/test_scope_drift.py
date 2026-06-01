# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.scope_drift import ScopeDriftSignal


async def test_scope_drift_blocks_blocked_tool() -> None:
    signal = ScopeDriftSignal()
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "danger", {}, "s", 0, datetime.now(timezone.utc)),
        [],
        {"blocked_tools": ["danger"]},
    )
    assert value == 0.0
