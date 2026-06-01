# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.chain_depth import ChainDepthSignal


async def test_chain_depth_penalizes_deep_delegation() -> None:
    signal = ChainDepthSignal()
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "tool", {}, "s", 3, datetime.now(timezone.utc)),
        [],
        {},
    )
    assert value == 0.4
