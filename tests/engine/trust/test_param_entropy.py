# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.param_entropy import ParamEntropySignal


async def test_param_entropy_detects_anomaly() -> None:
    signal = ParamEntropySignal()
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "search", {"x": "A1B2C3D4E5F6G7H8I9J0"}, "s", 0, datetime.now(timezone.utc)),
        [],
        {"param_entropy_baseline": {"search": {"mean": 1.0, "std": 0.3}}},
    )
    assert value in {0.4, 0.2}
