# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.tool_novelty import ToolNoveltySignal


async def test_tool_novelty_penalizes_unknown_tool() -> None:
    signal = ToolNoveltySignal()
    value = await signal.compute(
        TrustInput("spiffe://a", "ns", "cls", "unknown", {}, "s", 0, datetime.now(timezone.utc)),
        [{"tool_name": "search_kb"}],
        {"known_tools": ["search_kb"]},
    )
    assert value == 0.2
