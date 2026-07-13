# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tool novelty trust signal."""

from __future__ import annotations

from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class ToolNoveltySignal(BaseSignal):
    """Score trust by baseline tool familiarity."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from novel-tool rate."""
        known = set(profile.get("known_tools", []))
        if not known:
            return 0.5
        recent = [entry.get("tool_name") for entry in history[-20:]]
        extra = 0 if input_data.tool_name in known else 1
        novel = sum(1 for name in recent if name not in known) + extra
        rate = novel / max(1, len(recent) + extra)
        if input_data.tool_name in known:
            return 1.0 if rate <= 0.10 else 0.7 if rate <= 0.30 else 0.5
        return 0.7 if rate <= 0.10 else 0.4 if rate <= 0.30 else 0.2
