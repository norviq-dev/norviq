# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Scope drift trust signal."""

from __future__ import annotations

from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class ScopeDriftSignal(BaseSignal):
    """Score trust by class tool constraints."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from allow/block lists."""
        _ = history
        allowed = set(profile.get("allowed_tools", []))
        blocked = set(profile.get("blocked_tools", []))
        if not allowed and not blocked:
            return 0.7
        if input_data.tool_name in blocked:
            return 0.0
        if input_data.tool_name in allowed:
            return 1.0
        return 0.5
