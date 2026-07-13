# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Chain-depth trust signal."""

from __future__ import annotations

from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class ChainDepthSignal(BaseSignal):
    """Score trust by delegation chain depth."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from chain depth buckets."""
        _ = history, profile
        if input_data.chain_depth <= 0:
            return 1.0
        if input_data.chain_depth == 1:
            return 0.8
        if input_data.chain_depth == 2:
            return 0.6
        return 0.4 if input_data.chain_depth == 3 else 0.2
