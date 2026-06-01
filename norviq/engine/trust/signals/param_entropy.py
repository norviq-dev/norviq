# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Parameter entropy trust signal."""

from __future__ import annotations

import json
import math
from collections import Counter
from typing import Any

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.base import BaseSignal


class ParamEntropySignal(BaseSignal):
    """Score trust by entropy spike against baseline."""

    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return trust score from entropy z-score."""
        _ = history
        entropy = self.entropy_of_params(input_data.tool_params)
        baseline = profile.get("param_entropy_baseline", {}).get(input_data.tool_name, {})
        mean, std = float(baseline.get("mean", 4.0)), float(baseline.get("std", 1.0) or 1.0)
        z_score = (entropy - mean) / std
        if z_score <= 1.0:
            return 1.0
        if z_score <= 2.0:
            return 0.7
        return 0.4 if z_score <= 3.0 else 0.2

    @staticmethod
    def entropy_of_params(params: dict[str, Any]) -> float:
        """Return Shannon entropy for sorted JSON parameters."""
        return ParamEntropySignal._entropy(json.dumps(params, sort_keys=True))

    @staticmethod
    def _entropy(payload: str) -> float:
        """Return Shannon entropy for a string payload."""
        if not payload:
            return 0.0
        length = len(payload)
        counts = Counter(payload)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
