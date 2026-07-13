# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Data models for trust calculation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class TrustInput:
    """All data needed to compute trust score."""

    spiffe_id: str
    namespace: str
    agent_class: str
    tool_name: str
    tool_params: dict[str, Any]
    session_id: str
    chain_depth: int
    timestamp: datetime


@dataclass(slots=True)
class TrustResult:
    """Trust calculation result with signal breakdown."""

    score: float
    category: str
    signals: dict[str, float]
    weights: dict[str, float]
    dominant_signal: str
    recommendation: str
