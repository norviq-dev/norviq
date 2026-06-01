# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Abstract signal contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from norviq.engine.trust.models import TrustInput


class BaseSignal(ABC):
    """Compute one trust signal between zero and one."""

    @abstractmethod
    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return normalized trust contribution."""
