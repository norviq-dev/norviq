# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Trust score schema for policy enforcement."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from norviq.config import settings


class TrustScore(BaseModel):
    """Agent trust score determining policy enforcement level."""

    score: float = 0.8
    category: str = ""
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    violation_count: int = 0
    factors: dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": True}

    @field_validator("score")
    @classmethod
    def score_in_range(cls, value: float) -> float:
        """Validate that score is between zero and one."""
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"score must be 0.0-1.0, got {value}")
        return round(value, 4)

    def __init__(self, **data: Any) -> None:
        """Populate category automatically when not provided."""
        if not data.get("category"):
            score = round(float(data.get("score", 0.8)), 4)
            if score >= settings.trust_threshold:
                data["category"] = "High"
            elif score >= 0.4:
                data["category"] = "Medium"
            else:
                data["category"] = "Low"
        super().__init__(**data)

    def after_violation(self) -> "TrustScore":
        """Return a new trust score after applying violation penalty."""
        return TrustScore(
            score=max(0.0, self.score - settings.trust_violation_penalty),
            violation_count=self.violation_count + 1,
            factors={**self.factors, "last_violation": "penalty_applied"},
        )

    def is_trusted(self) -> bool:
        """Check whether trust score passes configured threshold."""
        return self.score >= settings.trust_threshold
