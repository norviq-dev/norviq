# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Pydantic request/response contracts for the fleet hub (never trust a raw dict)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class HeartbeatBody(BaseModel):
    """Cluster self-identification on heartbeat."""

    name: str = ""
    endpoint: str = ""
    region: str = ""


class AgentRollupIn(BaseModel):
    """One agent's rolled-up trust, pushed by a spoke relay."""

    spiffe_id: str
    namespace: str = ""
    agent_class: str = ""
    trust_score: float = 0.8
    trust_category: str = "High"
    last_seen: datetime | None = None


class AuditRollupIn(BaseModel):
    """One pre-aggregated audit counter bucket (cluster_id is taken from the path, not here)."""

    namespace: str = ""
    bucket_ts: datetime
    decision: str
    count: int = Field(ge=0)


class RollupBody(BaseModel):
    """The periodic rollup payload from a spoke relay."""

    agents: list[AgentRollupIn] = []
    audit: list[AuditRollupIn] = []
