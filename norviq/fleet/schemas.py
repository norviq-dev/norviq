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
    labels: dict[str, str] = {}     # P2: target_selector matching
    residency: bool = False         # P4: this spoke keeps raw audit in-cluster
    spiffe_id: str = ""             # S3: the spoke's attested SPIFFE identity (workload-api mode)
    console_url: str = ""           # F-69: the spoke's own console URL (drives the hub deep-link)


class PolicyAuthorBody(BaseModel):
    """Author/update a fleet policy (admin only)."""

    name: str = Field(min_length=1)
    namespace: str
    agent_class: str
    rego_source: str
    priority: int = 100
    enforcement_mode: str = "block"
    target_selector: dict[str, str] = {}   # {"env":"prod"} or {"cluster_id":"cluster-a"} (override)
    # F-40: a fleet-wide push (no cluster_id in the selector -> matches >1 cluster) must set this explicitly.
    confirm_fleet_wide: bool = False


class RolloutReportBody(BaseModel):
    """A spoke reports the outcome of applying a bundle."""

    bundle_version: int
    state: str                              # applied | failed
    applied_version: int = 0
    detail: str = ""


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
