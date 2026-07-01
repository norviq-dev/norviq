# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Pydantic request/response contracts for the fleet hub (never trust a raw dict)."""

from __future__ import annotations

import re
from datetime import datetime

import structlog
from pydantic import BaseModel, Field, field_validator

log = structlog.get_logger()

_SAFE_URL = re.compile(r"^https?://", re.IGNORECASE)


class HeartbeatBody(BaseModel):
    """Cluster self-identification on heartbeat."""

    name: str = ""
    endpoint: str = ""
    region: str = ""
    labels: dict[str, str] = {}     # P2: target_selector matching
    residency: bool = False         # P4: this spoke keeps raw audit in-cluster
    spiffe_id: str = ""             # S3: the spoke's attested SPIFFE identity (workload-api mode)
    console_url: str = ""           # F-69: the spoke's own console URL (drives the hub deep-link)

    @field_validator("console_url")
    @classmethod
    def _safe_console_url(cls, v: str) -> str:
        # R1 (P1): a spoke SELF-REPORTS console_url; the hub later renders it as a link a hub admin can click. Only
        # http(s) is safe — BLANK anything else (javascript:, data:, vbscript: …) so a malicious spoke can never
        # store a stored-XSS vector across the spoke->hub-admin trust boundary. Strip (don't 422) so a bad URL
        # doesn't drop the whole heartbeat/rollup.
        v = (v or "").strip()
        if v and not _SAFE_URL.match(v):
            log.warning("nrvq.fleet.console_url_rejected", scheme=v.split(":", 1)[0][:24], code="NRVQ-FLT-15040")
            return ""
        return v


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
