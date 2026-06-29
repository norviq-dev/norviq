# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet hub data model (F045). A SEPARATE DeclarativeBase from the spoke `Base` so fleet tables are
NEVER created in a spoke's norviq DB (and the spoke's tables are never created in the fleet DB)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FleetBase(DeclarativeBase):
    """Declarative metadata root for the fleet hub store (independent of the spoke Base)."""


class Cluster(FleetBase):
    """A registered spoke cluster; upsert by id, refreshed on each heartbeat."""

    __tablename__ = "cluster"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    endpoint: Mapped[str] = mapped_column(String(512), default="")
    region: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(20), default="healthy")  # advisory; recomputed on read
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AgentRollup(FleetBase):
    """Per-agent rollup pushed by a spoke relay; upsert by (cluster_id, spiffe_id)."""

    __tablename__ = "agent_rollup"
    cluster_id: Mapped[str] = mapped_column(String(255), ForeignKey("cluster.id", ondelete="CASCADE"), primary_key=True)
    spiffe_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    namespace: Mapped[str] = mapped_column(String(255), default="")
    agent_class: Mapped[str] = mapped_column(String(255), default="")
    trust_score: Mapped[float] = mapped_column(Float, default=0.8)
    trust_category: Mapped[str] = mapped_column(String(10), default="High")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        Index("idx_fleet_agent_cluster_ns", "cluster_id", "namespace"),
        Index("idx_fleet_agent_category", "trust_category"),
    )


class AuditRollup(FleetBase):
    """Pre-aggregated audit counters (raw rows stay in-cluster); upsert SET-absolute by
    (cluster_id, namespace, bucket_ts, decision) so relay retries self-heal and never double-count."""

    __tablename__ = "audit_rollup"
    cluster_id: Mapped[str] = mapped_column(String(255), ForeignKey("cluster.id", ondelete="CASCADE"), primary_key=True)
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    bucket_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    decision: Mapped[str] = mapped_column(String(20), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (Index("idx_fleet_audit_cluster_bucket", "cluster_id", "bucket_ts"),)
