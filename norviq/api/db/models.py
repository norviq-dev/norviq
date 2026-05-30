# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""PostgreSQL persistence models for Norviq API."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative metadata root."""


class Policy(Base):
    """Active policy per namespace and agent class."""

    __tablename__ = "policies"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str] = mapped_column(String(255))
    agent_class: Mapped[str] = mapped_column(String(255))
    rego_source: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    enforcement_mode: Mapped[str] = mapped_column(String(20), default="block")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        UniqueConstraint("namespace", "agent_class", name="uq_policy_ns_class"),
        Index("idx_policy_ns_class", "namespace", "agent_class"),
    )


class PolicyVersion(Base):
    """Stored version history for a policy."""

    __tablename__ = "policy_versions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    rego_source: Mapped[str] = mapped_column(Text)
    saved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    saved_by: Mapped[str] = mapped_column(String(255), default="")
    __table_args__ = (UniqueConstraint("policy_id", "version", name="uq_policyver_id_ver"),)


class AgentRegistryEntry(Base):
    """Registered agent identity and trust score."""

    __tablename__ = "agent_registry"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    spiffe_id: Mapped[str] = mapped_column(String(512), unique=True)
    namespace: Mapped[str] = mapped_column(String(255))
    agent_class: Mapped[str] = mapped_column(String(255))
    trust_score: Mapped[float] = mapped_column(Float, default=0.8)
    trust_category: Mapped[str] = mapped_column(String(10), default="High")
    violation_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        Index("idx_agent_ns", "namespace"),
        Index("idx_agent_spiffe", "spiffe_id"),
        Index("idx_agent_class", "agent_class"),
    )


class AuditLogEntry(Base):
    """Append-only audit log partitioned by month."""

    __tablename__ = "audit_log"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    tool_name: Mapped[str] = mapped_column(String(255))
    decision: Mapped[str] = mapped_column(String(20))
    agent_id: Mapped[str] = mapped_column(String(512))
    agent_class: Mapped[str] = mapped_column(String(255))
    namespace: Mapped[str] = mapped_column(String(255))
    policy_id: Mapped[str] = mapped_column(String(255), default="")
    rule_id: Mapped[str] = mapped_column(String(255), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    session_id: Mapped[str] = mapped_column(String(255), default="")
    trust_score: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True, default=_utcnow)
    payload: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    __table_args__ = (
        Index("idx_audit_ts", "timestamp_utc"),
        Index("idx_audit_ns_agent", "namespace", "agent_id"),
        Index("idx_audit_decision", "decision"),
        {"postgresql_partition_by": "RANGE (timestamp_utc)"},
    )


class User(Base):
    """API user for role-based access."""

    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AssetGraph(Base):
    """Asset inventory graph snapshot."""

    __tablename__ = "asset_graph"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    node_count: Mapped[int] = mapped_column(Integer)
    edge_count: Mapped[int] = mapped_column(Integer)
    graph_json: Mapped[dict[str, object]] = mapped_column(JSONB)
    hot_spots: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True)


class AttackPath(Base):
    """Computed attack path from asset graph."""

    __tablename__ = "attack_paths"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    graph_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("asset_graph.id"))
    source_node: Mapped[str] = mapped_column(String(512))
    target_node: Mapped[str] = mapped_column(String(512))
    path_json: Mapped[dict[str, object]] = mapped_column(JSONB)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
