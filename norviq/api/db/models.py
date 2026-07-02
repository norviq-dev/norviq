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
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    enforcement_mode: Mapped[str] = mapped_column(String(20), default="block", server_default="block")
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


class FleetBundleState(Base):
    """Spoke-side record of the last fleet policy bundle applied (F045 P2). Drives replay/rollback
    defense: the spoke rejects any bundle whose version <= last_applied_version. One row per cluster id."""

    __tablename__ = "fleet_bundle_state"
    cluster_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_applied_version: Mapped[int] = mapped_column(Integer, default=0)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_bundle_sha256: Mapped[str] = mapped_column(String(64), default="")
    # F-52: JSON list of "namespace:agent_class" keys applied from the last bundle, so the next pull can
    # RECONCILE — delete spoke policies that have been retracted (dropped from the bundle). null = none yet.
    last_manifest: Mapped[str | None] = mapped_column(Text, nullable=True)


class FleetJoinState(Base):
    """Single-cluster-first: the spoke's fleet enrollment, set by `norviq fleet join <token>` and read at startup so
    the relay/puller are (re)configured WITHOUT per-spoke Helm wiring. One row (id=1). `enabled=False` after a
    `leave` keeps the spoke single-cluster even if env still has fleet config."""

    __tablename__ = "fleet_join_state"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(default=False)
    cluster_id: Mapped[str] = mapped_column(String(255), default="")
    hub_url: Mapped[str] = mapped_column(Text, default="")
    bundle_pubkey: Mapped[str] = mapped_column(Text, default="")
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class NamespaceSettings(Base):
    """Persisted per-namespace runtime preferences (F046) — overrides for the config defaults shown in
    the Settings page. One row per namespace; null columns fall back to the effective config value."""

    __tablename__ = "namespace_settings"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    enforcement_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    trust_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    violation_penalty: Mapped[float | None] = mapped_column(Float, nullable=True)
    rate_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # F047: org sector hint (advisory) — drives sector-pack suggestions in the console.
    sector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # F-51: apply governance — "enforce" (default) or "dry_run_only" (high-assurance: the API rejects policy applies
    # for this namespace; dry-run + drafts still allowed). null falls back to "enforce".
    apply_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class NamespacePack(Base):
    """F047: a sector starter pack enabled for a namespace. The combined rego of a namespace's enabled
    packs is materialized as its (namespace, '__pack__') policy; this table is the source of truth for
    which packs are on. Default-OFF — no rows unless an admin enables a pack."""

    __tablename__ = "namespace_packs"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    pack_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled_by: Mapped[str] = mapped_column(String(255), default="")
    enabled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ApiKey(Base):
    """Issued API key (F046). Only the salted hash is stored — the secret is shown once at creation.
    Carries a role + namespace so a presented key authenticates as a scoped principal."""

    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    namespace: Mapped[str] = mapped_column(String(255), default="default")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(default=False)


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
    # OBS-2: decision source (sidecar / sidecar-http / sdk / redteam / ...) for audit attribution + UI filter.
    framework: Mapped[str] = mapped_column(String(32), default="", server_default="")
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
    namespace: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_node: Mapped[str] = mapped_column(String(512))
    target_node: Mapped[str] = mapped_column(String(512))
    path_json: Mapped[dict[str, object]] = mapped_column(JSONB)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
