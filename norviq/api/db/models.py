# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""PostgreSQL persistence models for Norviq API."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
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
    # HA last-applied convergence: DB-authoritative "last genuinely (re)applied" stamp, written by
    # PolicyLoader.create()/apply_to_target() using DB-side NOW() so every replica reads the same value
    # (see norviq/engine/policy_loader.py). Nullable — a row may exist without ever having been applied
    # (should not happen in practice since create() always stamps it, but kept nullable for pre-migration rows).
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    # Rollback fidelity: persist the priority + enforcement_mode AT this version, so a rollback AFTER a
    # restart restores the exact posture.
    priority: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    enforcement_mode: Mapped[str] = mapped_column(String(20), default="block", server_default="block")
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
    # SECURITY (fail-open fix): the admin FREEZE kill-switch + tighten-only trust CAP were Redis-only, so a
    # Redis flush/restart silently LIFTED them (a frozen/compromised agent un-froze). Persist them durably
    # here; they are warm-seeded back into Redis at startup so cache loss never re-permits a killed agent.
    frozen: Mapped[bool] = mapped_column(default=False)
    trust_cap: Mapped[float | None] = mapped_column(Float, nullable=True)
    __table_args__ = (
        Index("idx_agent_ns", "namespace"),
        Index("idx_agent_spiffe", "spiffe_id"),
        Index("idx_agent_class", "agent_class"),
    )


class FleetBundleState(Base):
    """Spoke-side record of the last fleet policy bundle applied. Drives replay/rollback
    defense: the spoke rejects any bundle whose version <= last_applied_version. One row per cluster id."""

    __tablename__ = "fleet_bundle_state"
    cluster_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_applied_version: Mapped[int] = mapped_column(Integer, default=0)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_bundle_sha256: Mapped[str] = mapped_column(String(64), default="")
    # JSON list of "namespace:agent_class" keys applied from the last bundle, so the next pull can
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
    """Persisted per-namespace runtime preferences — overrides for the config defaults shown in
    the Settings page. One row per namespace; null columns fall back to the effective config value."""

    __tablename__ = "namespace_settings"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    enforcement_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    trust_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    # DEPRECATED/vestigial: this never reaches the engine (not in _ENGINE_POSTURE_FIELDS), so a per-ns
    # value here is inert. It has no Settings knob or API surface; the column is retained (nullable,
    # unwritten) only to avoid a migration on existing rows. Do not resurrect without wiring it into
    # the posture mirror + evaluator and proving the effect.
    violation_penalty: Mapped[float | None] = mapped_column(Float, nullable=True)
    rate_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Org sector hint (advisory) — drives sector-pack suggestions in the console.
    sector: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Apply governance — "enforce" (default) or "dry_run_only" (high-assurance: the API rejects policy applies
    # for this namespace; dry-run + drafts still allowed). null falls back to "enforce".
    apply_mode: Mapped[str | None] = mapped_column(String(20), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class NamespacePack(Base):
    """A sector starter pack enabled for a namespace. The combined rego of a namespace's enabled
    packs is materialized as its (namespace, '__pack__') policy; this table is the source of truth for
    which packs are on. Default-OFF — no rows unless an admin enables a pack."""

    __tablename__ = "namespace_packs"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    pack_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled_by: Mapped[str] = mapped_column(String(255), default="")
    enabled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NamespaceBaselineControl(Base):
    """One baseline control's effect in a namespace: off | monitor | deny.

    Only ROWS THAT DIFFER from the shipped default are stored. A namespace with no rows is running
    every control at `monitor` — evaluating everything, dropping nothing — which is what a fresh
    install should be, and it means enrolling a namespace costs no writes at all.

    Sparse storage also keeps the default LIVE rather than frozen at install time: if a later release
    ships a new control, existing namespaces pick it up at its default instead of silently running
    without it because their stored map predates it. Materialized into the namespace's
    (namespace, '__baseline__') policy by norviq/api/baseline.py, exactly as packs are.
    """

    __tablename__ = "namespace_baseline_controls"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    effect: Mapped[str] = mapped_column(String(16), default="monitor")
    preset: Mapped[str] = mapped_column(String(32), default="strict")
    set_by: Mapped[str] = mapped_column(String(255), default="")
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ApiKey(Base):
    """Issued API key. Only the salted hash is stored — the secret is shown once at creation.
    Carries a role + namespace so a presented key authenticates as a scoped principal."""

    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    prefix: Mapped[str] = mapped_column(String(20))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    namespace: Mapped[str] = mapped_column(String(255), default="default")
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    # Identity binding (see auth.scoped_identity). Empty = unbound (the pre-existing behavior). When set,
    # /evaluate pins the key to exactly this agent_class / spiffe_id, so a workload key cannot be
    # evaluated as a different (looser) class or shed its agent_frozen: kill-switch by asserting another
    # spiffe_id. Issue workload keys WITH these set; leave them empty only for operator/CI keys.
    agent_class: Mapped[str] = mapped_column(String(255), default="")
    spiffe_id: Mapped[str] = mapped_column(String(512), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(default=False)
    # RETENTION: NULL = never expires. New keys default to now + api_key_default_ttl_days unless the
    # creator overrides (0 = never). The auth resolver rejects an expired key exactly like a revoked one.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    # Decision source (sidecar / sidecar-http / sdk / redteam / ...) for audit attribution + UI filter.
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
    # Force a password change on first login. The seeded admin starts True; /auth/change-password
    # clears it. Drives the forced change-password screen + the "default password in use" banner.
    must_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
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


class IntentDraft(Base):
    """A DRY-RUN positive-security intent draft (feat/intent-allowlist).

    Security-critical (auditor): this is a DEDICATED table the evaluator never reads — ``_collect_candidates``
    only queries ``policies``. A draft is deliberately NOT written to ``policies`` (that table is lazy-loaded and
    WOULD enforce). Drafts live here until an operator explicitly reviews + applies the rego via the gated
    Policies flow. ``priority`` mirrors the comprehensive baseline priority for the namespace so, when applied,
    ``_resolve_precedence``'s most-restrictive tie-break keeps the baseline block winning (tighten-only)."""

    __tablename__ = "intent_drafts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # the draft_id
    namespace: Mapped[str] = mapped_column(String(255))
    # For a compliance-remediation draft, ``agent_class`` is the PERSISTENCE target — the
    # per-class overlay key ``"<real_class>__remediation__"`` the draft is applied to (never the base
    # ``<real_class>`` key; that would let "Review & Apply" destroy the class's existing comprehensive policy —
    # the data-loss bug this guard prevents). For every other draft kind (Attack-Graph intent, capability-defend),
    # ``agent_class`` is still the real class directly.
    agent_class: Mapped[str] = mapped_column(String(255))
    # The REAL agent class a compliance-remediation draft affects, for UI display/traceability — distinct
    # from ``agent_class`` above once that becomes the compound overlay key. NULL for non-remediation drafts
    # (Attack-Graph/capability), where ``agent_class`` already IS the real class.
    affected_class: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rego_source: Mapped[str] = mapped_column(Text)
    allow_tools: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    toggles: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=1)
    covered_count: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int] = mapped_column(Integer, default=0)
    would_block: Mapped[int] = mapped_column(Integer, default=0)
    would_allow: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Provenance for a compliance-generated draft — which framework + control it remediates (NULL for
    # Attack-Graph intent drafts, which have no originating control). Makes the draft traceable in Policy Catalog.
    source_framework: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_control_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Retention: drafts auto-expire (14d real / 24h test). GC deletes ONLY expired NON-enforcing drafts —
    # never a policy/version (drafts live in this dedicated table the evaluator never reads). NULL = never expires.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    __table_args__ = (Index("idx_intent_draft_ns", "namespace"),)


class ToolVerbOverride(Base):
    """A PROMOTED verb for a tool the static classifier can't identify by name.

    The tool-classification lifecycle: an unclassified tool stays in the OBSERVATION phase (its calls are
    logged; when the params reveal the operation, that verb lands as evidence on the audit row). Once the
    evidence is conclusive an admin PROMOTES the tool to a defined verb here — from then on the tool is
    classified everywhere (allowlist chips, kill-chain hops) ahead of the name-based registry. Deleting the
    row demotes the tool back to observation. Never consulted by the evaluator — classification only."""

    __tablename__ = "tool_verb_overrides"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    verb: Mapped[str] = mapped_column(String(16))  # read | write | delete | send
    risk: Mapped[str] = mapped_column(String(16))  # low | medium | high | critical
    promoted_by: Mapped[str] = mapped_column(String(255), default="")
    # The observed-call evidence at promotion time ({"calls": N, "verbs": {"read": 12, ...}}) — audit trail
    # for WHY this verb was chosen.
    evidence: Mapped[dict[str, object] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


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


class MitreCoverageSnapshot(Base):
    """A periodic snapshot of Compliance (MITRE ATLAS) coverage, so the coverage-trend line renders from a
    REAL persisted series (never fabricated). One row per (namespace, framework, hour); the coverage endpoint
    upserts the current-hour row on read (throttled), so the series accumulates over time with no scheduler.

    ``kind`` distinguishes a coverage snapshot from an evidence-pack export event (the latest ``kind='export'``
    row backs the "last exported" indicator) — one table, two honest uses, no mock data."""

    __tablename__ = "mitre_coverage_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    namespace: Mapped[str] = mapped_column(String(255), default="__all__")
    framework: Mapped[str] = mapped_column(String(64), default="atlas")
    kind: Mapped[str] = mapped_column(String(16), default="snapshot")  # "snapshot" | "export"
    enforced: Mapped[int] = mapped_column(Integer, default=0)
    enforceable_total: Mapped[int] = mapped_column(Integer, default=0)
    coverage_pct: Mapped[int] = mapped_column(Integer, default=0)
    blocked: Mapped[int] = mapped_column(Integer, default=0)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        Index("idx_mitre_snap_ns_fw_kind", "namespace", "framework", "kind"),
        Index("idx_mitre_snap_ts", "timestamp_utc"),
        # Single-writer-per-hour for SNAPSHOTS — the structural backstop that makes the router's
        # read-then-insert throttle safe under concurrent GETs (the router also takes a transaction-scoped
        # advisory lock keyed on the same tuple). It is a FUNCTIONAL partial-unique index on the UTC-hour of
        # timestamp_utc over the EXISTING columns (deliberately no new column: an added column would need an
        # ALTER backfill in session.py to avoid breaking INSERTs on a DB provisioned before it, whereas a
        # functional index over existing columns never touches the INSERT statement and so cannot regress a
        # legacy table). `AT TIME ZONE 'UTC'` reduces timestamptz→timestamp so date_trunc is IMMUTABLE
        # (Postgres rejects a STABLE, tz-dependent expression in an index). Scoped to kind='snapshot' so
        # evidence-pack exports — several per hour are legitimate and must each refresh "last exported" — stay
        # unconstrained.
        Index("uq_mitre_snap_hourly", "namespace", "framework",
              text("date_trunc('hour', timestamp_utc AT TIME ZONE 'UTC')"), unique=True,
              postgresql_where=text("kind = 'snapshot'")),
    )


class RedTeamRun(Base):
    """A DURABLE record of one red-team suite run.

    This persists each run — the full result rows plus the computed efficacy roll-up — so the Red Team
    view has real history that survives an API restart and Compliance/Overview can read the
    "proven-blocking" evidence from the LAST run. Retention prunes to the most recent
    ``REDTEAM_RUN_RETENTION`` runs; nothing here ever influences enforcement (read-only evidence table)."""

    __tablename__ = "redteam_runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # the run_id (uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    namespace: Mapped[str] = mapped_column(String(255))
    targets: Mapped[list] = mapped_column(JSONB)  # agent classes evaluated
    total: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    pass_rate: Mapped[float] = mapped_column(Float, default=0.0)
    # Per-attack detail is DETAIL-PRUNED to NULL once a run ages out of the detail window (summary kept). The
    # newest run per namespace is never pruned, so results/latest always returns full detail.
    results: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # per-attack×class rows; NULL once pruned
    efficacy: Mapped[dict[str, object]] = mapped_column(JSONB)  # roll-up (overall + per-technique/owasp) — SUMMARY
    created_by: Mapped[str] = mapped_column(String(255), default="")
    __table_args__ = (Index("idx_redteam_run_created", "created_at"),)


class McpToolPin(Base):
    """A pinned MCP tool DEFINITION — the control-plane record of what was approved.

    WHY THIS IS A CONTROL-PLANE TABLE AND NOT PROXY-LOCAL STATE. A pin is an APPROVAL, and approvals
    are policy: they are the operator's statement that this exact tool definition, from this exact
    server, is the one the model may be shown. Keeping them in each proxy's memory (or a file on an
    emptyDir) makes them per-pod, invisible to the console, unauditable, and — worst — resettable by
    anything that restarts the pod, which is precisely the moment an attacker would choose. Putting
    them here gets tenant scoping, RBAC, the audit trail and console visibility for free, because
    every one of those already exists for the policy tables next to it.

    The digest covers only the SECURITY-RELEVANT fields of a definition (name/title/description/
    inputSchema/outputSchema/annotations — see norviq/mcp/pins.canonical_definition), so a server
    re-serialising its catalog or bumping unrelated metadata does not register as a change. A drift
    detector that cries wolf gets switched off, which is worse than not having one.

    ``approved_digest`` is deliberately NOT updated when drift is observed. Silently adopting the new
    definition would mean an attacker need only absorb a single blocked call before their rug pull
    takes effect; adopting it is an explicit operator action (POST /mcp/pins/approve, which names the
    digest so an approval cannot race a second change). ``last_digest`` records what the server is
    currently serving so the console can diff approved-vs-served.

    Never consulted by the evaluator. This is Gate A state; enforcement of a tool CALL is Gate B.
    """

    __tablename__ = "mcp_tool_pins"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    tool_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    approved_digest: Mapped[str] = mapped_column(String(64))
    # What the server is serving right now. Equal to approved_digest in the steady state; different
    # means drift, and the pair is what the console diffs.
    last_digest: Mapped[str] = mapped_column(String(64), default="")
    # The canonical JSON of the APPROVED definition. Kept because "what did it used to say?" is the
    # first question asked when a rug pull fires, and the old definition cannot be re-fetched after
    # the server has already changed it.
    approved_canonical: Mapped[str] = mapped_column(Text, default="")
    last_canonical: Mapped[str] = mapped_column(Text, default="")
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_by: Mapped[str] = mapped_column(String(255), default="")
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_severity: Mapped[str] = mapped_column(String(16), default="none")
    findings: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    drift_count: Mapped[int] = mapped_column(Integer, default=0)
    transport: Mapped[str] = mapped_column(String(16), default="stdio")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (
        Index("idx_mcp_pin_ns_server", "namespace", "server_id"),
        Index("idx_mcp_pin_last_seen", "last_seen_at"),
    )


class McpServer(Base):
    """An MCP server as the OPERATOR has decided about it — not as it was observed.

    `mcp_tool_pins` records what a server SERVED; this records what an operator SAID about it. They are
    deliberately separate rows: `GET /mcp/servers` used to derive the server list by grouping pins in
    memory, so a server existed only as a side effect of having observed a tool from it — there was
    nowhere to put a decision, no way to name a server before it was seen, and `forget` (which deletes
    pins) would have taken the decision with it.

    `discovered` on first sight, NEVER `registered`. Observed and approved must be different states, for
    the same reason Gate A reports `scan_severity: "unknown"` rather than `"none"` for a definition it
    never scanned: "I have not looked at this" must not read like "I looked and it was fine".
    Registration is always a human act.

    Keyed `(namespace, server_id)` to match McpToolPin, so a server reachable from two namespaces is
    registered twice. That is the tenant-safe reading: one namespace approving a server must not
    silently authorise every other one.
    """

    __tablename__ = "mcp_servers"
    namespace: Mapped[str] = mapped_column(String(255), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    # discovered | registered | blocked
    status: Mapped[str] = mapped_column(String(16), default="discovered")
    # Whether WRITE-verb tools on this server may be called. Separate from `status` because "may I
    # reach it at all" and "may I write through it" are different questions — collapsing them is what
    # left reads from an unregistered server ungoverned.
    writable: Mapped[bool] = mapped_column(Boolean, default=False)
    decided_by: Mapped[str] = mapped_column(String(255), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    # THE SERVER'S IDENTITY SURFACE, hashed the way a tool definition is. `server_id` is only the
    # `--server-id` the proxy was started with — operator-chosen, PEP-reported, not cryptographic — so
    # without this "registered" means no more than "something claimed this name". The digest covers the
    # initialize/discover response (serverInfo name+version, instructions banner) and the tool-name set,
    # so a wholesale toolset swap under a stable name is visible as identity drift, which is a stronger
    # signal than any single tool drifting.
    identity_digest: Mapped[str] = mapped_column(String(64), default="")
    last_identity_digest: Mapped[str] = mapped_column(String(64), default="")
    identity_canonical: Mapped[str] = mapped_column(Text, default="")
    identity_drift_count: Mapped[int] = mapped_column(Integer, default=0)
    transport: Mapped[str] = mapped_column(String(16), default="stdio")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    __table_args__ = (Index("idx_mcp_server_ns_status", "namespace", "status"),)


class SiemForwardCursor(Base):
    """Where the SIEM forwarder got to, durably.

    The cursor lived only in `AuditForwarder._cursor_ts`, initialized to None. So every API restart
    re-forwarded the audit log from row ONE: the whole history duplicated into the collector on each
    restart, inflating alert counts, block-rate dashboards and any retention-based compliance report
    built on that stream — while `nrvq.siem.forwarded count=N` logged success throughout.

    Skipping instead of duplicating would be no better on an audit-evidence path (silently dropped
    evidence), so the cursor is persisted rather than defaulted either way. One row per forwarder
    identity; `id` is a fixed key because there is exactly one forwarder per deployment today, and a
    named key leaves room for more without a migration.
    """

    __tablename__ = "siem_forward_cursor"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default="default")
    cursor_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
