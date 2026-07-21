# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Runtime configuration for Norviq."""

import os
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _preload_env_files() -> None:
    """Load .env files without requiring python-dotenv."""
    repo_root = Path(__file__).resolve().parents[1]
    preexisting = set(os.environ.keys())
    for filename in (".env", ".env.local"):
        path = repo_root / filename
        if not path.exists():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if not key:
                continue
            # Keep externally provided environment values authoritative.
            if key in preexisting:
                continue
            # Let .env.local override .env.
            if filename == ".env.local" or key not in os.environ:
                os.environ[key] = value
    # Backward-compatible aliases for local config.
    if "NRVQ_PG_URL" not in os.environ and "NRVQ_DB_URL" in os.environ:
        os.environ["NRVQ_PG_URL"] = os.environ["NRVQ_DB_URL"]


_preload_env_files()


class NorviqSettings(BaseSettings):
    """Norviq configuration from NRVQ_ environment variables."""

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),
        env_prefix="NRVQ_",
        extra="ignore",
    )

    # Base URL the SDK's PolicyEngineClient posts /api/v1/evaluate to (NRVQ_POLICY_ENGINE_URL).
    # Default matches the in-cluster central API service (same target as api_url).
    policy_engine_url: str = "http://norviq-api:8080"
    enforcement_mode: str = "block"
    # Decision when an enforcing namespace has NO policy loaded (deny-by-default for a PEP).
    # "deny" (default) blocks unconfigured namespaces in block mode; "allow" restores fail-open behavior.
    # Only applies in enforcement_mode="block"; audit/monitor mode always allows (visibility only).
    no_policy_decision: str = "deny"
    sdk_timeout_ms: int = 5000
    sdk_fallback_mode: str = "block"
    sdk_retry_max_attempts: int = 2
    sdk_retry_backoff_base_ms: int = 100
    sdk_circuit_fail_threshold: int = 3
    sdk_circuit_reset_after_ms: int = 2000
    sdk_http_max_connections: int = 20
    sdk_http_max_keepalive_connections: int = 10
    spiffe_socket: str = "/tmp/spiffe-mock.sock"  # nosec B108 - Settings default (dev/test mock path), overridden by NRVQ_SPIFFE_SOCKET in prod
    spiffe_cache_ttl_s: int = 300
    # Workload-identity resolution mode. "mock" = env-var identity (default;
    # local/tests/attack-suite). "workload-api" = real SPIFFE Workload API SVID, FAIL-CLOSED on
    # socket/SVID error (no env-var fallback). NRVQ_SPIFFE_MODE; revert to mock with no redeploy.
    spiffe_mode: str = "mock"
    redis_url: str = "redis://localhost:6379"
    redis_max_connections: int = 20
    # Proactively re-validate idle Redis connections (resilience after a Redis restart).
    redis_health_check_interval_s: int = 15
    redis_ttl_policy_s: int = 60
    redis_ttl_eval_s: int = 5
    redis_ttl_trust_s: int = 30
    trust_threshold: float = 0.7
    trust_violation_penalty: float = 0.05
    evaluator_max_concurrency: int = 10
    # OPA evaluation runtime. "server" = long-lived OPA queried over HTTP (default, low latency + HA);
    # "subprocess" = legacy per-call `opa eval` fork (rollback gate, no redeploy needed to revert).
    opa_mode: str = "server"
    # Base URL of the OPA server (the in-pod sidecar). Empty -> spawn a managed `opa run --server`
    # on startup (local/dev/tests). NRVQ_OPA_URL.
    opa_url: str = ""
    # Bind address for the managed OPA server when opa_url is unset.
    opa_addr: str = "127.0.0.1:8181"
    # Tight per-query HTTP timeout; on timeout/error the evaluator fails CLOSED (block).
    opa_timeout_ms: int = 250
    # Separate, larger timeout for the module PUSH (Policy API PUT). A push is NOT the hot path — it
    # happens once per (key, digest) per pod — but OPA recompiles its whole module store on every PUT,
    # which at a realistic store size exceeds the tight query timeout. Sharing opa_timeout_ms made the
    # FIRST eval of any freshly-applied/enabled policy fail closed (evaluator_error) or produce an empty
    # override-validation error. Keep the query timeout tight; give push real headroom.
    opa_push_timeout_ms: int = 5000
    debug_opa_logging: bool = Field(default=False, validation_alias=AliasChoices("DEBUG_OPA_LOGGING", "DEBUG_OPA"))
    evaluator_rate_limit_per_window: int = 60
    evaluator_rate_limit_window_s: int = 60
    # Exempt read-like tools from the per-identity rate limiter so a benign read spike isn't denied
    # (a legitimate availability hit under load). Write/destructive tools are still rate-limited (fail-safe).
    evaluator_rate_limit_read_exempt: bool = True
    evaluator_rate_limit_read_prefixes: tuple[str, ...] = (
        "get_", "read_", "list_", "query_", "fetch_", "describe_", "view_", "monitor_", "poll_", "report_", "search_",
    )
    evaluator_delete_prefix: str = "delete"
    evaluator_wildcard_value: str = "*"
    evaluator_sql_deny_keywords: tuple[str, ...] = (
        "drop table",
        "delete from",
        "truncate",
        "alter table",
        "; --",
    )
    evaluator_non_cacheable_rules: tuple[str, ...] = ("rate_limit_exceeded", "escalate_low_trust")
    # --- HTTP-level rate limiting. evaluator_rate_limit_* above is an OPA POLICY decision on the
    # evaluated tool call; this is a separate HTTP-layer throttle in front of the whole API (DoS defense),
    # Redis-backed (INCR+EXPIRE fixed window) so it is shared correctly across HA replicas. Keyed per-identity
    # (unverified JWT `sub` — cheap, no signature check on the hot path; downstream auth still fully verifies
    # the token before anything happens) with a per-client-IP fallback for unauthenticated requests.
    http_rate_limit_enabled: bool = True
    http_rate_limit_window_s: int = 60
    # Paths never throttled — k8s liveness/readiness probes and the Prometheus scrape must never 429.
    http_rate_limit_exclude_paths: tuple[str, ...] = ("/healthz", "/readyz", "/metrics")
    # /evaluate is the hot enforcement path (every gated tool call) — give it a HIGH ceiling so it is never
    # the bottleneck; expensive/auth-adjacent routes get much stricter ceilings.
    http_rate_limit_evaluate_per_window: int = 3000
    http_rate_limit_auth_login_per_window: int = 20   # per-IP (pre-auth route)
    http_rate_limit_dry_run_per_window: int = 20
    http_rate_limit_redteam_per_window: int = 15
    http_rate_limit_default_per_window: int = 300     # everything else
    # OPT-IN, default-OFF output-DLP. Norviq's PEP is INPUT-only; when enabled the SDK adapter scans an
    # allowed tool's RETURN value and redacts PAN/SSN before it propagates (minimal; full output-DLP is roadmap).
    sdk_output_dlp_enabled: bool = False
    pg_url: str = "postgresql://norviq:norviq_dev@localhost:5432/norviq"
    db_ssl_mode: str = Field(
        default="prefer",
        validation_alias=AliasChoices("DB_SSL_MODE", "PG_SSL_MODE", "PG_SSLMODE", "NRVQ_DB_SSL_MODE"),
    )
    pg_pool_size: int = Field(default=10, validation_alias=AliasChoices("PG_POOL_SIZE", "DB_POOL_SIZE"))
    db_pool_max_overflow: int = 5
    db_pool_timeout: int = 5
    db_command_timeout: int = 5
    # Recycle pooled DB connections older than this (bounds staleness; pairs with pool_pre_ping).
    db_pool_recycle_s: int = 300
    # RETENTION: 30-day default — the console never displays a window longer than 30d (time ranges cap
    # at 30d), so anything older serves only external compliance horizons. Compliance/SOC2/ISO users
    # raise this to 90-365 via Helm (auditRetentionDays); the audit-evidence export packs are the
    # supported path for durable long-term evidence. <=0 disables pruning (keep forever).
    audit_retention_days: int = 30
    # How often the background retention pruner sweeps ALL retention-managed tables
    # (audit_log, coverage snapshots, expired drafts, agent registry, asset-graph snapshots) — started/
    # cancelled from the API lifespan. Each table has its own <=0 disable switch; the interval itself
    # has no disable — a sweep just finds nothing to delete once a table is within its window.
    audit_retention_prune_interval_s: int = 3600
    # Compliance coverage trend snapshots + evidence-export events: 30d exactly covers the UI's 30d
    # trend view; raise alongside audit_retention_days for longer compliance horizons. <=0 keeps forever.
    coverage_snapshot_retention_days: int = 30
    # Asset-graph snapshots: one full-graph row is persisted per evaluated tool call, but every reader
    # only uses the NEWEST row per namespace — keep a small history for restore/debugging and prune the
    # rest (rows referenced by attack_paths are always kept: FK has no cascade). <=0 keeps forever.
    graph_snapshot_keep_per_namespace: int = 10
    # Agent registry hygiene: identities unseen for this many days are removed (decommissioned agents
    # otherwise accumulate forever and surface as phantom "awaiting" nodes). <=0 keeps forever.
    agent_registry_retention_days: int = 90
    # New API keys default to this expiry (per-key override at creation; 0 at creation = never).
    # Pre-existing keys (no expires_at) never expire — unchanged behavior. <=0 here = new keys
    # default to never-expiring.
    api_key_default_ttl_days: int = 90
    # Bounded concurrency for audit_emitter's fire-and-forget DB writes, so a flood of tool
    # calls can't fan out enough concurrent audit INSERTs to exhaust the DB pool (pg_pool_size +
    # db_pool_max_overflow) and starve every other endpoint. Sized comfortably under the pool ceiling.
    audit_emit_max_concurrency: int = 8
    # Policy-Catalog draft + version retention (keeps the store + UI bounded; all Helm/env-configurable). NONE of
    # these ever touch an enforcing policy or the current-enforcing version — retention is decoupled from enforcement.
    draft_ttl_days: int = 14              # real intent drafts auto-expire after this many days
    draft_ttl_test_hours: int = 24        # test/e2e (synthetic-class) drafts expire fast
    draft_cap_per_namespace: int = 50     # hard ceiling of real drafts per namespace (evict oldest beyond it)
    policy_scope_cap_per_namespace: int = 200  # hard ceiling of distinct (ns,class) policy scopes per namespace
    drafts_page_size: int = 15            # bounded drafts endpoint page size (top-N newest + total count)
    policy_version_keep_count: int = 20   # keep at least the last N versions per policy
    policy_version_keep_days: int = 90    # ...and any version saved within this window; prune older EXCEPT current
    # Red-team run retention (read-only EVIDENCE table — never touches enforcement). Two tiers keep the DB +
    # history view bounded: FULL per-attack detail is kept only for the newest few runs (or a short TTL); older
    # runs keep just their SUMMARY (efficacy %, counts, per-technique roll-up, targets, timestamp). SAFETY: the
    # latest run per namespace is ALWAYS protected — its detail + summary are never pruned.
    redteam_detail_keep_runs: int = 1     # keep full per-attack detail for the newest N runs / namespace (last-run-only default)
    redteam_detail_keep_days: int = 7     # ...and any run within this window; older runs are detail-pruned (summary kept)
    redteam_summary_keep_runs: int = 20   # keep summaries (no detail) for the newest N runs / namespace
    redteam_summary_keep_days: int = 30   # ...and any run within this window; older runs are deleted entirely
    redteam_history_page_size: int = 20   # bounded /redteam/results history page size (summaries only)
    # The per-namespace in-flight guard (_INFLIGHT_SUITES) only stops a double-submit for the
    # SAME namespace — an admin (or a compromised admin token) can still fan out concurrent suites across
    # many namespaces, each = len(targets) x len(ATTACKS) evaluate calls + a DB persist. This caps how
    # many suite runs (across ALL namespaces) may execute at once, process-wide.
    redteam_suite_global_concurrency: int = 3
    # Opt-in, default OFF: capture MASKED tool_params on the audit record (PAN->****1111,
    # SSN->***-**-6789, secrets->****) for event reconstruction (PCI 10.3) without storing raw PII/PAN.
    audit_capture_masked_params: bool = False
    # Opt-in: HMAC-SHA256 key for the tamper-evident /audit/export?signed=true manifest. Empty =
    # the signed export still hash-chains (integrity) but the manifest signature is null (no shared-key auth).
    audit_export_signing_key: str = ""
    otel_endpoint: str = "http://localhost:4317"
    otel_enabled: bool = True
    otel_disabled: bool = False
    prometheus_port: int = 9090
    log_level: str = "INFO"
    log_format: str = "json"
    socket_path: str = "/tmp/norviq-proxy.sock"  # nosec B108 - Settings default; the sidecar's socket lives on a pod-private emptyDir, path overridable via NRVQ_SOCKET_PATH
    http_fallback_port: int = 8282
    api_port: int = 8080
    # Reject over-large request bodies (defense against the base64 fan-out DoS amplifier and
    # generic memory abuse). 256 KiB is far above any legitimate tool-call payload. NRVQ_MAX_REQUEST_BODY_BYTES.
    max_request_body_bytes: int = 262144
    # Injected-sidecar evaluation mode. "proxy" (default) = the sidecar POSTs each tool call to
    # the central norviq-api /api/v1/evaluate with a namespace-scoped service JWT (DB/OPA stay central,
    # nothing per-pod). "embedded" = the sidecar runs its own RedisCache+OPA+PolicyLoader (air-gapped/edge;
    # needs NRVQ_REDIS_URL/NRVQ_PG_URL/NRVQ_OPA_* wired in). NRVQ_SIDECAR_MODE.
    sidecar_mode: str = "proxy"
    # Central API base URL the thin-proxy sidecar calls (NRVQ_API_URL). Same value the webhook injects.
    api_url: str = "http://norviq-api:8080"
    # Bearer token the thin-proxy sidecar presents to /evaluate (role=service, namespace-scoped). The
    # webhook mints + injects this per workload; empty in embedded mode. NRVQ_API_TOKEN.
    api_token: str = ""
    # --- auto-mTLS (internal control-plane TLS). OFF by default -> plaintext http, EXACTLY as today
    # (byte-identical behavior keeps the whole suite + k8s probes green). When true AND api_url is https,
    # the sidecar builds a mutual-TLS ssl.SSLContext: trusts the internal CA (internal_api_ca_pem) and
    # presents the injected client cert/key (internal_client_cert_pem/internal_client_key_pem). The webhook
    # injector mints the per-namespace client cert and injects all four as env (NRVQ_INTERNAL_TLS +
    # NRVQ_API_CA_PEM/NRVQ_CLIENT_CERT_PEM/NRVQ_CLIENT_KEY_PEM); the bearer token is kept (defense in depth).
    internal_tls: bool = False
    # Already-decoded PEM strings (NOT file paths) injected by the webhook from the internal CA secrets.
    internal_api_ca_pem: str = Field(default="", validation_alias=AliasChoices("API_CA_PEM", "NRVQ_API_CA_PEM"))
    internal_client_cert_pem: str = Field(
        default="", validation_alias=AliasChoices("CLIENT_CERT_PEM", "NRVQ_CLIENT_CERT_PEM")
    )
    internal_client_key_pem: str = Field(
        default="", validation_alias=AliasChoices("CLIENT_KEY_PEM", "NRVQ_CLIENT_KEY_PEM")
    )
    api_secret_key: str = Field(
        default="change-me-in-production",  # Replace in non-dev deployments.
        # NRVQ_API_SECRET_KEY is what the Helm chart sets — include it so the key is rotatable.
        validation_alias=AliasChoices("API_SECRET_KEY", "JWT_SECRET", "NRVQ_API_SECRET_KEY"),
    )
    # When true, the API refuses to start on a weak/default/short JWT secret or the default
    # admin password (fail-closed — see the boot check in api/main.py). Defaults True: a forgeable
    # default secret is a fleet-wide trust-root compromise, so "secure by default" wins over
    # dev-convenience. Local dev / tests / the attack suite set NRVQ_REQUIRE_STRONG_SECRET=false (or
    # export a real NRVQ_API_SECRET_KEY, which is the better fix and satisfies this unchanged).
    require_strong_secret: bool = True
    # --- Local username/password login. The PRIMARY no-IdP path (replaces the CLI/paste-token
    # quick-start as the default). The CLI/token mint (token_mint) stays for automation; OIDC SSO stays
    # for enterprise. Credentials live in norviq-secrets; the seed admin is hashed at boot (bcrypt).
    auth_login_enabled: bool = True
    auth_admin_username: str = Field(
        default="admin", validation_alias=AliasChoices("AUTH_ADMIN_USERNAME", "NRVQ_AUTH_ADMIN_USERNAME")
    )
    # Plaintext default, HASHED at boot (ensure_default_admin); never stored/logged in the clear. Override in
    # norviq-secrets for real installs. With require_strong_secret the API refuses to start while it is still
    # the built-in default (no-default-in-prod).
    auth_admin_password: str = Field(
        default="norviq", validation_alias=AliasChoices("AUTH_ADMIN_PASSWORD", "NRVQ_AUTH_ADMIN_PASSWORD")
    )
    # The built-in default sentinel — drives the forced first-login change + the "default password in use"
    # banner + the prod boot-refusal. Not itself a credential.
    auth_default_admin_password: str = "norviq"
    # Short session-token lifetime for a password login (HS256, signed with api_secret_key).
    auth_session_ttl_s: int = 3600
    # Brute-force defense: after this many failed logins for one username within the window, lock the
    # username out (429 + backoff) until the window expires. Per-username counter in Redis; success resets it.
    auth_login_max_attempts: int = 5
    auth_login_window_s: int = 300
    # Minimum length enforced on a NEW password at change-time (defense-in-depth; not applied to the seed).
    auth_min_password_length: int = 12
    # --- OIDC (SSO). All default-off so legacy HS256 stays the only
    # path until an IdP is wired; flipping oidc_enabled adds RS256/ES256 validation ALONGSIDE HS256.
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_jwks_cache_ttl_s: int = 300
    # Anti-DoS floor: minimum seconds between forced JWKS refetches on an unknown kid.
    oidc_jwks_min_refresh_s: int = 30
    oidc_group_claim: str = "groups"
    # group -> {"role": "...", "namespace": "..."}; parses from a JSON env string. e.g.
    # NRVQ_OIDC_GROUP_MAPPINGS='{"norviq-admins":{"role":"admin"},"team-a":{"role":"viewer","namespace":"team-a"}}'
    oidc_group_mappings: dict[str, dict[str, str]] = {}
    # Keep validating legacy HS256 tokens during migration; flip false at cutover once all
    # clients use OIDC (a short-TTL break-glass service token path is retained).
    legacy_hs256_enabled: bool = True
    webhook_port: int = 8443
    webhook_cert_dir: str = "/etc/norviq/certs"
    sidecar_image: str = "norviq/norviq-engine:engine-latest"
    session_ttl_s: int = 3600
    graph_max_nodes: int = 5000
    # SIEM forwarder (outbound audit push). Off by default; the pull export endpoint is always on.
    siem_enabled: bool = False
    siem_webhook_url: str = ""
    siem_format: str = "ndjson"  # ndjson | syslog
    siem_poll_interval_s: int = 30
    # --- Multi-cluster fleet, read-only. OFF by default -> single-cluster behaves as today.
    # Spoke relay: pushes agent + audit ROLLUPS to the hub fleet-api. Fire-and-forget, never on the
    # enforce hot path (hub down -> local enforcement unaffected; fleet views degrade, never open).
    fleet_enabled: bool = False
    fleet_api_url: str = ""             # hub base URL the relay pushes to
    fleet_cluster_id: str = ""          # this cluster's id in the fleet
    fleet_cluster_name: str = ""
    fleet_cluster_region: str = ""
    fleet_cluster_endpoint: str = ""
    # This cluster's OWN console URL, advertised to the hub on heartbeat so the hub console can deep-link
    # "open <cluster>'s console" for a remote selection. Optional — absent -> the deep-link shows guidance instead.
    fleet_cluster_console_url: str = ""
    fleet_relay_interval_s: int = 60
    fleet_stale_after_s: int = 180      # hub: heartbeat older than this -> cluster status "stale"
    # Relay->hub auth: OIDC client-credentials (preferred); falls back to a self-minted HS256 service
    # token (with the cluster claim) when the token URL is unset and legacy HS256 is enabled.
    fleet_oidc_token_url: str = ""
    fleet_oidc_client_id: str = ""
    fleet_oidc_client_secret: str = ""
    # HUB ONLY: the fleet-api's own dedicated Postgres (separate store from any spoke DB).
    fleet_pg_url: str = "postgresql://norviq:norviq_dev@fleet-postgresql:5432/norviq_fleet"
    # --- Signed policy-push. The signing keypair is a DEDICATED fleet trust root, DISTINCT from
    # api_secret_key (so compromising the token secret can't forge bundles). HUB holds the private key;
    # spokes hold ONLY the public key. A spoke with an empty pubkey FAILS CLOSED (applies no bundle).
    fleet_signing_key: str = ""         # hub: RS256 private key PEM
    fleet_bundle_pubkey: str = ""       # spoke: RS256 public key PEM (the trust root)
    fleet_bundle_ttl_s: int = 900       # hub: signed bundle validity window (expires_at = issued_at + ttl)
    fleet_pull_interval_s: int = 60     # spoke: how often to pull + verify + apply the bundle
    # Residency: this spoke keeps raw audit in-cluster (rollups still leave; drill-down is blocked).
    fleet_residency: bool = False
    # Labels this cluster advertises to the hub for policy target_selector matching (e.g. {"env":"prod"}).
    fleet_cluster_labels: dict[str, str] = {}


settings = NorviqSettings()
if settings.otel_disabled:
    settings.otel_enabled = False
