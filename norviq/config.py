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

    policy_engine_url: str = "http://localhost:8181"
    enforcement_mode: str = "block"
    # F-04: decision when an enforcing namespace has NO policy loaded (deny-by-default for a PEP).
    # "deny" (default) blocks unconfigured namespaces in block mode; "allow" restores the old fail-open.
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
    spiffe_socket: str = "/tmp/spiffe-mock.sock"
    spiffe_cache_ttl_s: int = 300
    # Workload-identity resolution mode (IDENTITY epic B2). "mock" = env-var identity (default;
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
    debug_opa_logging: bool = Field(default=False, validation_alias=AliasChoices("DEBUG_OPA_LOGGING", "DEBUG_OPA"))
    evaluator_rate_limit_per_window: int = 60
    evaluator_rate_limit_window_s: int = 60
    # F-23: exempt read-like tools from the per-identity rate limiter so a benign read spike isn't denied
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
    # F-22: OPT-IN, default-OFF output-DLP. Norviq's PEP is INPUT-only; when enabled the SDK adapter scans an
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
    audit_retention_days: int = 365
    # F-19 (opt-in, default OFF): capture MASKED tool_params on the audit record (PAN->****1111,
    # SSN->***-**-6789, secrets->****) for event reconstruction (PCI 10.3) without storing raw PII/PAN.
    audit_capture_masked_params: bool = False
    # F-19 (opt-in): HMAC-SHA256 key for the tamper-evident /audit/export?signed=true manifest. Empty =
    # the signed export still hash-chains (integrity) but the manifest signature is null (no shared-key auth).
    audit_export_signing_key: str = ""
    otel_endpoint: str = "http://localhost:4317"
    otel_enabled: bool = True
    otel_disabled: bool = False
    prometheus_port: int = 9090
    log_level: str = "INFO"
    log_format: str = "json"
    socket_path: str = "/tmp/norviq-proxy.sock"
    http_fallback_port: int = 8282
    api_port: int = 8080
    # PERF-1: reject over-large request bodies (defense against the base64 fan-out DoS amplifier and
    # generic memory abuse). 256 KiB is far above any legitimate tool-call payload. NRVQ_MAX_REQUEST_BODY_BYTES.
    max_request_body_bytes: int = 262144
    # SIDE-2: injected-sidecar evaluation mode. "proxy" (default) = the sidecar POSTs each tool call to
    # the central norviq-api /api/v1/evaluate with a namespace-scoped service JWT (DB/OPA stay central,
    # nothing per-pod). "embedded" = the sidecar runs its own RedisCache+OPA+PolicyLoader (air-gapped/edge;
    # needs NRVQ_REDIS_URL/NRVQ_PG_URL/NRVQ_OPA_* wired in). NRVQ_SIDECAR_MODE.
    sidecar_mode: str = "proxy"
    # Central API base URL the thin-proxy sidecar calls (NRVQ_API_URL). Same value the webhook injects.
    api_url: str = "http://norviq-api:8080"
    # Bearer token the thin-proxy sidecar presents to /evaluate (role=service, namespace-scoped). The
    # webhook mints + injects this per workload; empty in embedded mode. NRVQ_API_TOKEN.
    api_token: str = ""
    api_secret_key: str = Field(
        default="change-me-in-production",  # Replace in non-dev deployments.
        # NRVQ_API_SECRET_KEY is what the Helm chart sets — include it so the key is rotatable.
        validation_alias=AliasChoices("API_SECRET_KEY", "JWT_SECRET", "NRVQ_API_SECRET_KEY"),
    )
    # When true (set in prod via NRVQ_REQUIRE_STRONG_SECRET), the API refuses to start on the
    # default JWT secret. Defaults False so local dev / tests / the attack suite keep working.
    require_strong_secret: bool = False
    # --- OIDC (SSO) — IDENTITY epic stage A1/A2. All default-off so legacy HS256 stays the only
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
    # Keep validating legacy HS256 tokens during migration; flip false at cutover (A4) once all
    # clients use OIDC (a short-TTL break-glass service token path is retained).
    legacy_hs256_enabled: bool = True
    webhook_port: int = 8443
    webhook_cert_dir: str = "/etc/norviq/certs"
    sidecar_image: str = "sanman97/norviq-engine:engine-latest"
    session_ttl_s: int = 3600
    graph_max_nodes: int = 5000
    # SIEM forwarder (outbound audit push). Off by default; the pull export endpoint is always on.
    siem_enabled: bool = False
    siem_webhook_url: str = ""
    siem_format: str = "ndjson"  # ndjson | syslog
    siem_poll_interval_s: int = 30
    # --- Multi-cluster fleet (F045), MVP P1 read-only. OFF by default -> single-cluster behaves as today.
    # Spoke relay: pushes agent + audit ROLLUPS to the hub fleet-api. Fire-and-forget, never on the
    # enforce hot path (hub down -> local enforcement unaffected; fleet views degrade, never open).
    fleet_enabled: bool = False
    fleet_api_url: str = ""             # hub base URL the relay pushes to
    fleet_cluster_id: str = ""          # this cluster's id in the fleet
    fleet_cluster_name: str = ""
    fleet_cluster_region: str = ""
    fleet_cluster_endpoint: str = ""
    # F-69: this cluster's OWN console URL, advertised to the hub on heartbeat so the hub console can deep-link
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
    # --- F045 P2 signed policy-push. The signing keypair is a DEDICATED fleet trust root, DISTINCT from
    # api_secret_key (so compromising the token secret can't forge bundles). HUB holds the private key;
    # spokes hold ONLY the public key. A spoke with an empty pubkey FAILS CLOSED (applies no bundle).
    fleet_signing_key: str = ""         # hub: RS256 private key PEM
    fleet_bundle_pubkey: str = ""       # spoke: RS256 public key PEM (the trust root)
    fleet_bundle_ttl_s: int = 900       # hub: signed bundle validity window (expires_at = issued_at + ttl)
    fleet_pull_interval_s: int = 60     # spoke: how often to pull + verify + apply the bundle
    # P4 residency: this spoke keeps raw audit in-cluster (rollups still leave; drill-down is blocked).
    fleet_residency: bool = False
    # P2: labels this cluster advertises to the hub for policy target_selector matching (e.g. {"env":"prod"}).
    fleet_cluster_labels: dict[str, str] = {}


settings = NorviqSettings()
if settings.otel_disabled:
    settings.otel_enabled = False
