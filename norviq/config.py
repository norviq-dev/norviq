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
    redis_url: str = "redis://localhost:6379"
    redis_max_connections: int = 20
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
    pg_url: str = "postgresql://norviq:norviq_dev@localhost:5432/norviq"
    db_ssl_mode: str = Field(
        default="prefer",
        validation_alias=AliasChoices("DB_SSL_MODE", "PG_SSL_MODE", "PG_SSLMODE", "NRVQ_DB_SSL_MODE"),
    )
    pg_pool_size: int = Field(default=10, validation_alias=AliasChoices("PG_POOL_SIZE", "DB_POOL_SIZE"))
    db_pool_max_overflow: int = 5
    db_pool_timeout: int = 5
    db_command_timeout: int = 5
    audit_retention_days: int = 365
    otel_endpoint: str = "http://localhost:4317"
    otel_enabled: bool = True
    otel_disabled: bool = False
    prometheus_port: int = 9090
    log_level: str = "INFO"
    log_format: str = "json"
    socket_path: str = "/tmp/norviq-proxy.sock"
    http_fallback_port: int = 8282
    api_port: int = 8080
    api_secret_key: str = Field(
        default="change-me-in-production",  # Replace in non-dev deployments.
        # NRVQ_API_SECRET_KEY is what the Helm chart sets — include it so the key is rotatable.
        validation_alias=AliasChoices("API_SECRET_KEY", "JWT_SECRET", "NRVQ_API_SECRET_KEY"),
    )
    # When true (set in prod via NRVQ_REQUIRE_STRONG_SECRET), the API refuses to start on the
    # default JWT secret. Defaults False so local dev / tests / the attack suite keep working.
    require_strong_secret: bool = False
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


settings = NorviqSettings()
if settings.otel_disabled:
    settings.otel_enabled = False
