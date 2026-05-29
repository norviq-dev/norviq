"""Tests for Norviq settings."""

from norviq.config import NorviqSettings, settings


def test_settings_defaults() -> None:
    """Load defaults when no NRVQ vars are set."""
    loaded = NorviqSettings()
    assert loaded.policy_engine_url == "http://localhost:8181"
    assert loaded.redis_url == "redis://localhost:6379"
    assert loaded.enforcement_mode == "audit"
    assert loaded.trust_threshold == 0.7
    assert loaded.log_level == "INFO"


def test_settings_reads_env_vars(monkeypatch) -> None:
    """Read NRVQ_ values from environment."""
    monkeypatch.setenv("NRVQ_POLICY_ENGINE_URL", "http://policy.internal:8181")
    monkeypatch.setenv("NRVQ_ENFORCEMENT_MODE", "block")
    monkeypatch.setenv("NRVQ_REDIS_URL", "redis://cache:6379")
    monkeypatch.setenv("NRVQ_TRUST_THRESHOLD", "0.9")
    loaded = NorviqSettings()
    assert loaded.policy_engine_url == "http://policy.internal:8181"
    assert loaded.enforcement_mode == "block"
    assert loaded.redis_url == "redis://cache:6379"
    assert loaded.trust_threshold == 0.9


def test_settings_validates_types(monkeypatch) -> None:
    """Parse scalar values into typed fields."""
    monkeypatch.setenv("NRVQ_SDK_TIMEOUT_MS", "9000")
    monkeypatch.setenv("NRVQ_PG_POOL_SIZE", "25")
    monkeypatch.setenv("NRVQ_TRUST_VIOLATION_PENALTY", "0.15")
    loaded = NorviqSettings()
    assert isinstance(loaded.sdk_timeout_ms, int)
    assert isinstance(loaded.pg_pool_size, int)
    assert isinstance(loaded.trust_violation_penalty, float)
    assert loaded.sdk_timeout_ms == 9000
    assert loaded.pg_pool_size == 25
    assert loaded.trust_violation_penalty == 0.15


def test_settings_singleton_import() -> None:
    """Expose importable settings singleton."""
    assert isinstance(settings, NorviqSettings)
