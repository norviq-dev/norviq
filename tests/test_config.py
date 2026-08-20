# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for Norviq settings."""

import os

from norviq.config import NorviqSettings, settings


def test_settings_defaults(monkeypatch) -> None:
    """Load code defaults when no NRVQ vars / env files are present."""
    for key in list(os.environ):
        if key.startswith("NRVQ_"):
            monkeypatch.delenv(key, raising=False)
    # _env_file=None ignores the dev .env/.env.local so we assert true code defaults.
    loaded = NorviqSettings(_env_file=None)
    # In-cluster central API service — the URL PolicyEngineClient posts /api/v1/evaluate to.
    assert loaded.policy_engine_url == "http://norviq-api:8080"
    assert loaded.redis_url == "redis://localhost:6379"
    assert loaded.enforcement_mode == "block"  # secure fail-closed default (see config.py)
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
    # pg_pool_size's validation_alias is PG_POOL_SIZE/DB_POOL_SIZE (no NRVQ_ prefix) — config.py.
    monkeypatch.setenv("PG_POOL_SIZE", "25")
    monkeypatch.setenv("NRVQ_TRUST_VIOLATION_PENALTY", "0.15")
    loaded = NorviqSettings(_env_file=None)
    assert isinstance(loaded.sdk_timeout_ms, int)
    assert isinstance(loaded.pg_pool_size, int)
    assert isinstance(loaded.trust_violation_penalty, float)
    assert loaded.sdk_timeout_ms == 9000
    assert loaded.pg_pool_size == 25
    assert loaded.trust_violation_penalty == 0.15


def test_settings_singleton_import() -> None:
    """Expose importable settings singleton."""
    assert isinstance(settings, NorviqSettings)


def test_api_secret_key_reads_nrvq_prefixed_env(monkeypatch) -> None:
    """The chart sets NRVQ_API_SECRET_KEY — it must actually populate api_secret_key."""
    monkeypatch.setenv("NRVQ_API_SECRET_KEY", "rotated-prod-secret-123")
    loaded = NorviqSettings(_env_file=None)
    assert loaded.api_secret_key == "rotated-prod-secret-123"


def test_db_ssl_mode_reads_nrvq_prefixed_env(monkeypatch) -> None:
    """NRVQ_DB_SSL_MODE from the chart configmap must populate db_ssl_mode."""
    monkeypatch.setenv("NRVQ_DB_SSL_MODE", "verify-full")
    loaded = NorviqSettings(_env_file=None)
    assert loaded.db_ssl_mode == "verify-full"


def test_require_strong_secret_defaults_true(monkeypatch) -> None:
    """Fail-closed by default — a forgeable default JWT secret is a fleet-wide trust-root
    compromise, so the boot-time refusal is ON unless explicitly disabled (NRVQ_REQUIRE_STRONG_SECRET=false)
    or a real secret is configured. Dev/tests set an explicit strong NRVQ_API_SECRET_KEY (see
    tests/conftest.py) rather than disabling the guard, so the guard itself stays covered."""
    for key in list(os.environ):
        if key.startswith("NRVQ_"):
            monkeypatch.delenv(key, raising=False)
    loaded = NorviqSettings(_env_file=None)
    assert loaded.require_strong_secret is True


def test_the_chart_s_rate_limit_var_actually_reaches_the_limiter(monkeypatch) -> None:
    """`config.rateLimit` must change the throttle. It silently did not.

    helm/norviq/templates/configmap.yaml renders `config.rateLimit` as NRVQ_RATE_LIMIT. No Settings
    field consumed that name, and SettingsConfigDict(extra="ignore") drops an unmatched env var
    without a word — so an operator tightening the per-identity limiter to 5/60s kept getting the
    code default of 60/60s, with nothing anywhere to tell them.

    Both defaults are 60, which is what made it invisible: the documented value matched the effective
    one, so the knob looked wired right up until somebody depended on it. That is the same shape as
    every other defect this release chased — a control that reads as working while doing nothing.

    Asserting a NON-default value is the point. A test that set it to 60 would pass against the bug.
    """
    from norviq.config import NorviqSettings

    monkeypatch.delenv("NRVQ_EVALUATOR_RATE_LIMIT_PER_WINDOW", raising=False)
    monkeypatch.setenv("NRVQ_RATE_LIMIT", "5")
    assert NorviqSettings().evaluator_rate_limit_per_window == 5

    # The canonical name must keep working — a validation_alias REPLACES the env_prefix lookup, so
    # listing only the chart's variable would have broken anyone setting it the documented way.
    monkeypatch.delenv("NRVQ_RATE_LIMIT", raising=False)
    monkeypatch.setenv("NRVQ_EVALUATOR_RATE_LIMIT_PER_WINDOW", "7")
    assert NorviqSettings().evaluator_rate_limit_per_window == 7

    monkeypatch.delenv("NRVQ_EVALUATOR_RATE_LIMIT_PER_WINDOW", raising=False)
    assert NorviqSettings().evaluator_rate_limit_per_window == 60


def test_every_env_var_the_chart_renders_is_actually_consumed() -> None:
    """The chart must not render a variable that nothing reads.

    This class of bug has now happened twice — NRVQ_RATE_LIMIT and NRVQ_VIOLATION_PENALTY — and both
    times the shape was identical: configmap.yaml renders a name, no Settings field binds it,
    SettingsConfigDict(extra="ignore") drops it in silence, and because the chart default matched the
    code default the knob looked wired right up until an operator depended on it. One of them governs
    a rate limiter and the other how fast a misbehaving identity loses trust; both read as configured
    while doing nothing.

    Fixing instances leaves the class open, so this asserts the invariant over EVERY rendered
    variable. A new one added to configmap.yaml without a matching field fails here rather than in
    somebody's cluster.
    """
    import re
    from pathlib import Path
    from pydantic import AliasChoices
    from norviq.config import NorviqSettings

    cm = Path(__file__).resolve().parents[1] / "helm/norviq/templates/configmap.yaml"
    rendered = set(re.findall(r"^\s{2}(NRVQ_[A-Z0-9_]+):", cm.read_text(), re.M))

    consumed: set[str] = set()
    for name, field in NorviqSettings.model_fields.items():
        consumed.add(f"NRVQ_{name.upper()}")           # the env_prefix binding
        alias = getattr(field, "validation_alias", None)
        if isinstance(alias, AliasChoices):
            consumed.update(str(c).upper() for c in alias.choices)
        elif isinstance(alias, str):
            consumed.add(alias.upper())

    # Consumed OUTSIDE pydantic, deliberately. Each needs its reader named, so that "it is fine, it
    # is read elsewhere" is a checkable claim rather than an assumption — the assumption is exactly
    # what let the two real orphans sit here unnoticed.
    NON_PYDANTIC = {
        "NRVQ_API_WORKERS": "Dockerfile.api CMD — uvicorn --workers ${NRVQ_API_WORKERS:-4}",
    }

    orphans = sorted(rendered - consumed - set(NON_PYDANTIC))
    assert not orphans, (
        "configmap.yaml renders variables nothing consumes: "
        + ", ".join(orphans)
        + ". Either bind them with a validation_alias, or record the reader in NON_PYDANTIC."
    )
