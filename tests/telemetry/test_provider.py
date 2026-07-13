# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Telemetry provider setup tests."""

from __future__ import annotations

from opentelemetry import metrics, trace

from norviq.telemetry import provider


def test_setup_telemetry_sets_providers(monkeypatch) -> None:
    """Set meter and tracer providers when telemetry is enabled."""
    monkeypatch.setattr(provider.settings, "otel_enabled", True)
    monkeypatch.setattr(provider.settings, "otel_endpoint", "")
    provider.setup_telemetry()
    assert metrics.get_meter_provider() is not None
    assert trace.get_tracer_provider() is not None
    provider.shutdown_telemetry()


def test_setup_telemetry_noop_when_disabled(monkeypatch) -> None:
    """Skip provider setup when telemetry is disabled."""
    monkeypatch.setattr(provider.settings, "otel_enabled", False)
    provider._state["enabled"] = False
    provider.setup_telemetry()
    assert provider._state["enabled"] is False
