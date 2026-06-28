# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Telemetry metric recording tests."""

from __future__ import annotations

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from norviq.telemetry import metrics as tel_metrics


def _metric_names(reader: InMemoryMetricReader) -> set[str]:
    """Collect all exported metric names."""
    data = reader.get_metrics_data()
    names: set[str] = set()
    for resource_metric in data.resource_metrics:
        for scope_metric in resource_metric.scope_metrics:
            for metric in scope_metric.metrics:
                names.add(metric.name)
    return names


def test_records_tool_call_and_cache_metrics() -> None:
    """Record counters and histograms for tool call and cache events."""
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    tel_metrics.init_metrics(provider.get_meter("norviq-test"))
    labels = {"namespace": "tenant-a", "agent_class": "support", "tool_name": "search", "decision": "block"}
    tel_metrics.record_tool_call(labels, latency_ms=12.5, trust_score=0.4, cache_hit_value=False)
    tel_metrics.record_api_latency("/ping", latency_ms=3.1)
    tel_metrics.record_cache_hit("eval")
    tel_metrics.record_cache_miss("eval")
    names = _metric_names(reader)
    assert "norviq_tool_calls_total" in names
    assert "norviq_tool_calls_blocked_total" in names
    assert "norviq_evaluation_latency_ms" in names
    assert "norviq_trust_score" in names
    assert "norviq_api_request_latency_ms" in names
    assert "norviq_cache_hits_total" in names
    assert "norviq_cache_misses_total" in names


def test_prometheus_mirror_exposes_norviq_metrics() -> None:
    """The /metrics mirror registry surfaces norviq_* series even with OTel disabled."""
    from prometheus_client import generate_latest

    assert tel_metrics.NRVQ_REGISTRY is not None
    labels = {"namespace": "tenant-b", "agent_class": "support", "tool_name": "search", "decision": "block"}
    tel_metrics.record_tool_call(labels, latency_ms=8.0, trust_score=0.6, cache_hit_value=False)
    tel_metrics.record_cache_hit("eval")
    tel_metrics.record_cache_miss("policy")
    tel_metrics.record_api_latency("/api/v1/evaluate", latency_ms=4.2)
    out = generate_latest(tel_metrics.NRVQ_REGISTRY).decode()
    assert "norviq_tool_calls_total" in out
    assert "norviq_tool_calls_blocked_total" in out
    assert "norviq_cache_hits_total" in out
    assert "norviq_cache_misses_total" in out
    assert "norviq_evaluation_latency_ms_bucket" in out
    assert "norviq_trust_score_bucket" in out
    assert "norviq_api_request_latency_ms_bucket" in out
