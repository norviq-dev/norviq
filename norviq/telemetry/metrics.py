# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Metric instruments and recording helpers."""

from __future__ import annotations

import structlog
from opentelemetry import metrics
from opentelemetry.metrics import Meter

log = structlog.get_logger()
_meter: Meter = metrics.get_meter("norviq")

tool_call_total = None
tool_call_blocked = None
cache_hits = None
cache_misses = None
policy_violations = None
evaluation_latency = None
trust_score_distribution = None
api_request_latency = None
active_agents = None
block_rate = None
graph_nodes = None
graph_edges = None


def init_metrics(meter: Meter | None = None) -> None:
    """Create all telemetry instruments."""
    global _meter, tool_call_total, tool_call_blocked, cache_hits, cache_misses
    global policy_violations, evaluation_latency, trust_score_distribution, api_request_latency
    global active_agents, block_rate, graph_nodes, graph_edges
    _meter = meter or metrics.get_meter("norviq")
    tool_call_total = _meter.create_counter("norviq_tool_calls_total", description="Total tool calls processed", unit="1")
    tool_call_blocked = _meter.create_counter(
        "norviq_tool_calls_blocked_total", description="Total tool calls blocked", unit="1"
    )
    cache_hits = _meter.create_counter("norviq_cache_hits_total", description="Cache hits (policy + eval)", unit="1")
    cache_misses = _meter.create_counter("norviq_cache_misses_total", description="Cache misses", unit="1")
    policy_violations = _meter.create_counter(
        "norviq_policy_violations_total", description="Policy violations by OWASP category", unit="1"
    )
    evaluation_latency = _meter.create_histogram(
        "norviq_evaluation_latency_ms", description="Policy evaluation latency in milliseconds", unit="ms"
    )
    trust_score_distribution = _meter.create_histogram("norviq_trust_score", description="Trust score distribution", unit="1")
    api_request_latency = _meter.create_histogram(
        "norviq_api_request_latency_ms",
        description="API request latency in milliseconds",
        unit="ms",
    )
    active_agents = _meter.create_up_down_counter("norviq_active_agents", description="Number of active agents", unit="1")
    block_rate = _meter.create_up_down_counter("norviq_block_rate_percent", description="Block rate percentage", unit="%")
    graph_nodes = _meter.create_up_down_counter("norviq_graph_nodes", description="Asset graph node count", unit="1")
    graph_edges = _meter.create_up_down_counter("norviq_graph_edges", description="Asset graph edge count", unit="1")


def record_tool_call(labels: dict[str, str], latency_ms: float, trust_score: float, cache_hit_value: bool) -> None:
    """Record tool call counters and latency histograms."""
    try:
        tool_call_total.add(1, labels)
        latency_labels = {"namespace": labels.get("namespace", "default"), "cache_hit": str(cache_hit_value).lower()}
        evaluation_latency.record(latency_ms, latency_labels)
        trust_score_distribution.record(trust_score, {"namespace": labels.get("namespace", "default")})
        if labels.get("decision") == "block":
            tool_call_blocked.add(1, labels)
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")


def record_cache_hit(cache_type: str) -> None:
    """Record cache-hit counter for the provided cache type."""
    _record_cache(cache_hits, cache_type)


def record_cache_miss(cache_type: str) -> None:
    """Record cache-miss counter for the provided cache type."""
    _record_cache(cache_misses, cache_type)


def _record_cache(counter, cache_type: str) -> None:
    """Record cache counters with consistent error handling."""
    try:
        counter.add(1, {"cache_type": cache_type})
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")


def record_api_latency(endpoint: str, latency_ms: float) -> None:
    """Record API latency in dedicated request histogram."""
    try:
        api_request_latency.record(latency_ms, {"endpoint": endpoint})
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")


init_metrics()
