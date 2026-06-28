# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Metric instruments and recording helpers."""

from __future__ import annotations

import structlog
from opentelemetry import metrics
from opentelemetry.metrics import Meter

log = structlog.get_logger()
_meter: Meter = metrics.get_meter("norviq")

# Prometheus mirror: the OTel meters above only surface on /metrics when OTel is
# enabled (provider.py wires a PrometheusMetricReader). OTel is off by default, so
# we also record into prometheus_client instruments on a dedicated registry that
# exporter.py always mounts — guaranteeing norviq_* lines on /metrics either way.
try:
    from prometheus_client import CollectorRegistry, Counter, Histogram

    NRVQ_REGISTRY: CollectorRegistry | None = CollectorRegistry()
    _LATENCY_BUCKETS = (1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
    _p_tool_calls = Counter(
        "norviq_tool_calls_total", "Total tool calls processed",
        ["namespace", "agent_class", "tool_name", "decision"], registry=NRVQ_REGISTRY,
    )
    _p_tool_blocked = Counter(
        "norviq_tool_calls_blocked_total", "Total tool calls blocked",
        ["namespace", "agent_class", "tool_name"], registry=NRVQ_REGISTRY,
    )
    _p_cache_hits = Counter("norviq_cache_hits_total", "Cache hits", ["cache_type"], registry=NRVQ_REGISTRY)
    _p_cache_misses = Counter("norviq_cache_misses_total", "Cache misses", ["cache_type"], registry=NRVQ_REGISTRY)
    _p_eval_latency = Histogram(
        "norviq_evaluation_latency_ms", "Policy evaluation latency in milliseconds",
        ["namespace", "cache_hit"], buckets=_LATENCY_BUCKETS, registry=NRVQ_REGISTRY,
    )
    _p_trust = Histogram(
        "norviq_trust_score", "Trust score distribution", ["namespace"],
        buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0), registry=NRVQ_REGISTRY,
    )
    _p_api_latency = Histogram(
        "norviq_api_request_latency_ms", "API request latency in milliseconds",
        ["endpoint"], buckets=_LATENCY_BUCKETS, registry=NRVQ_REGISTRY,
    )
except ModuleNotFoundError:  # pragma: no cover
    NRVQ_REGISTRY = None
    _p_tool_calls = _p_tool_blocked = _p_cache_hits = _p_cache_misses = None
    _p_eval_latency = _p_trust = _p_api_latency = None

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
    namespace = labels.get("namespace", "default")
    try:
        tool_call_total.add(1, labels)
        latency_labels = {"namespace": namespace, "cache_hit": str(cache_hit_value).lower()}
        evaluation_latency.record(latency_ms, latency_labels)
        trust_score_distribution.record(trust_score, {"namespace": namespace})
        if labels.get("decision") == "block":
            tool_call_blocked.add(1, labels)
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")
    if _p_tool_calls is not None:
        try:
            agent_class = labels.get("agent_class", "")
            tool_name = labels.get("tool_name", "")
            decision = labels.get("decision", "")
            _p_tool_calls.labels(namespace, agent_class, tool_name, decision).inc()
            _p_eval_latency.labels(namespace, str(cache_hit_value).lower()).observe(latency_ms)
            _p_trust.labels(namespace).observe(trust_score)
            if decision == "block":
                _p_tool_blocked.labels(namespace, agent_class, tool_name).inc()
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
    mirror = _p_cache_hits if counter is cache_hits else _p_cache_misses
    if mirror is not None:
        try:
            mirror.labels(cache_type).inc()
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")


def record_api_latency(endpoint: str, latency_ms: float) -> None:
    """Record API latency in dedicated request histogram."""
    try:
        api_request_latency.record(latency_ms, {"endpoint": endpoint})
    except Exception as exc:  # pragma: no cover
        log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")
    if _p_api_latency is not None:
        try:
            _p_api_latency.labels(endpoint).observe(latency_ms)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.telemetry.metric_failed", error=str(exc), code="NRVQ-TEL-12005")


init_metrics()
