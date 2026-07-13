# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OpenTelemetry provider setup for Norviq."""

from __future__ import annotations

import structlog
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from norviq.config import settings

log = structlog.get_logger()
_state = {"enabled": False}


def setup_telemetry() -> None:
    """Initialize OpenTelemetry providers and exporters."""
    if not settings.otel_enabled:
        return
    _setup_metrics()
    _setup_tracing()
    _state["enabled"] = True
    log.info("nrvq.telemetry.initialized", code="NRVQ-TEL-12000")


def _setup_metrics() -> None:
    """Configure metrics with Prometheus exporter."""
    try:
        from opentelemetry.exporter.prometheus import PrometheusMetricReader

        reader = PrometheusMetricReader()
        metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
        log.info("nrvq.telemetry.metrics_ready", endpoint="/metrics", code="NRVQ-TEL-12001")
    except ModuleNotFoundError:
        metrics.set_meter_provider(MeterProvider())
        log.warning("nrvq.telemetry.prometheus_missing", code="NRVQ-TEL-12007")


def _setup_tracing() -> None:
    """Configure tracing with optional OTLP exporter."""
    provider = TracerProvider()
    if settings.otel_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        log.info("nrvq.telemetry.tracing_ready", endpoint=settings.otel_endpoint, code="NRVQ-TEL-12002")
    else:
        log.warning("nrvq.telemetry.no_otel_endpoint", code="NRVQ-TEL-12003")
    trace.set_tracer_provider(provider)


def shutdown_telemetry() -> None:
    """Gracefully shut down telemetry providers."""
    if not _state["enabled"]:
        return
    trace.get_tracer_provider().shutdown()
    _state["enabled"] = False
    log.info("nrvq.telemetry.shutdown", code="NRVQ-TEL-12004")
