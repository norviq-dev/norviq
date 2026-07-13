# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Prometheus exporter helpers."""

from fastapi import FastAPI
from starlette.responses import PlainTextResponse


def mount_metrics_endpoint(app: FastAPI) -> None:
    """Mount Prometheus scrape endpoint on /metrics over the norviq_* mirror registry."""
    try:
        from prometheus_client import make_asgi_app

        from norviq.telemetry.metrics import NRVQ_REGISTRY

        # Serve the dedicated norviq registry so norviq_* metrics are present even when
        # OTel is disabled; fall back to the default registry if the mirror is unavailable.
        app.mount("/metrics", make_asgi_app(registry=NRVQ_REGISTRY) if NRVQ_REGISTRY else make_asgi_app())
    except ModuleNotFoundError:
        @app.get("/metrics")
        async def _fallback_metrics() -> PlainTextResponse:
            return PlainTextResponse("# prometheus_client is not installed\n")
