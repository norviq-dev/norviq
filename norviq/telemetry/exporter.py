# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Prometheus exporter helpers."""

from fastapi import FastAPI
from starlette.responses import PlainTextResponse


def mount_metrics_endpoint(app: FastAPI) -> None:
    """Mount Prometheus scrape endpoint on /metrics."""
    try:
        from prometheus_client import make_asgi_app

        app.mount("/metrics", make_asgi_app())
    except ModuleNotFoundError:
        @app.get("/metrics")
        async def _fallback_metrics() -> PlainTextResponse:
            return PlainTextResponse("# prometheus_client is not installed\n")
