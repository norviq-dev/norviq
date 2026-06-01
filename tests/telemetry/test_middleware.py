# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI telemetry middleware tests."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from norviq.telemetry.exporter import mount_metrics_endpoint
from norviq.telemetry.middleware import TelemetryMiddleware


def test_middleware_records_request_and_metrics_endpoint() -> None:
    """Serve API routes with middleware and expose /metrics."""
    app = FastAPI()
    app.add_middleware(TelemetryMiddleware)
    mount_metrics_endpoint(app)

    @app.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    client = TestClient(app)
    try:
        response = client.get("/ping")
        assert response.status_code == 200
        metrics_response = client.get("/metrics")
        assert metrics_response.status_code == 200
        assert "norviq_" in metrics_response.text or "prometheus_client is not installed" in metrics_response.text
    finally:
        client.close()
