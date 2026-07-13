# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI middleware for request traces and latency metrics."""

from __future__ import annotations

import time

from opentelemetry import trace
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from norviq.telemetry.metrics import record_api_latency

tracer = trace.get_tracer("norviq.api")


class TelemetryMiddleware(BaseHTTPMiddleware):
    """Record span and latency for each incoming request."""

    async def dispatch(self, request: Request, call_next) -> Response:
        """Wrap each request in a span and emit latency."""
        with tracer.start_as_current_span(
            name=f"{request.method} {request.url.path}",
            attributes={"http.method": request.method, "http.url": str(request.url), "http.route": request.url.path},
        ) as span:
            start = time.perf_counter()
            response = await call_next(request)
            latency_ms = (time.perf_counter() - start) * 1000
            span.set_attribute("http.status_code", response.status_code)
            span.set_attribute("http.latency_ms", latency_ms)
            record_api_latency(request.url.path, latency_ms)
            return response
