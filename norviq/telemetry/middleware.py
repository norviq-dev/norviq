# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Request traces and latency metrics, as pure ASGI.

This MUST NOT be ``BaseHTTPMiddleware`` — the same rule already documented in ``body_limit.py`` and
``rate_limit.py``, and for the same reason plus a measured one.

``BaseHTTPMiddleware`` does not simply call the app. For every request it opens an anyio task group, pipes
the downstream response through a pair of memory object streams, and re-emits it from a second task. That
machinery is per-request and it sits on the enforcement hot path: this middleware is registered FIRST, and
``add_middleware`` prepends, so it is the INNERMOST wrapper around the router — every `/evaluate` call pays
it.

Measured on AKS after the CPU-throttling fix, with handler-level phases in place:

    total_asgi   66.1 ms      (outermost, the whole ASGI call)
    route_total  26.4 ms      (the handler, of which route_evaluate is 25.7)
    ratelimit     4.4 ms
    auth          3.5 ms
    -> ~32 ms unaccounted for, i.e. MORE than the entire policy evaluation

Rewritten as pure ASGI, the request is passed straight through and only the response START message is
inspected for its status code — no task group, no streams, no re-emission.

Behaviour is deliberately identical: same span name and attributes, same `record_api_latency` call with the
same path label. The one improvement is that latency is recorded in a ``finally``, so a request that raises
still reports its cost — an exception path that is slow is exactly the case worth seeing, and
``BaseHTTPMiddleware`` dropped it.
"""

from __future__ import annotations

import time

from opentelemetry import trace
from starlette.datastructures import URL

from norviq.telemetry.metrics import record_api_latency

tracer = trace.get_tracer("norviq.api")


class TelemetryMiddleware:
    """Record a span and request latency for each incoming request."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        """Pass the request through, capturing only the response status on its way out."""
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Mutable holder rather than a nonlocal: the wrapper below is a closure called from the app, and
        # a plain assignment would need `nonlocal` in every branch. Defaults to 500 so a request that dies
        # before emitting a response start is not recorded as a success.
        status = {"code": 500}

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        with tracer.start_as_current_span(
            name=f"{scope.get('method', '')} {path}",
            # URL is built lazily from the scope — the same string BaseHTTPMiddleware produced via
            # `str(request.url)`, without constructing a Request object per call.
            attributes={
                "http.method": scope.get("method", ""),
                "http.url": str(URL(scope=scope)),
                "http.route": path,
            },
        ) as span:
            start = time.perf_counter()
            try:
                await self.app(scope, receive, send_wrapper)
            finally:
                latency_ms = (time.perf_counter() - start) * 1000
                span.set_attribute("http.status_code", status["code"])
                span.set_attribute("http.latency_ms", latency_ms)
                record_api_latency(path, latency_ms)
