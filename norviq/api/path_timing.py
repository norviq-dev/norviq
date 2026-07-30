# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Outermost ASGI timer: total time the API holds a request.

`TelemetryMiddleware` already records `api_request_latency`, but Starlette's `add_middleware` PREPENDS, so
the middleware added LAST is outermost — and Telemetry is added first, making it the innermost of the three.
Its number therefore excludes everything wrapping it: the rate limiter (measured separately at ~9 ms), the
body-size limiter, and whatever ASGI/uvicorn work happens around them.

That mattered. The sidecar measured ~156 ms waiting on its upstream call while the API reported 93 ms for
`/evaluate`, leaving ~46 ms with nowhere to attribute it — and two of the three candidate explanations sat in
exactly that unmeasured window. This closes it: recorded as far out as ASGI allows, so
`total_asgi - api_request_latency` is the cost of the outer layers, and
`upstream(post) - total_asgi` is genuinely the wire.

Passthrough only. It touches neither scope nor messages, so it cannot alter a response — and it must be
registered LAST in `create_app` or it stops being outermost and measures the wrong thing.
"""

from __future__ import annotations

from time import perf_counter

from norviq.telemetry.metrics import record_path_phase


# The enforcement hot path. Everything else shares one bucket, so cardinality stays at two.
_HOT_PATH = "/api/v1/evaluate"


class PathTimingMiddleware:
    """Time the full downstream ASGI call. Pure ASGI so it wraps middleware, not just routes."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        # Bucketed by path, because an UNLABELLED total is not comparable to anything. The first version of
        # this metric aggregated every endpoint, so a handful of /metrics scrapes (341 ms each) and /readyz
        # (30-50 ms) inflated the mean, and subtracting the /evaluate-only inner metric from it produced a
        # ~47 ms "gap" that was partly an artefact of my own aggregation. Two buckets only — the hot path and
        # everything else — so this stays comparable without unbounded label cardinality from path params.
        bucket = "total_asgi" if scope.get("path") == _HOT_PATH else "total_asgi_other"
        t0 = perf_counter()
        try:
            await self.app(scope, receive, send)
        finally:
            # `finally`, so a request that raises still reports its cost. An exception path that is slow is
            # exactly the case worth seeing, and it is the one a `try/else` would silently drop.
            record_path_phase("api", bucket, (perf_counter() - t0) * 1000.0)
