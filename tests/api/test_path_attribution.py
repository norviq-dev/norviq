# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Request-path attribution must be complete, cheap, and unable to change behaviour.

The caller-observed cost of one enforcement decision decomposed (measured on AKS) as roughly 50% sidecar
process, 35% API HTTP layer, 15% evaluator — and only the evaluator was instrumented. Three optimisation
hypotheses were formed and disproven against that unmeasured 85% (OPA fork serialisation, per-call logging,
CPU throttling), which is why the remaining components are measured before anything is optimised.

The load-bearing tests here are the behavioural ones. `get_current_user` is a dependency of every
authenticated route, so wrapping it must not alter what it returns, what it raises, or its FastAPI
signature; and the rate limiter must still fail OPEN when Redis is unreachable.
"""

from __future__ import annotations

import inspect

import pytest
from fastapi import Depends, HTTPException

from norviq.api import auth as auth_mod
from norviq.telemetry.metrics import record_path_phase


def test_the_auth_wrapper_keeps_the_fastapi_signature() -> None:
    """FastAPI resolves dependencies by inspecting the signature. Changing it breaks every route."""
    sig = inspect.signature(auth_mod.get_current_user)
    assert list(sig.parameters) == ["creds", "request"]
    creds_default = sig.parameters["creds"].default
    assert isinstance(creds_default, type(Depends(lambda: None))), "creds must stay a Depends(...) default"


def test_the_wrapper_delegates_and_returns_the_same_claims(monkeypatch) -> None:
    """Instrumentation must not change the value a route receives."""
    import asyncio

    sentinel = {"sub": "alice", "role": "admin", "namespace": "team-a"}

    async def fake(creds, request):
        return sentinel

    monkeypatch.setattr(auth_mod, "_authenticate", fake)
    got = asyncio.run(auth_mod.get_current_user(creds=None, request=None))
    assert got is sentinel


def test_the_wrapper_still_raises_and_still_records(monkeypatch) -> None:
    """A slow REJECTION hurts a caller exactly as much as a slow acceptance, so the timer runs in a
    `finally` and the exception must propagate untouched."""
    import asyncio

    recorded: list[tuple[str, str, float]] = []

    async def fake(creds, request):
        raise HTTPException(status_code=401, detail="Missing token")

    monkeypatch.setattr(auth_mod, "_authenticate", fake)
    monkeypatch.setattr(auth_mod, "record_path_phase",
                        lambda c, p, ms: recorded.append((c, p, ms)))
    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_mod.get_current_user(creds=None, request=None))
    assert exc.value.status_code == 401
    assert recorded and recorded[0][0] == "api" and recorded[0][1] == "auth", (
        "the rejected path was not measured — the worst case would be invisible"
    )


def test_the_rate_limiter_still_fails_open_when_redis_is_down() -> None:
    """The limiter's own docstring promises fail-open. Adding a timer must not turn a Redis outage into a
    rejected request — that would convert an availability event into an enforcement outage."""
    import asyncio

    from norviq.api.rate_limit import RateLimitMiddleware
    from norviq.config import settings

    if not settings.http_rate_limit_enabled:
        pytest.skip("rate limiting disabled in this configuration")

    called: list[bool] = []

    async def downstream(scope, receive, send):
        called.append(True)

    class BrokenCache:
        async def incr_call_count(self, *_a, **_kw):
            raise RuntimeError("redis is down")

    class _State:
        cache = BrokenCache()

    class _App:
        state = _State()

    mw = RateLimitMiddleware(downstream)
    scope = {"type": "http", "path": "/api/v1/evaluate", "app": _App(), "headers": [],
             "client": ("10.0.0.1", 1234)}
    asyncio.run(mw(scope, None, None))
    assert called, "a Redis failure must not block the request"


def test_recorder_never_raises_on_hostile_input() -> None:
    """Runs on the hot path with telemetry possibly uninitialised; raising would fail a tool call."""
    record_path_phase("api", "auth", 1.0)
    record_path_phase("sidecar", "evaluate", 0.0)
    record_path_phase("sidecar", "unattributed", -1.0)
    record_path_phase("", "", float("nan"))


def test_the_sidecar_exposes_a_metrics_endpoint() -> None:
    """The caller-observed metric is recorded in the SIDECAR process. Without a scrape endpoint there it was
    recorded and unreachable, which is why that number had to be derived arithmetically instead of read."""
    from norviq.sidecar.http_fallback import create_http_fallback

    app = create_http_fallback(interceptor=None, emitter=None, resolver=None)  # type: ignore[arg-type]
    paths = {getattr(r, "path", None) for r in app.routes}
    mounts = {getattr(r, "path", None) for r in app.router.routes}
    assert "/metrics" in paths or "/metrics" in mounts, f"no /metrics on the sidecar app: {paths | mounts}"


# --- Closing the accounting: the outermost timer and the upstream split -----------------------------


def test_path_timing_is_the_outermost_middleware() -> None:
    """The whole point is measuring OUTSIDE the other layers.

    Starlette prepends, so the last-added middleware is outermost. TelemetryMiddleware is added first and is
    therefore the INNERMOST of the three — its `api_request_latency` excludes the rate limiter (~9 ms) and
    the body-size limiter. If PathTiming stops being outermost it silently measures a subset and the ~46 ms
    it exists to attribute becomes invisible again.
    """
    from norviq.api.main import create_app

    names = [m.cls.__name__ for m in create_app().user_middleware]
    assert names[0] == "PathTimingMiddleware", f"PathTiming must be outermost, got order {names}"
    assert "RateLimitMiddleware" in names[1:], "the rate limiter must still wrap the real work"


def test_path_timing_is_a_transparent_passthrough() -> None:
    """It must not alter scope, messages or the response — it only observes.

    Registered outside the rate limiter, so a bug here would affect every request including the ones the
    limiter is meant to reject cheaply.
    """
    import asyncio

    from norviq.api.path_timing import PathTimingMiddleware

    seen: dict = {}

    async def downstream(scope, receive, send):
        seen["scope"] = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    sent: list = []

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "path": "/api/v1/evaluate"}
    asyncio.run(PathTimingMiddleware(downstream)(scope, None, send))
    assert seen["scope"] is scope, "scope was replaced or copied"
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert sent[0]["status"] == 200 and sent[1]["body"] == b"ok"


def test_path_timing_records_even_when_the_request_raises() -> None:
    """A slow failing request is exactly the case worth seeing; `try/else` would drop it."""
    import asyncio

    from norviq.api import path_timing

    recorded: list = []

    async def boom(scope, receive, send):
        raise RuntimeError("handler exploded")

    orig = path_timing.record_path_phase
    path_timing.record_path_phase = lambda c, p, ms: recorded.append((c, p))
    try:
        with pytest.raises(RuntimeError):
            asyncio.run(path_timing.PathTimingMiddleware(boom)(
                {"type": "http", "path": "/api/v1/evaluate"}, None, None
            ))
    finally:
        path_timing.record_path_phase = orig
    # The hot-path bucket specifically: a failing enforcement call is the one whose cost matters most.
    assert ("api", "total_asgi") in recorded


def test_path_timing_ignores_non_http_scopes() -> None:
    """Websockets and lifespan must pass through untouched — timing them would be meaningless."""
    import asyncio

    from norviq.api.path_timing import PathTimingMiddleware

    called: list = []

    async def downstream(scope, receive, send):
        called.append(scope["type"])

    asyncio.run(PathTimingMiddleware(downstream)({"type": "lifespan"}, None, None))
    asyncio.run(PathTimingMiddleware(downstream)({"type": "websocket"}, None, None))
    assert called == ["lifespan", "websocket"]


def test_total_asgi_is_bucketed_so_it_stays_comparable() -> None:
    """An unlabelled total is not comparable to a per-endpoint inner metric.

    The first version aggregated every path, so /metrics scrapes (341 ms each) and /readyz inflated the mean
    and subtracting the /evaluate-only inner metric produced a gap that was partly an aggregation artefact.
    Two buckets: the hot path and everything else — comparable, and bounded against path-param cardinality.
    """
    import asyncio

    from norviq.api import path_timing

    seen: list = []

    async def ok(scope, receive, send):
        return None

    orig = path_timing.record_path_phase
    path_timing.record_path_phase = lambda c, p, ms: seen.append(p)
    try:
        asyncio.run(path_timing.PathTimingMiddleware(ok)({"type": "http", "path": "/api/v1/evaluate"}, None, None))
        asyncio.run(path_timing.PathTimingMiddleware(ok)({"type": "http", "path": "/metrics"}, None, None))
        asyncio.run(path_timing.PathTimingMiddleware(ok)({"type": "http", "path": "/api/v1/policies/a/b"}, None, None))
    finally:
        path_timing.record_path_phase = orig
    assert seen == ["total_asgi", "total_asgi_other", "total_asgi_other"], seen
