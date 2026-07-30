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
