# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HIGH-1 — HTTP-level rate limiting (norviq/api/rate_limit.py).

Covers the three load-bearing behaviors: excluded paths (k8s probes) are never throttled, an
over-limit caller gets 429 + Retry-After, and a Redis outage fails OPEN (availability > strictness)
rather than taking the whole API down.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from norviq.api.rate_limit import RateLimitMiddleware
from norviq.config import settings


class _FakeCache:
    """Minimal stand-in for RedisCache.incr_call_count (fixed-window counter)."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    async def incr_call_count(self, key: str, window_s: int = 60) -> int:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


class _BrokenCache:
    """Simulates Redis being unreachable — every call raises."""

    async def incr_call_count(self, key: str, window_s: int = 60) -> int:
        raise ConnectionError("redis unreachable")


def _app(cache) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)
    app.state.cache = cache

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/api/v1/whatever")
    async def whatever():
        return {"ok": True}

    return app


def test_excluded_paths_bypass_rate_limit(monkeypatch) -> None:
    """/healthz must never 429, even when the caller is already far over any configured limit."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 1)
    cache = _FakeCache()
    # Pre-fill the bucket a probe would use if it were (wrongly) counted, well past the limit.
    cache.counts["http:default:ip:testclient"] = 999
    client = TestClient(_app(cache))
    for _ in range(5):
        resp = client.get("/healthz")
        assert resp.status_code == 200
    # Confirm the exclusion actually short-circuited (no bucket key was ever touched for this path).
    assert not any(k for k in cache.counts if k != "http:default:ip:testclient")


def test_over_limit_returns_429_with_retry_after(monkeypatch) -> None:
    """The Nth+1 request within the window past the ceiling gets 429 + Retry-After."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 2)
    monkeypatch.setattr(settings, "http_rate_limit_window_s", 60)
    client = TestClient(_app(_FakeCache()))
    assert client.get("/api/v1/whatever").status_code == 200
    assert client.get("/api/v1/whatever").status_code == 200
    resp = client.get("/api/v1/whatever")
    assert resp.status_code == 429
    assert resp.headers.get("retry-after") == "60"


def test_redis_down_fails_open(monkeypatch) -> None:
    """A Redis outage must never take the API down — requests pass through un-throttled."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 1)
    client = TestClient(_app(_BrokenCache()))
    for _ in range(5):
        resp = client.get("/api/v1/whatever")
        assert resp.status_code == 200


def test_disabled_short_circuits(monkeypatch) -> None:
    """http_rate_limit_enabled=False bypasses the limiter entirely (operator kill switch)."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", False)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 1)
    client = TestClient(_app(_FakeCache()))
    for _ in range(5):
        assert client.get("/api/v1/whatever").status_code == 200
