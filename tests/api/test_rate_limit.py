# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP-level rate limiting (norviq/api/rate_limit.py).

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


# --- X-Forwarded-For trust (throttle-bypass regression) --------------------------------------------
# XFF is client-writable, so bucketing on its left-most entry let a caller rotate the header and never
# fill a bucket. It is now believed only when the TCP PEER is a trusted proxy AND the chain is long
# enough, taking the Nth entry from the RIGHT. _client_ip is unit-tested directly against an ASGI scope
# because TestClient's peer is the fixed literal "testclient", which is not an IP and so is never trusted.

from norviq.api.rate_limit import _client_ip  # noqa: E402 - grouped with the XFF cases below

_TRUSTED_PEER = ("127.0.0.1", 51000)  # the in-pod nginx
_UNTRUSTED_PEER = ("10.42.0.9", 51000)  # another pod hitting the API port directly


def _scope(peer, *xff_headers):
    return {"client": peer, "headers": [(b"x-forwarded-for", v.encode()) for v in xff_headers]}


def test_rotating_xff_cannot_evade_the_throttle(monkeypatch) -> None:
    """THE BYPASS: from an UNTRUSTED peer a fresh XFF per request must not mint a fresh bucket."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 2)
    client = TestClient(_app(_FakeCache()))
    codes = [
        client.get("/api/v1/whatever", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code for i in range(1, 6)
    ]
    assert codes[:2] == [200, 200]
    assert codes[2:] == [429, 429, 429]  # every rotated value collapses to the one peer bucket


def test_xff_from_untrusted_peer_is_ignored(monkeypatch) -> None:
    """A workload hitting the API port directly cannot reach the forgeable path at all."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    assert _client_ip(_scope(_UNTRUSTED_PEER, "203.0.113.9")) == "10.42.0.9"


def test_xff_from_trusted_proxy_yields_the_real_client(monkeypatch) -> None:
    """Through the in-pod nginx (which REPLACES the header) each caller keeps its own bucket."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    assert _client_ip(_scope(_TRUSTED_PEER, "203.0.113.9")) == "203.0.113.9"


def test_trusted_proxy_uses_nth_entry_from_the_right(monkeypatch) -> None:
    """Forged left-hand entries are ignored; only what our own proxy appended is used."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    assert _client_ip(_scope(_TRUSTED_PEER, "1.2.3.4, 5.6.7.8, 198.51.100.23")) == "198.51.100.23"


def test_duplicate_xff_headers_cannot_hand_the_attacker_the_value(monkeypatch) -> None:
    """A proxy that ADDS its own header line must not leave the attacker's line first."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    # First header is the caller's own; the second was added by our proxy.
    assert _client_ip(_scope(_TRUSTED_PEER, "1.2.3.4", "198.51.100.23")) == "198.51.100.23"


def test_short_xff_chain_falls_back_to_peer(monkeypatch) -> None:
    """Fewer entries than trusted hops = it didn't traverse the expected chain -> use the peer."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 2)
    assert _client_ip(_scope(_TRUSTED_PEER, "203.0.113.9")) == "127.0.0.1"


def test_hops_zero_always_uses_the_peer(monkeypatch) -> None:
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 0)
    assert _client_ip(_scope(_TRUSTED_PEER, "203.0.113.9")) == "127.0.0.1"


def test_port_and_ipv6_forms_normalize_to_one_bucket(monkeypatch) -> None:
    """A rotating source port (or a bracketed/odd IPv6 spelling) must not mint a fresh bucket."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    assert _client_ip(_scope(_TRUSTED_PEER, "203.0.113.7:41022")) == "203.0.113.7"
    assert _client_ip(_scope(_TRUSTED_PEER, "203.0.113.7:41999")) == "203.0.113.7"  # same bucket
    assert _client_ip(_scope(_TRUSTED_PEER, "[2001:db8::1]:41022")) == "2001:db8::1"
    assert _client_ip(_scope(_TRUSTED_PEER, "2001:0db8:0000::1")) == "2001:db8::1"  # canonicalized


def test_garbage_xff_entry_falls_back_to_peer(monkeypatch) -> None:
    """A non-IP string must never become a bucket key."""
    monkeypatch.setattr(settings, "http_rate_limit_trusted_proxy_hops", 1)
    assert _client_ip(_scope(_TRUSTED_PEER, "not-an-ip")) == "127.0.0.1"


def test_disabled_short_circuits(monkeypatch) -> None:
    """http_rate_limit_enabled=False bypasses the limiter entirely (operator kill switch)."""
    monkeypatch.setattr(settings, "http_rate_limit_enabled", False)
    monkeypatch.setattr(settings, "http_rate_limit_default_per_window", 1)
    client = TestClient(_app(_FakeCache()))
    for _ in range(5):
        assert client.get("/api/v1/whatever").status_code == 200
