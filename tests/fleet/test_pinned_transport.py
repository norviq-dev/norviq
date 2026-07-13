# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SSRF-02 (CRITICAL, DNS-rebind) regression: `ssrf_guard.assert_safe_url_async` only validates the
addresses a hostname resolves to AT VALIDATION TIME. Handing the raw hostname to `httpx` afterward lets
httpx re-resolve INDEPENDENTLY at connect time — a rebinding DNS server can answer the first (guard)
lookup with a public/allowed address and a SECOND (dial-time) lookup with a blocked address
(169.254.169.254/an internal service) for the exact same hostname, so the guard's decision never applies
to the actual connection. `pinned_transport.resolve_and_pin` closes this by resolving once and hardcoding
the outbound TCP target to that one validated IP.

These tests simulate a rebind by making `socket.getaddrinfo` return a different address on the second
call than on the first — proving the connect target is the FIRST (validated) address, never a later
one, and that the dial issues exactly one resolution total."""

from __future__ import annotations

import http.server
import socket
import threading

import httpx
import pytest

from norviq.fleet import pinned_transport, ssrf_guard
from norviq.fleet.pinned_transport import resolve_and_pin
from norviq.fleet.ssrf_guard import SSRFBlockedError


class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Seen-Host", self.headers.get("Host") or "")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # silence stdout noise
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    thread.join(timeout=2)


async def test_pinned_dial_uses_first_validated_ip_never_a_later_resolution(monkeypatch, local_server) -> None:
    """The guard resolves once (call #1 -> the real local server's IP); a rebind attacker would answer
    any SECOND lookup with a different, unroutable address (#2 -> 240.0.0.1, IANA reserved). If the
    outbound dial re-resolved the hostname (the pre-fix bug), it would connect to the rebind address and
    this request would fail/hang. It must instead succeed against the FIRST validated IP, and
    getaddrinfo must be invoked exactly once total (guard-time only — no re-resolution at connect)."""
    port = local_server
    calls = {"n": 0}

    def fake_getaddrinfo(host, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("240.0.0.1", 0))]  # rebind target, unroutable

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    # Loopback is normally blocked by the guard; allow it through here so the test can point at a real
    # local server without needing a routable public IP (the blocklist logic itself is covered by
    # test_ssrf_guard.py — this test is only about the resolve-once/pin behavior).
    monkeypatch.setattr(ssrf_guard, "_is_blocked_ip", lambda ip: False)
    monkeypatch.setattr(pinned_transport, "_is_blocked_ip", lambda ip: False)

    pinned_ip, transport = await resolve_and_pin(f"http://rebind.example.test:{port}/x", context="test")
    assert pinned_ip == "127.0.0.1"
    assert calls["n"] == 1  # exactly one resolution at guard time

    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        resp = await client.get(f"http://rebind.example.test:{port}/hello")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # The Host header sent to the server is still the ORIGINAL hostname (SNI/virtual-hosting parity),
    # even though the socket connected to 127.0.0.1, not to whatever "rebind.example.test" would resolve to.
    assert resp.headers.get("X-Seen-Host") == f"rebind.example.test:{port}"
    # Still exactly one resolution overall — proves the transport dialed the PINNED ip without
    # triggering httpx's own independent DNS lookup.
    assert calls["n"] == 1


async def test_resolve_and_pin_rejects_unroutable_host_before_any_dial() -> None:
    """A host that fails the guard outright (e.g. resolves to a blocked address) must raise before a
    transport is ever built — no pinned dial for a URL that never passed validation."""
    with pytest.raises(SSRFBlockedError):
        await resolve_and_pin("http://169.254.169.254/latest/meta-data/", context="test")


async def test_resolve_and_pin_defense_in_depth_rejects_a_blocked_pinned_ip(monkeypatch) -> None:
    """Defense in depth: even if `assert_safe_url_async` were to (hypothetically, via a future
    regression) return a blocked address, `resolve_and_pin` independently re-asserts publicness before
    building the pinned transport, rather than trusting the upstream result blindly."""

    async def fake_assert_safe_url_async(url, *, context):
        return ["169.254.169.254"]

    monkeypatch.setattr(pinned_transport, "assert_safe_url_async", fake_assert_safe_url_async)
    with pytest.raises(SSRFBlockedError, match="re-assertion"):
        await resolve_and_pin("http://whatever.example/", context="test")


async def test_pinned_transport_connect_target_matches_validated_address(monkeypatch, local_server) -> None:
    """Direct proof the httpx transport's socket target equals the validated address: patch the pinned
    backend's connect_tcp to record what host it was asked to dial, and confirm it is exactly the
    guard-validated IP, not the request's hostname."""
    port = local_server
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
    monkeypatch.setattr(ssrf_guard, "_is_blocked_ip", lambda ip: False)
    monkeypatch.setattr(pinned_transport, "_is_blocked_ip", lambda ip: False)

    pinned_ip, transport = await resolve_and_pin(f"http://another-fake-host.test:{port}/", context="test")
    backend = transport._pool._network_backend  # noqa: SLF001 - white-box assertion on the pin itself
    assert backend._pinned_ip == pinned_ip == "127.0.0.1"

    # `backend.connect_tcp` receives whatever (untrusted) hostname httpcore's connection asks for — that
    # is expected input, not proof of what actually got dialed. Spy one level deeper, on the INNER
    # backend that `_PinnedNetworkBackend` delegates the real socket connect to, to see the address that
    # was actually used on the wire.
    seen = {}
    real_inner_connect_tcp = backend._backend.connect_tcp  # noqa: SLF001 - white-box assertion

    async def spy_inner_connect_tcp(host, *args, **kwargs):
        seen["host"] = host
        return await real_inner_connect_tcp(host, *args, **kwargs)

    monkeypatch.setattr(backend._backend, "connect_tcp", spy_inner_connect_tcp)  # noqa: SLF001

    async with httpx.AsyncClient(transport=transport, timeout=5.0) as client:
        resp = await client.get(f"http://another-fake-host.test:{port}/hello")
    assert resp.status_code == 200
    assert seen["host"] == "127.0.0.1"  # the pinned backend dialed the validated IP, not the hostname
