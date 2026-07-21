# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Close the DNS-rebinding gap: `ssrf_guard.assert_safe_url_async` validates a URL's resolved
addresses, but a caller that then hands the raw hostname to `httpx` lets httpx RE-RESOLVE independently
at connect time. A DNS-rebinding attacker answers the guard's lookup with a public IP and answers
httpx's later, separate lookup with a blocked address (169.254.169.254 / an internal service) for the
SAME hostname — the guard passes, the connection goes somewhere it was never validated to go, and if the
caller attaches a bearer token (e.g. the minted admin token on the fleet drill-down dial) that token is
handed to whatever answered.

This module closes the resolve/connect gap: resolve the host ONCE (via `ssrf_guard`), then build an
httpx transport whose TCP connect target is HARDCODED to that already-validated IP. The original
hostname is still used for the HTTP `Host` header and the TLS SNI/certificate check (httpx sets `Host`
from the request URL regardless of transport; httpcore defaults TLS `server_hostname` to the
connection's origin hostname — see `httpcore/_async/connection.py::AsyncHTTPConnection._connect`) — only
the socket's destination address changes, so virtual hosting and cert validation keep working normally.

Deliberately kept SEPARATE from `ssrf_guard.py`, which is stdlib-only (no httpx import) so it stays safe
to import from `schemas.py` pydantic validators without adding a runtime dependency there.
"""

from __future__ import annotations

import ipaddress
import typing

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend

from norviq.fleet.ssrf_guard import SSRFBlockedError, _is_blocked_ip, assert_safe_url_async

if typing.TYPE_CHECKING:
    from httpcore._backends.base import SOCKET_OPTION


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """`httpcore.AsyncNetworkBackend` that dials `pinned_ip` no matter what host it is asked to connect
    to. `AsyncHTTPConnection._connect` (httpcore) passes the request origin's HOSTNAME to
    `connect_tcp` and would otherwise resolve it itself — that independent resolution is exactly the
    TOCTOU a DNS-rebinding attacker exploits. Swapping only `connect_tcp`'s target leaves everything
    else (TLS SNI/server_hostname default, HTTP Host header) keyed off the original hostname.
    """

    def __init__(self, pinned_ip: str) -> None:
        self._pinned_ip = pinned_ip
        self._backend = AutoBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable["SOCKET_OPTION"] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # `host` is the (untrusted / independently re-resolvable) origin hostname — ignored on purpose;
        # always dial the address `ssrf_guard` already validated.
        return await self._backend.connect_tcp(
            self._pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: typing.Iterable["SOCKET_OPTION"] | None = None
    ) -> httpcore.AsyncNetworkStream:  # pragma: no cover - fleet dials are always TCP http(s)
        raise NotImplementedError("pinned fleet transport does not support unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _build_pinned_transport(pinned_ip: str) -> httpx.AsyncHTTPTransport:
    """Build an `httpx.AsyncHTTPTransport` whose TCP connect target is hardcoded to `pinned_ip`.

    Constructed via the normal PUBLIC `httpx.AsyncHTTPTransport()` constructor (so cert/trust_env
    handling is identical to every other httpx client in this codebase), then the connection pool's
    network backend is swapped for `_PinnedNetworkBackend`. `httpx.AsyncHTTPTransport` does not expose
    `network_backend` as a public constructor argument, so this reaches into `transport._pool`, the one
    attribute `httpcore.AsyncConnectionPool.__init__` itself uses to store it (`self._network_backend =
    ...`) — stable across the httpcore 1.x series this project depends on. If that attribute is ever
    renamed upstream, FAIL LOUD rather than silently falling back to unpinned (re-resolving) dialing,
    which would silently reopen the rebind gap.
    """
    transport = httpx.AsyncHTTPTransport()
    pool = transport._pool  # noqa: SLF001 - see docstring: reaching into httpcore's own storage attr
    if not hasattr(pool, "_network_backend"):
        raise RuntimeError(
            "httpx/httpcore internals changed: AsyncConnectionPool no longer exposes _network_backend — "
            "the DNS-rebind pin can no longer be applied; refusing to fall back to unpinned dialing."
        )
    pool._network_backend = _PinnedNetworkBackend(pinned_ip)  # noqa: SLF001
    return transport


async def resolve_and_pin(url: str, *, context: str) -> tuple[str, httpx.AsyncHTTPTransport]:
    """Resolve `url`'s host ONCE via the SSRF guard and return `(pinned_ip, transport)`, where
    `transport` is an httpx transport hardcoded to dial `pinned_ip`. The caller then issues the request
    against the ORIGINAL `url` (unchanged hostname/Host header/TLS SNI) through this transport — httpx
    can no longer independently re-resolve the hostname at connect time.

    Raises `SSRFBlockedError` if the URL fails the guard, mirroring `assert_safe_url_async`.
    """
    validated_ips = await assert_safe_url_async(url, context=context)
    if not validated_ips:
        raise SSRFBlockedError(f"{context}: no validated address to pin to")
    pinned_ip = validated_ips[0]
    # Defense in depth: re-assert the chosen address is public right before it is dialed, independent
    # of whatever assert_safe_url_async's implementation does upstream (guards a future refactor there).
    try:
        ip_obj = ipaddress.ip_address(pinned_ip)
    except ValueError as exc:
        raise SSRFBlockedError(f"{context}: validated address '{pinned_ip}' is unparsable") from exc
    if _is_blocked_ip(ip_obj):
        raise SSRFBlockedError(f"{context}: pinned address {pinned_ip} failed the re-assertion")
    transport = _build_pinned_transport(pinned_ip)
    return pinned_ip, transport
