# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SSRF guard for any URL the hub or a spoke DIALS on a peer's say-so (a spoke-reported `endpoint`,
a spoke-reported `hub_url`, a join-token `hub_url`). Dependency-free (stdlib only: `ipaddress` +
`socket`) so it can be imported from `schemas.py` (pydantic validators) without adding a runtime dep.

Threat: a spoke self-reports its `endpoint`/`hub_url`; the hub later dials it — with a MINTED ADMIN
BEARER, in the audit drill-down case — so an attacker-controlled or internal-pointing value turns
into SSRF into the hub's own network AND exfiltrates a hub-valid admin token to whatever answers.
This guard must run at DIAL TIME (not just on write) because a hostname can be re-pointed (DNS
rebinding) between when it was stored and when it is dialed — resolving here, right before the
request, is the narrowest window practical without a dependency on a resolving HTTP transport.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}


class SSRFBlockedError(ValueError):
    """Raised when a URL is not a safe target for an outbound fleet request."""


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Reject anything that is not a routable, public unicast address.

    Covers (this is the rejection table `verify` checks against):
      - loopback:      127.0.0.0/8, ::1
      - link-local:     169.254.0.0/16 (INCLUDES the cloud metadata IP 169.254.169.254), fe80::/10
      - private:        10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7 (via ip.is_private)
      - unspecified:    0.0.0.0, ::
      - multicast / reserved (IANA "special-purpose" ranges, e.g. 240.0.0.0/4, 100.64.0.0/10 CGNAT)
    `is_private` alone already implies loopback/link-local for stdlib `ipaddress`, but the individual
    checks are kept explicit so the rejection reason (and this docstring) stays legible.
    """
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


def assert_safe_url(url: str, *, context: str = "outbound fleet request") -> None:
    """Raise `SSRFBlockedError` unless `url` is http(s) AND every address its host resolves to is a
    public, routable unicast address.

    Synchronous (blocking DNS via `socket.getaddrinfo`) — safe to call from a pydantic
    `field_validator` or any other sync context. Async callers (FastAPI route handlers) MUST use
    `assert_safe_url_async` instead so this does not block the event loop.
    """
    parsed = urlsplit((url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"{context}: scheme '{scheme or '(none)'}' is not http/https")
    host = parsed.hostname
    if not host:
        raise SSRFBlockedError(f"{context}: URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"{context}: could not resolve host '{host}': {exc}") from exc
    if not infos:
        raise SSRFBlockedError(f"{context}: host '{host}' resolved to no addresses")
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw_addr = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_addr)
        except ValueError as exc:
            raise SSRFBlockedError(
                f"{context}: host '{host}' resolved to an unparsable address '{raw_addr}'"
            ) from exc
        if _is_blocked_ip(ip):
            raise SSRFBlockedError(
                f"{context}: host '{host}' resolves to a blocked address {ip} "
                "(loopback/link-local incl. cloud metadata/private/unspecified/multicast/reserved)"
            )


async def assert_safe_url_async(url: str, *, context: str = "outbound fleet request") -> None:
    """Async wrapper: runs the (blocking) DNS resolution off the event loop via a worker thread — use
    this from FastAPI route handlers so a slow/hanging resolver can't stall the hot path."""
    await asyncio.to_thread(assert_safe_url, url, context=context)


def is_safe_url(url: str, *, context: str = "outbound fleet request") -> bool:
    """Boolean wrapper around `assert_safe_url` for call sites that want a bool, not an exception."""
    try:
        assert_safe_url(url, context=context)
    except SSRFBlockedError:
        return False
    return True
