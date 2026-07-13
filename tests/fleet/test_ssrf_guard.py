# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SSRF-01 (CRITICAL): the guard the hub/spoke must run before dialing ANY peer-reported URL
(a spoke's self-reported `endpoint`, a join token's `hub_url`) — a spoke self-reports `endpoint`,
the hub later dials it with a minted ADMIN bearer (drill-down), so an unguarded URL is SSRF + an
admin-token-exfil chain. Every case here uses an IP literal (or `localhost`, which every platform
resolves via /etc/hosts) so the test never depends on real DNS/network access."""

from __future__ import annotations

import pytest

from norviq.fleet.ssrf_guard import SSRFBlockedError, assert_safe_url, assert_safe_url_async, is_safe_url

# The rejection table: cloud metadata, loopback (v4/v6/hostname), RFC1918 private (all three blocks),
# link-local, unspecified, multicast, a non-http(s) scheme, and a URL with no host at all.
_BLOCKED = [
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata (link-local)
    "http://169.254.1.1",                          # link-local, non-metadata address
    "http://localhost:8080",                       # loopback via hostname
    "http://127.0.0.1",                             # loopback v4
    "http://[::1]:8080",                            # loopback v6
    "http://10.1.2.3",                              # RFC1918 10/8
    "http://172.16.0.5",                            # RFC1918 172.16/12
    "http://192.168.1.5",                           # RFC1918 192.168/16
    "http://0.0.0.0",                                # unspecified
    "http://224.0.0.1",                              # multicast
    "ftp://8.8.8.8",                                 # disallowed scheme
    "javascript:alert(1)",                           # disallowed scheme, no host
    "not-a-url",                                     # no scheme, no host
    "",                                              # empty
]

# Public IP literals — getaddrinfo() parses a numeric literal locally (no DNS query), so this stays
# network-independent while still exercising the "allowed" path end-to-end.
_ALLOWED = [
    "http://8.8.8.8",
    "https://1.1.1.1:8443/api/v1/audit/records",
]


@pytest.mark.parametrize("url", _BLOCKED)
def test_blocked_hosts_are_rejected(url: str) -> None:
    with pytest.raises(SSRFBlockedError):
        assert_safe_url(url, context="test")
    assert is_safe_url(url) is False


@pytest.mark.parametrize("url", _ALLOWED)
def test_public_hosts_are_allowed(url: str) -> None:
    assert_safe_url(url, context="test")  # must not raise
    assert is_safe_url(url) is True


@pytest.mark.asyncio
async def test_async_wrapper_blocks_same_as_sync() -> None:
    with pytest.raises(SSRFBlockedError):
        await assert_safe_url_async("http://169.254.169.254/", context="test")
    await assert_safe_url_async("http://8.8.8.8", context="test")  # must not raise


def test_unresolvable_host_is_rejected() -> None:
    # A hostname that fails DNS resolution entirely must be rejected, not silently allowed through.
    with pytest.raises(SSRFBlockedError):
        assert_safe_url("http://this-host-does-not-exist.invalid.", context="test")


def test_heartbeat_endpoint_rejects_non_http_scheme() -> None:
    # SSRF-01: the write-time shape check on HeartbeatBody.endpoint mirrors console_url's pattern —
    # blank (don't 422) anything not http(s). The full host-range reject (this module's job) runs at
    # DIAL TIME, not here — a pydantic validator must not do blocking DNS I/O on the request hot path.
    from norviq.fleet.schemas import HeartbeatBody

    assert HeartbeatBody(endpoint="javascript:alert(1)").endpoint == ""
    assert HeartbeatBody(endpoint="file:///etc/passwd").endpoint == ""
    assert HeartbeatBody(endpoint="  gopher://x  ").endpoint == ""
    assert HeartbeatBody(endpoint="").endpoint == ""
    # http(s) shapes are preserved here — even a private/metadata host, since THIS check is scheme-only;
    # ssrf_guard.assert_safe_url_async is what rejects those, at dial time (see test_fleet_policy_drilldown_ssrf.py).
    assert HeartbeatBody(endpoint="https://spoke.example:8443").endpoint == "https://spoke.example:8443"
    assert HeartbeatBody(endpoint="http://169.254.169.254").endpoint == "http://169.254.169.254"
