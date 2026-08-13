# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Classify a destination host as cloud-metadata / loopback / private (F-006).

## What this is for

The stock baseline evaluated `http_fetch` to `169.254.169.254/latest/meta-data/` as `allow`, along
with `metadata.google.internal`, `127.0.0.1` and decimal-encoded loopback. SSRF-to-IMDS is a
credential-theft primitive, not a per-agent business rule: one allowed fetch returns the node's role
credentials, and every policy written above that point is then moot.

## Why this is Python and not more Rego

Two reasons, both concrete.

The alternate encodings are the whole game and a regex is the wrong tool for them. `2130706433`,
`0x7f000001`, `017700000001`, `127.1` and `[::ffff:127.0.0.1]` are all loopback, and a pattern that
tries to enumerate those spellings will miss one. `ipaddress` already decides this correctly, so the
job here is to feed it every spelling the URL grammar allows and let it answer.

And the preset is at 24 of the API validator's 25 regex ops, so a Rego-side implementation could not
have afforded a single `regex.match` anyway. The engine publishes a fact; the policy reads it. Same
shape as the data-class wiring.

## The line this deliberately does NOT cross

RFC1918 is classified but is NOT part of the baseline block. An agent running in Kubernetes talks to
in-cluster services on 10.x/172.16-31.x constantly — that is ordinary traffic, not an attack, and a
baseline that refused it would be turned off within a day. That is the same lesson as the
`sensitive_keys`-holding-`token` over-block that turned 39 of 53 vendor tools into sinks.

So `private` is published for a customer who wants to write that rule, and only `metadata` and
`loopback` are wired to the baseline floor: fetching the IMDS endpoint or an agent's own localhost
admin port has no legitimate reason to appear in a tool call's arguments.
"""

from __future__ import annotations

import ipaddress
import socket

# Hostnames that resolve to a cloud instance-metadata service. Matched on the exact host or a parent
# suffix, never as a substring: `contains(host, "metadata")` would flag `metadata.acme.com`, an
# ordinary customer service name.
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",           # GCP
        "metadata.goog",                       # GCP (short form)
        "instance-data",                       # AWS (legacy hostname)
        "metadata.azure.com",
        "metadata.packet.net",
        "metadata.platformequinix.com",
    }
)

# Addresses that ARE the metadata service. 169.254.169.254 is AWS/GCP/Azure/DO/Oracle; 169.254.170.2
# is the ECS task-credential endpoint, which hands out task role credentials and is missed by anyone
# who only blocks the well-known one; fd00:ec2::254 is the AWS IPv6 form.
_METADATA_ADDRS = frozenset({"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"})


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse `host` as an IP in any spelling a URL may carry, or None if it is a name.

    `ipaddress` accepts the dotted-quad and IPv6 forms directly. The bare-integer, hex and octal
    spellings are what an SSRF filter is usually caught out by, so they are converted explicitly:
    `http://2130706433/` is `127.0.0.1`, and a browser or requests-style client will happily go there.
    """
    h = host.strip().strip("[]").rstrip(".")
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Bare integer / hex / octal — `int(x, 0)` reads 0x and 0o prefixes, and a leading-zero octal
    # (`017700000001`) is handled explicitly because Python 3 rejects it in base 0.
    try:
        if h.startswith(("0x", "0X")):
            value = int(h, 16)
        elif h.startswith("0o", 0) or (h.startswith("0") and len(h) > 1 and h[1:].isdigit()):
            value = int(h.lstrip("0") or "0", 8)
        elif h.isdigit():
            value = int(h, 10)
        else:
            # NOT a return: the short dotted forms below still have to be tried. An earlier draft
            # returned here and `127.1` came back unclassified — the one spelling most likely to be
            # typed by hand.
            value = -1
        if 0 <= value <= 0xFFFFFFFF:
            return ipaddress.ip_address(value)
    except ValueError:
        pass
    # Short dotted forms: `127.1` is 127.0.0.1 and `10.1` is 10.0.0.1. `ipaddress` rejects both —
    # correctly, since they are not valid presentation addresses — but `inet_aton` accepts them and so
    # does every C-backed HTTP client, which is what actually resolves the URL. Matching the resolver
    # rather than the spec is the point: an SSRF filter that is stricter than the client it protects
    # simply does not see the request that gets made.
    try:
        return ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(h)))
    except (OSError, ValueError):
        return None


def classify_host(host: str) -> str | None:
    """`metadata` | `loopback` | `private` | None, for one destination host.

    Ordered most-specific first: the metadata addresses are inside link-local, and reporting one of
    them as merely `private` would put an IMDS fetch in the category this module deliberately does not
    block.
    """
    if not host or not isinstance(host, str):
        return None
    h = host.strip().lower().rstrip(".")
    if h in _METADATA_HOSTS or any(h.endswith("." + m) for m in _METADATA_HOSTS):
        return "metadata"
    # Loopback by NAME, which no amount of IP parsing reaches. `http://localhost:8080/admin` is the
    # ordinary way to write an SSRF at the agent's own sidecar or admin port, and RFC 6761 reserves
    # `localhost` and everything under `.localhost` to resolve to loopback.
    if h == "localhost" or h.endswith(".localhost") or h == "localhost.localdomain":
        return "loopback"
    ip = _as_ip(h)
    if ip is None:
        return None
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged as the IPv4 it carries.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if str(ip) in _METADATA_ADDRS:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        # The rest of 169.254/16 is not the metadata service, but a tool call has no business
        # reaching it either, and it is where the cloud providers put their variants.
        return "metadata"
    if ip.is_private or ip.is_reserved or ip.is_unspecified:
        return "private"
    return None


def classify_hosts(hosts: list[str]) -> dict[str, list[str]]:
    """Group hosts by class, dropping the empty groups.

    Returns e.g. `{"metadata": ["169.254.169.254"]}`. Sorted and de-duplicated so a policy can use set
    operations against it, matching how `destinations` is already published.
    """
    out: dict[str, set[str]] = {}
    for host in hosts:
        kind = classify_host(host)
        if kind:
            out.setdefault(kind, set()).add(host)
    return {k: sorted(v) for k, v in sorted(out.items())}
