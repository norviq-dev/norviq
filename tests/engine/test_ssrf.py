# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-006: SSRF-to-metadata is a baseline floor, and the encodings are the whole attack.

The stock baseline allowed `http_fetch` to `169.254.169.254/latest/meta-data/`. One such call returns
the node's role credentials, at which point every policy written above it is moot — which is why this
is a floor rather than a per-agent rule.

The precision half is asserted just as hard, and the RFC1918 case is the one that matters: an agent in
Kubernetes talks to in-cluster services on 10.x constantly. Blocking that would be the
`sensitive_keys`-holds-`token` over-block all over again, so `private` is published for a customer
rule and deliberately left out of the block.
"""

from __future__ import annotations

import pytest

from norviq.engine.ssrf import classify_host, classify_hosts


@pytest.mark.parametrize(
    ("label", "host"),
    [
        ("aws/gcp/azure imds", "169.254.169.254"),
        ("ecs task credentials", "169.254.170.2"),
        ("alibaba imds", "100.100.100.200"),
        ("gcp by name", "metadata.google.internal"),
        ("gcp subdomain", "x.metadata.google.internal"),
        ("link-local generally", "169.254.1.1"),
    ],
)
def test_metadata_endpoints_are_classified(label, host):
    assert classify_host(host) == "metadata", label


@pytest.mark.parametrize(
    ("label", "host"),
    [
        ("dotted quad", "127.0.0.1"),
        ("decimal", "2130706433"),
        ("hex", "0x7f000001"),
        ("octal", "017700000001"),
        ("short dotted", "127.1"),
        ("ipv6", "::1"),
        ("bracketed ipv6", "[::1]"),
        ("ipv4-mapped ipv6", "::ffff:127.0.0.1"),
        ("by name", "localhost"),
        ("rfc6761 subdomain", "api.localhost"),
        ("trailing dot", "127.0.0.1."),
    ],
)
def test_every_loopback_spelling_is_classified(label, host):
    """A filter stricter than the HTTP client it protects does not see the request that gets made."""
    assert classify_host(host) == "loopback", label


@pytest.mark.parametrize("host", ["10.0.0.5", "172.16.3.9", "192.168.1.1"])
def test_rfc1918_is_classified_but_as_private(host):
    assert classify_host(host) == "private"


@pytest.mark.parametrize(
    "host",
    [
        "api.acme.com",
        "metadata.acme.com",          # substring match would have flagged this
        "my-metadata-service.io",
        "localhost.acme.com",         # NOT under .localhost
        "8.8.8.8",
        "1.1.1.1",
        "github.com",
        "",
    ],
)
def test_public_and_lookalike_hosts_are_not_flagged(host):
    assert classify_host(host) is None, host


def test_classify_hosts_groups_and_drops_empties():
    got = classify_hosts(["169.254.169.254", "127.0.0.1", "api.acme.com", "10.0.0.5"])
    assert got == {
        "loopback": ["127.0.0.1"],
        "metadata": ["169.254.169.254"],
        "private": ["10.0.0.5"],
    }
    assert classify_hosts(["api.acme.com"]) == {}


def test_the_derived_fact_reaches_the_input_document():
    """The preset reads `derived.destinations.internal`; if the key moves, the floor silently lifts."""
    from norviq.engine.evaluator import OPAEvaluator

    ev = OPAEvaluator.__new__(OPAEvaluator)
    url = "http://169.254.169.254/latest/meta-data/"
    dests = ev._destinations([url], ev._destination_keyed_hosts({"url": url}))
    assert dests["internal"] == {"metadata": ["169.254.169.254"]}
    benign = ev._destinations(["https://api.acme.com/v1"], frozenset())
    assert benign["internal"] == {}
