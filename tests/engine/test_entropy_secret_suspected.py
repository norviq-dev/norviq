# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-004: a bare credential VALUE is flagged, and flagged as its own advisory class.

The AWS access-key id (`AKIA…`) is caught by shape. The 40-character secret access-key value
(`wJalr…`) has no shape and matched nothing — and it is the half that actually signs requests.

The separation is the design, not an implementation detail. A high-entropy 40-character string is a
credential, a SHA-256 digest, a JWT segment, a git commit or a session id, and nothing in the bytes
distinguishes them. Folding this into `secret` would have been one line and would make
`llm02_data_leakage` fire on every commit hash in a payload — destroying the 0-false-positive
property everything else in the detector is built on.
"""

from __future__ import annotations

import pytest

from norviq.engine.entropy import looks_like_secret_value, shannon_entropy
from norviq.engine.evaluator import OPAEvaluator


def _classes(params: dict) -> list[str]:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    return ev._data_classes(params, [v for v in params.values() if isinstance(v, str)])


@pytest.mark.parametrize(
    "value",
    [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",   # the AWS secret access key from the finding
        "xoxb-2FaKe9Token8ForTesting1234567890abcd",
        "AIzaSyD3fAkE1KeyForTesting9876543210xyzAb",
    ],
)
def test_bare_credential_values_are_flagged(value):
    assert looks_like_secret_value(value), value


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("sha-256 digest", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"),
        ("url", "https://cdn.example.com/a/b/c/asset.png"),
        ("path", "/var/lib/docker/overlay2/abcdef0123456789"),
        ("prose", "the quick brown fox jumps over the lazy dog"),
        ("digits", "0123456789012345678901234567890123456789"),
        ("lowercase slug", "abcdefghijklmnopqrstuvwxyzabcdefghij"),
        ("short id", "ORD-002"),
        ("hex-ish id", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"),
    ],
)
def test_high_entropy_non_secrets_are_not_flagged(label, value):
    """Precision here comes from EXCLUDING known-benign shapes, not from the entropy threshold — a
    digest and a secret have the same entropy, so no score can separate them."""
    assert not looks_like_secret_value(value), label


def test_it_is_reported_as_a_distinct_class():
    assert _classes({"body": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}) == ["secret_suspected"]


def test_a_real_secret_still_reports_as_secret():
    """The advisory class must not displace the precise one — `AKIA…` is a shape match, not a guess."""
    assert _classes({"body": "AKIAIOSFODNN7EXAMPLE"}) == ["secret"]


def test_the_advisory_class_does_not_fire_when_a_real_secret_was_found():
    """No point flagging a maybe beside a certainty; it would just make the audit row noisier."""
    got = _classes({"a": "AKIAIOSFODNN7EXAMPLE", "b": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
    assert got == ["secret"]


def test_the_zero_false_positive_corpus_is_untouched():
    """The benign corpus from the F-032 battery must produce NOTHING, advisory class included."""
    for benign in [
        "ORD-002", "2026-08-11", "550e8400-e29b-41d4-a716-446655440000",
        "please refund the customer, order 12345", "version 1.2.3 build 4567",
        "call me on 555 0134", "#a1b2c3",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]:
        assert _classes({"body": benign}) == [], benign


def test_entropy_is_actually_measured():
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 4.2
