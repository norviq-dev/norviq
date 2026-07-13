# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Signed bundle core (F045 P2 S1): the trust-root signature verification. The most security-critical unit
tests — a regression here would let a compromised hub or MITM inject an allow-all policy."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from norviq.fleet.bundle import (
    BundleVerifyError,
    canonical_bytes,
    parse_rfc3339,
    rfc3339_z,
    sign_bundle,
    verify_bundle,
)


def _gen_rsa_pem() -> str:
    try:
        import rsa as rsalib

        _, priv = rsalib.newkeys(2048)
        return priv.save_pkcs1().decode()
    except Exception:  # pragma: no cover
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa as crsa

        key = crsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()


def _pub(priv_pem: str) -> str:
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _bundle() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "cluster_id": "cluster-a",
        "bundle_version": 42,
        "issued_at": rfc3339_z(now),
        "not_before": rfc3339_z(now - timedelta(minutes=1)),
        "expires_at": rfc3339_z(now + timedelta(minutes=15)),
        "prev_bundle_version": 41,
        "policies": [
            {"namespace": "payments", "agent_class": "checkout", "rego_source": "package x", "priority": 100,
             "enforcement_mode": "block", "version": 7},
        ],
    }


def test_round_trip_verifies() -> None:
    priv = _gen_rsa_pem()
    body = sign_bundle(_bundle(), priv)
    out = verify_bundle(body, _pub(priv))
    assert out["bundle_version"] == 42 and out["policies"][0]["agent_class"] == "checkout"


def test_canonicalization_is_stable_and_z_only() -> None:
    # The +00:00 vs Z hazard: parse round-trips, and policies order-independent canonical bytes match.
    b1 = _bundle()
    b2 = copy.deepcopy(b1)
    b2["policies"] = list(reversed(b2["policies"])) + []  # different list order, same content
    assert canonical_bytes(b1) == canonical_bytes(b2)
    assert b1["issued_at"].endswith("Z") and "+00:00" not in b1["issued_at"]
    assert parse_rfc3339(b1["issued_at"]).tzinfo is timezone.utc


def test_tampered_payload_rejected() -> None:
    # Attacker swaps the rego to allow-all but keeps the old (valid) signature -> reject.
    priv = _gen_rsa_pem()
    body = sign_bundle(_bundle(), priv)
    body["payload"]["policies"][0]["rego_source"] = 'package x\ndefault decision = "allow"'
    with pytest.raises(BundleVerifyError):
        verify_bundle(body, _pub(priv))


def test_wrong_key_rejected() -> None:
    body = sign_bundle(_bundle(), _gen_rsa_pem())
    with pytest.raises(BundleVerifyError):
        verify_bundle(body, _pub(_gen_rsa_pem()))  # a DIFFERENT trust root


def test_unsigned_rejected() -> None:
    body = {"payload": _bundle()}  # no jws
    with pytest.raises(BundleVerifyError):
        verify_bundle(body, _pub(_gen_rsa_pem()))


def test_empty_pubkey_fails_closed() -> None:
    body = sign_bundle(_bundle(), _gen_rsa_pem())
    with pytest.raises(BundleVerifyError):
        verify_bundle(body, "")  # a spoke with no configured trust root must NEVER apply
