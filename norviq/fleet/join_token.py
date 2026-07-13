# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fleet JOIN TOKEN (single-cluster-first enrollment). The hub MINTS a short-lived, scoped, HMAC-signed token that
carries everything a plain spoke needs to enroll — the hub endpoint, the spoke's cluster_id, and the bundle PUBLIC
key (the trust root). The token is signed with the shared service secret (api_secret_key) so the spoke can verify
it; the hub's PRIVATE signing key never leaves the hub. Replaces the per-spoke Helm `--set apiUrl/bundlePubkey`
hand-wiring with one `norviq fleet join <token>` action.

Security: short-lived (minutes), admin-minted, cluster-scoped, and single-use (the hub tracks the jti and rejects a
second claim). The carried pubkey is the trust root delivered *with* the signed token, not blindly fetched."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

_TYP = "nrvq-join"
_VERSION = 1


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def derive_bundle_pubkey(signing_key_pem: str) -> str:
    """Derive the RS256 PUBLIC key PEM (the bundle trust root) from the hub's PRIVATE signing key PEM."""
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(signing_key_pem.encode(), password=None)
    # SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----") — the same PEM format jose's
    # `RSAKey(...).public_key().to_pem()` (default pem_format="PKCS8") produced.
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def mint_join_token(
    *, secret: str, hub_url: str, cluster_id: str, bundle_pubkey: str, ttl_s: int = 600,
    cluster_name: str = "", cluster_region: str = "", labels: dict | None = None,
) -> tuple[str, dict]:
    """Mint a signed join token. Returns (token, payload). The payload's `jti` is what the hub tracks for single-use."""
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "v": _VERSION, "typ": _TYP, "jti": str(uuid.uuid4()),
        "hub": hub_url, "cid": cluster_id, "pub": bundle_pubkey,
        "name": cluster_name, "region": cluster_region, "labels": labels or {},
        "iat": now, "exp": now + int(ttl_s),
    }
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}", payload


def verify_join_token(token: str, secret: str) -> dict:
    """Verify signature + type + expiry; return the payload. Raises ValueError on any failure (fail-closed)."""
    try:
        body, sig = token.strip().split(".", 1)
    except ValueError as exc:
        raise ValueError("malformed join token") from exc
    expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise ValueError("join token signature invalid")
    payload = json.loads(_unb64(body))
    if payload.get("typ") != _TYP or payload.get("v") != _VERSION:
        raise ValueError("not a Norviq join token")
    if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
        raise ValueError("join token expired")
    for k in ("hub", "cid", "pub", "jti"):
        if not payload.get(k):
            raise ValueError(f"join token missing {k}")
    return payload
