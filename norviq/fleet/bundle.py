# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Signed fleet policy bundle. THE single shared module imported by BOTH the hub (sign) and the
spoke (verify) so the canonical signed bytes are byte-identical on both sides — canonicalization drift is
the #1 way to silently break (or weaken) signature verification.

Trust model: the spoke's public key (NRVQ_FLEET_BUNDLE_PUBKEY) is the trust root. The hub builds + serves
bundles, but a spoke applies one ONLY if the RS256 JWS over the canonical bytes verifies against that key —
so a compromised hub process / MITM / malicious DB row cannot forge an "allow-all" without the private key.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from jwt import PyJWTError as JWSError
from jwt import api_jws as jws

# Scopes a bundle may NEVER carry, checked by the hub when a policy is authored and when a bundle is
# built, and again by the spoke before it applies one. Each is managed PER CLUSTER by its own path: the
# chart's baseline by the webhook controller, `__pack__*` by the packs API, `__controls__` by the
# baseline controls API, `__egress__` and `__mcp__` by their registries. Every one of them except
# `__baseline__` is also refused by POST /policies (policies._MANAGED_SCOPES, pinned by a test).
#
# `__controls__` matters most: a cluster's saved controls REPLACE its chart baseline, so a fleet push to
# that key could switch a spoke's baseline off. The hub reserved only __baseline__ and __pack__ and the
# spoke filtered nothing; measured on the resolver, a strict module with every control off, applied at
# that key beside a class policy that allows, took run_shell from block/deny_shell_execution to
# allow/class_allow.
RESERVED_SCOPES = frozenset({
    "__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__controls__", "__egress__", "__mcp__",
})


def rfc3339_z(dt: datetime) -> str:
    """One UTC formatter used everywhere (e.g. 2026-06-29T10:00:00Z) — NEVER mix `Z` and `+00:00`."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(value: str) -> datetime:
    """Parse the `...Z` UTC timestamps this module emits."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def canonical_bytes(payload: dict) -> bytes:
    """Deterministic canonical JSON bytes for signing/verifying. Frozen on BOTH sides:
    sorted keys, no whitespace, ensure_ascii=False, policies pre-ordered by (namespace, agent_class)."""
    normalized = dict(payload)
    policies = normalized.get("policies") or []
    normalized["policies"] = sorted(policies, key=lambda p: (p.get("namespace", ""), p.get("agent_class", "")))
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_bundle(payload: dict, signing_key_pem: str, kid: str = "fleet-bundle-1") -> dict:
    """Hub: sign the canonical bundle bytes (RS256) and return the wire body {payload, jws}."""
    token = jws.encode(canonical_bytes(payload), signing_key_pem, algorithm="RS256", headers={"kid": kid})
    return {"payload": payload, "jws": token}


class BundleVerifyError(Exception):
    """Raised when a bundle fails signature/integrity verification (fail-closed)."""


def verify_bundle(body: dict, pubkey_pem: str) -> dict:
    """Spoke: verify the JWS against the trust-root pubkey and return the SIGNED payload.

    Fail-closed: empty pubkey, missing/invalid signature, or a payload that does not match the signed bytes
    all raise BundleVerifyError. The caller MUST act on the returned (signed) payload, never the wire dict.
    """
    if not pubkey_pem:
        raise BundleVerifyError("no fleet bundle public key configured (fail-closed)")
    token = body.get("jws")
    if not token:
        raise BundleVerifyError("missing bundle signature")
    try:
        verified = jws.decode(token, pubkey_pem, algorithms=["RS256"])  # single-alg allowlist (alg-confusion-safe)
    except (JWSError, Exception) as exc:  # noqa: BLE001 - any verify failure is fail-closed
        raise BundleVerifyError(f"signature verify failed: {exc}") from exc
    # The signature covers `verified`; re-derive canonical bytes from the wire payload and require equality,
    # so a valid-but-stale signature cannot be paired with a swapped payload.
    wire_payload = body.get("payload") or {}
    if canonical_bytes(wire_payload) != verified:
        raise BundleVerifyError("payload does not match signed bytes")
    return json.loads(verified)
