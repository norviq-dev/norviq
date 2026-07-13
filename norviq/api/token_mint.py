# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LOGIN-2: mint a short-lived admin session token FROM the in-cluster secret.

Runs INSIDE the api pod (which holds ``NRVQ_API_SECRET_KEY`` in its environment), invoked by the
``norviq login`` CLI via ``kubectl exec`` — so an operator gets a first-login token WITHOUT ever seeing
the signing key and WITHOUT hand-crafting a JWT. Prints ONLY the token to stdout (nothing else), so the
CLI can capture it cleanly. This is the legacy-HS256 human-login path; it is deliberately separate from
the workload service token the webhook mints for injected sidecars (SIDE-2).
"""

from __future__ import annotations

import argparse
import sys
import time

import jwt

from norviq.config import settings


def mint_admin_token(ttl_seconds: int = 3600, sub: str = "cli-admin", role: str = "admin") -> str:
    """Return a signed short-lived token for first-login. Admin => any namespace ('*')."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        # Admin is namespace-agnostic; '*' matches every tenant (see auth.scoped_namespace).
        "namespace": "*" if role == "admin" else "",
        "iat": now,
        "exp": now + max(60, int(ttl_seconds)),
    }
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def mint_session_token(
    *, sub: str, role: str, namespace: str, must_change: bool = False, ttl_seconds: int = 3600
) -> str:
    """LOGIN-2: sign a short-lived HS256 session token for a username/password login.

    Same signer/shape as ``mint_admin_token`` (so every existing consumer validates it identically),
    plus a ``must_change`` claim carrying the force-password-change state the console gates on.
    """
    now = int(time.time())
    claims = {
        "sub": sub,
        "role": role,
        "namespace": namespace,
        "must_change": bool(must_change),
        "iat": now,
        "exp": now + max(60, int(ttl_seconds)),
    }
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def main(argv: list[str] | None = None) -> int:
    """CLI entry: print ONLY the minted token to stdout."""
    parser = argparse.ArgumentParser(description="Mint a short-lived Norviq admin session token (in-pod).")
    parser.add_argument("--ttl", type=int, default=3600, help="token lifetime in seconds (default 3600)")
    parser.add_argument("--role", default="admin", choices=["admin", "viewer"], help="role claim (default admin)")
    parser.add_argument("--sub", default="cli-admin", help="subject claim (default cli-admin)")
    args = parser.parse_args(argv)
    # stdout carries ONLY the token; keep the signing key off stdout/stderr entirely.
    sys.stdout.write(mint_admin_token(ttl_seconds=args.ttl, sub=args.sub, role=args.role))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
