# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Reset a local-login user's password FROM inside the api pod — a NO-EGRESS admin recovery path.

Runs INSIDE the api pod (which holds the DB connection), invoked by the ``norviq admin reset-password``
CLI via ``kubectl exec``. There is NO email / SMTP / outbound network: the operator already has cluster
access (kubectl), so the recovery is a direct, authenticated, in-cluster reset. It sets a fresh one-time
password (or an operator-supplied one), flags ``must_change=True`` so the next login forces a change, and
prints ONLY the new password to stdout so the CLI can capture it cleanly. The signing key / existing hash
never leave the pod; nothing is logged in the clear.

Usage (in-pod):
    python -m norviq.api.admin_reset [--username admin] [--password <pw>]
With no --password a strong random one-time password is generated and printed.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

from sqlalchemy import select

from norviq.api.db.models import User
from norviq.api.db.session import close_db, get_session, init_db
from norviq.api.passwords import hash_password
from norviq.config import settings

# Unambiguous alphabet for a one-time password an operator retypes once (no 0/O/1/l/I).
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def _one_time_password(n: int = 20) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


async def reset_password(username: str, new_password: str) -> None:
    """Set ``username``'s password hash to ``new_password`` and force a change on next login."""
    # Standalone process (not the app lifespan): initialize the DB engine before opening a session.
    await init_db()
    provider = get_session()
    session = await provider.__anext__()
    try:
        row = (await session.execute(select(User).where(User.username == username))).scalar_one_or_none()
        if row is None:
            print(f"error: no local user '{username}'", file=sys.stderr)
            raise SystemExit(2)
        row.password_hash = hash_password(new_password)
        row.must_change = True
        await session.commit()
    finally:
        await provider.aclose()
        await close_db()


def main() -> None:
    ap = argparse.ArgumentParser(prog="norviq.api.admin_reset", description="Reset a local-login user's password.")
    ap.add_argument("--username", default=settings.auth_admin_username, help="user to reset (default: the admin).")
    ap.add_argument("--password", default=None, help="new password; omit to generate a one-time one.")
    ap.add_argument("--to-default", action="store_true",
                    help="restore the documented DEFAULT password (must_change forces an immediate change).")
    args = ap.parse_args()

    if args.to_default:
        # The deliberate weak default (drives the forced first-login change + the 'default password in use'
        # banner). This is the documented frictionless recovery, so the >=min-length gate does not apply here.
        new_password = settings.auth_default_admin_password
    else:
        # Otherwise enforce the same minimum length the change-password path requires — never set a weak hash.
        new_password = args.password or _one_time_password(max(20, settings.auth_min_password_length))
        if len(new_password) < settings.auth_min_password_length:
            print(f"error: password must be at least {settings.auth_min_password_length} characters", file=sys.stderr)
            raise SystemExit(2)

    asyncio.run(reset_password(args.username, new_password))
    # ONLY the new password on stdout (nothing else) so the CLI captures it cleanly. Not logged.
    print(new_password)


if __name__ == "__main__":
    main()
