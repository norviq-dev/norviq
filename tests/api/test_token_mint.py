# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The in-pod token minter emits a valid short-lived admin session token, and only the token."""

from __future__ import annotations

import asyncio

from norviq.api import auth, token_mint


def test_mint_admin_token_is_accepted_by_auth() -> None:
    tok = token_mint.mint_admin_token(ttl_seconds=3600)
    claims = asyncio.run(auth.decode_token(tok))
    assert claims.get("role") == "admin"
    assert claims.get("namespace") == "*"
    assert claims.get("sub") == "cli-admin"


def test_mint_viewer_token_is_scoped() -> None:
    tok = token_mint.mint_admin_token(ttl_seconds=600, role="viewer")
    claims = asyncio.run(auth.decode_token(tok))
    assert claims.get("role") == "viewer"
    assert claims.get("namespace") == ""


def test_main_prints_only_the_token(capsys) -> None:
    rc = token_mint.main(["--ttl", "600"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    # exactly one line, three dot-separated JWT segments, nothing else (no key, no banner).
    assert "\n" not in out
    assert out.count(".") == 2
