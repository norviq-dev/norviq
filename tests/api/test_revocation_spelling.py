# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A logged-out token must stay logged out however it is spelled.

The denylist was keyed on SHA-256 of the raw string. An HS256 signature is 43 base64url characters
carrying 256 bits, so its last character has two spare low bits, and PyJWT before 2.14.0 accepted all
four values. Re-spelling that one character produced a token that missed the denylist and still
verified. These tests build the re-spellings directly, so they hold whichever PyJWT is installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

import jwt
import pytest

from norviq.api import session_revocation as sr

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _token(sub: str = "admin") -> str:
    return jwt.encode({"sub": sub, "exp": int(time.time()) + 600}, "k" * 48, algorithm="HS256")


def _respellings(tok: str) -> list[str]:
    head, payload, sig = tok.split(".")
    base = _ALPHA.index(sig[-1]) & ~0b11
    return [f"{head}.{payload}.{sig[:-1]}{_ALPHA[base + k]}" for k in range(4) if _ALPHA[base + k] != sig[-1]]


class _FakeCache:
    def __init__(self) -> None:
        self.store: dict[str, int] = {}

    async def revoke_token(self, h: str, ttl: int) -> None:
        self.store[h] = ttl

    async def is_token_revoked(self, h: str) -> bool:
        return h in self.store


@pytest.fixture(autouse=True)
def _clean_mirror():
    sr._mirror.clear()
    yield
    sr._mirror.clear()


def test_every_spelling_of_a_token_shares_one_key() -> None:
    tok = _token()
    variants = _respellings(tok)
    assert len(variants) == 3
    assert len({hashlib.sha256(v.encode()).hexdigest() for v in [tok, *variants]}) == 4  # the old key differed
    assert {sr.token_hash(v) for v in [tok, *variants]} == {sr.token_hash(tok)}


@pytest.mark.parametrize("use_cache", [False, True], ids=["mirror", "redis"])
def test_a_revoked_token_stays_revoked_when_respelled(use_cache: bool) -> None:
    cache = _FakeCache() if use_cache else None
    tok = _token()
    asyncio.run(sr.revoke(cache, tok, int(time.time()) + 600))
    if use_cache:
        sr._mirror.clear()  # prove the Redis path on its own
    for variant in _respellings(tok):
        assert asyncio.run(sr.is_revoked(cache, variant)), "a re-spelled revoked token was accepted"


def test_a_different_token_is_not_caught() -> None:
    asyncio.run(sr.revoke(None, _token("admin"), int(time.time()) + 600))
    assert not asyncio.run(sr.is_revoked(None, _token("someone-else")))


def test_a_token_revoked_under_the_old_key_stays_revoked() -> None:
    """Upgrade safety: 0.2.5 wrote sha256(raw). A token logged out before the upgrade must not come back."""
    cache = _FakeCache()
    tok = _token()
    cache.store[hashlib.sha256(tok.encode()).hexdigest()] = 600
    assert asyncio.run(sr.is_revoked(cache, tok))


def test_a_revocation_is_still_readable_by_the_old_key() -> None:
    """Rollback safety: a 0.2.5 replica checks sha256(raw); it must still see a revocation 0.2.6 wrote."""
    cache = _FakeCache()
    tok = _token()
    asyncio.run(sr.revoke(cache, tok, int(time.time()) + 600))
    assert hashlib.sha256(tok.encode()).hexdigest() in cache.store


def test_a_non_jwt_credential_keeps_working() -> None:
    key = "nrvq_sk_not-a-jwt"
    asyncio.run(sr.revoke(None, key, int(time.time()) + 600))
    assert asyncio.run(sr.is_revoked(None, key))
    assert sr.token_hash(key) == hashlib.sha256(key.encode()).hexdigest()
