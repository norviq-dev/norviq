# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Join-token security: a spoke must only accept a token that is correctly signed by the shared service secret,
unexpired, the right type, and complete. Tamper / expiry / wrong-secret / wrong-type all fail closed."""

from __future__ import annotations

import time

import pytest

from norviq.fleet.join_token import mint_join_token, verify_join_token

_SECRET = "shared-service-secret"
_KW = dict(secret=_SECRET, hub_url="http://hub:8080", cluster_id="fleet-z", bundle_pubkey="-----PUB-----")


def test_mint_verify_roundtrip() -> None:
    token, payload = mint_join_token(**_KW)
    out = verify_join_token(token, _SECRET)
    assert out["cid"] == "fleet-z" and out["hub"] == "http://hub:8080" and out["pub"] == "-----PUB-----"
    assert out["jti"] == payload["jti"]


def test_tampered_payload_rejected() -> None:
    token, _ = mint_join_token(**_KW)
    body, sig = token.split(".", 1)
    # flip a character in the signed body -> signature no longer matches
    bad = (body[:-1] + ("A" if body[-1] != "A" else "B")) + "." + sig
    with pytest.raises(ValueError, match="signature"):
        verify_join_token(bad, _SECRET)


def test_wrong_secret_rejected() -> None:
    token, _ = mint_join_token(**_KW)
    with pytest.raises(ValueError, match="signature"):
        verify_join_token(token, "a-different-secret")


def test_expired_token_rejected() -> None:
    token, _ = mint_join_token(**_KW, ttl_s=-1)  # already expired
    with pytest.raises(ValueError, match="expired"):
        verify_join_token(token, _SECRET)


def test_short_ttl_then_expiry(monkeypatch) -> None:
    token, payload = mint_join_token(**_KW, ttl_s=1)
    assert verify_join_token(token, _SECRET)["exp"] == payload["exp"]
    # fast-forward past expiry
    real = time.time
    monkeypatch.setattr("norviq.fleet.join_token.datetime", __import__("datetime").datetime)
    later = payload["exp"] + 5

    class _DT(__import__("datetime").datetime):
        @classmethod
        def now(cls, tz=None):
            return __import__("datetime").datetime.fromtimestamp(later, tz=tz)

    monkeypatch.setattr("norviq.fleet.join_token.datetime", _DT)
    with pytest.raises(ValueError, match="expired"):
        verify_join_token(token, _SECRET)
    _ = real


def test_malformed_rejected() -> None:
    with pytest.raises(ValueError):
        verify_join_token("not-a-token", _SECRET)
