# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OIDC dual-mode auth: RS256 validation against a SYNTHETIC in-process JWKS.

No live IdP: a test-generated RSA keypair signs tokens and its public JWK is served via a stubbed
JWKS client. Covers the good path, group->role/namespace mapping, claim rejections (iss/aud/exp/kid),
the alg-confusion downgrade, and that legacy HS256 still works while migration is on.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import httpx
import jwt
import pytest
from fastapi.security import HTTPAuthorizationCredentials
from jwt import PyJWTError as JWTError

from norviq.api import auth as auth_mod
from norviq.api.jwks import JwksClient
from norviq.config import settings

_KID = "test-kid"


def _gen_rsa_pem() -> str:
    """Generate a 2048-bit RSA private key PEM (prefers `cryptography`; falls back to the pure-python `rsa` lib)."""
    try:  # prefer cryptography if a future env adds it
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa as crsa

        key = crsa.generate_private_key(public_exponent=65537, key_size=2048)
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
    except Exception:
        import rsa as rsalib

        _, priv = rsalib.newkeys(2048)
        return priv.save_pkcs1().decode()


@pytest.fixture(scope="module")
def rsa_keys() -> dict:
    """Private PEM + public JWK (with kid) for signing/verifying synthetic OIDC tokens."""
    from cryptography.hazmat.primitives import serialization

    priv_pem = _gen_rsa_pem()
    private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    public_key = private_key.public_key()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["alg"] = "RS256"
    jwk["kid"] = _KID
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {"priv_pem": priv_pem, "jwk": jwk, "pub_pem": pub_pem}


class _StubJwks:
    """JWKS client double: returns the test JWK for the known kid, else fails closed."""

    def __init__(self, jwk: dict) -> None:
        self._jwk = jwk

    async def get_key(self, kid: str) -> dict:
        if kid == self._jwk["kid"]:
            return self._jwk
        raise JWTError(f"unknown kid {kid}")


@pytest.fixture
def oidc_on(rsa_keys, monkeypatch) -> dict:
    """Enable OIDC with a stubbed JWKS + a group-mapping config."""
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example")
    monkeypatch.setattr(settings, "oidc_audience", "norviq")
    monkeypatch.setattr(settings, "oidc_group_claim", "groups")
    monkeypatch.setattr(
        settings,
        "oidc_group_mappings",
        {
            "norviq-admins": {"role": "admin"},
            "team-a": {"role": "viewer", "namespace": "team-a"},
            "team-b": {"role": "viewer", "namespace": "team-b"},
        },
    )
    monkeypatch.setattr(auth_mod, "get_jwks_client", lambda: _StubJwks(rsa_keys["jwk"]))
    return rsa_keys


def _mint(priv_pem: str, claims: dict, kid: str | None = _KID) -> str:
    base = {"iss": "https://idp.example", "aud": "norviq", "exp": int(time.time()) + 300, "sub": "alice"}
    base.update(claims)
    headers = {"kid": kid} if kid else {}
    return jwt.encode(base, priv_pem, algorithm="RS256", headers=headers)


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.mark.asyncio
async def test_admin_group_maps_to_admin(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"], "sub": "root"})
    user = await auth_mod.get_current_user(_creds(token))
    assert user["role"] == "admin" and user["namespace"] == "" and user["sub"] == "root"


@pytest.mark.asyncio
async def test_team_group_maps_to_scoped_viewer(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["team-a"]})
    user = await auth_mod.get_current_user(_creds(token))
    assert user["role"] == "viewer" and user["namespace"] == "team-a"


@pytest.mark.asyncio
async def test_unmapped_groups_get_least_privilege_floor(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["random-okta-group"]})
    user = await auth_mod.get_current_user(_creds(token))
    assert user["role"] == "viewer" and user["namespace"] == ""


@pytest.mark.asyncio
async def test_conflicting_namespaces_fail_closed(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["team-a", "team-b"]})
    with pytest.raises(Exception) as exc:  # HTTPException(401)
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_admin_group_wins_over_viewer(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["team-a", "norviq-admins"]})
    user = await auth_mod.get_current_user(_creds(token))
    assert user["role"] == "admin" and user["namespace"] == ""


# --- Fleet: cluster dimension in the group mapping + scoped_cluster ---


@pytest.mark.asyncio
async def test_group_mapping_sets_cluster_dimension(oidc_on, monkeypatch) -> None:
    monkeypatch.setattr(settings, "oidc_group_mappings", {
        "fleet-admins": {"role": "admin", "cluster": "*"},
        "cluster-a-viewer": {"role": "viewer", "cluster": "cluster-a"},
    })
    admin = await auth_mod.get_current_user(_creds(_mint(oidc_on["priv_pem"], {"groups": ["fleet-admins"]})))
    assert admin["role"] == "admin" and admin["cluster"] == "*"
    viewer = await auth_mod.get_current_user(_creds(_mint(oidc_on["priv_pem"], {"groups": ["cluster-a-viewer"]})))
    assert viewer["role"] == "viewer" and viewer["cluster"] == "cluster-a"


@pytest.mark.asyncio
async def test_conflicting_clusters_fail_closed(oidc_on, monkeypatch) -> None:
    monkeypatch.setattr(settings, "oidc_group_mappings", {
        "a": {"role": "viewer", "cluster": "cluster-a"},
        "b": {"role": "viewer", "cluster": "cluster-b"},
    })
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(_mint(oidc_on["priv_pem"], {"groups": ["a", "b"]})))
    assert getattr(exc.value, "status_code", None) == 401


def test_scoped_cluster_enforces() -> None:
    # admin / "*" see any cluster; a scoped viewer is pinned to its own, 403 otherwise.
    assert auth_mod.scoped_cluster({"role": "admin", "cluster": "*"}, "cluster-b") == "cluster-b"
    assert auth_mod.scoped_cluster({"role": "viewer", "cluster": "*"}, "cluster-b") == "cluster-b"
    assert auth_mod.scoped_cluster({"role": "viewer", "cluster": "cluster-a"}, None) == "cluster-a"
    assert auth_mod.scoped_cluster({"role": "viewer", "cluster": "cluster-a"}, "cluster-a") == "cluster-a"
    with pytest.raises(Exception) as exc:
        auth_mod.scoped_cluster({"role": "viewer", "cluster": "cluster-a"}, "cluster-b")
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        {"iss": "https://evil.example"},
        {"aud": "someone-else"},
        {"exp": int(time.time()) - 10},
    ],
)
async def test_bad_iss_aud_exp_rejected(oidc_on, bad) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"], **bad})
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


# --- H1: must_change lockdown is an EXACT-path allowlist, not a URL-suffix test ---


def _req(path: str) -> SimpleNamespace:
    """Minimal Request double: get_current_user reads only ``request.url.path`` (+ app.state.cache,
    which is None-safe here)."""
    return SimpleNamespace(url=SimpleNamespace(path=path), app=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/auth/change-password", "/api/v1/auth/logout", "/api/v1/me"])
async def test_must_change_token_allowed_on_exact_flag_clearing_paths(oidc_on, path) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"], "must_change": True})
    user = await auth_mod.get_current_user(_creds(token), _req(path))
    assert user["role"] == "admin" and user["must_change"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/policies",                       # a real, non-allowed route
        "/api/v1/policies/x/auth/change-password",  # crafted to END WITH an allowed suffix
        "/api/v1/agents/spoof/auth/logout",         # crafted to END WITH an allowed suffix
        "/api/v1/audit/frame/me",                   # crafted to END WITH `/me`
    ],
)
async def test_must_change_token_blocked_on_suffix_crafted_paths(oidc_on, path) -> None:
    # FAIL-ON-BUG: the old `path.endswith((...))` gate let the last three through (403 never raised).
    # With the exact-equality allowlist, every real route other than the three exact ones is 403.
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"], "must_change": True})
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token), _req(path))
    assert getattr(exc.value, "status_code", None) == 403


@pytest.mark.asyncio
async def test_unknown_kid_rejected(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"]}, kid="rotated-away")
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_missing_kid_rejected(oidc_on) -> None:
    token = _mint(oidc_on["priv_pem"], {"groups": ["norviq-admins"]}, kid=None)
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_alg_confusion_hs256_with_public_key_rejected(oidc_on) -> None:
    """Attacker forges an HS256 token using the RSA PUBLIC key bytes as the HMAC secret -> must 401."""

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": _KID}).encode())
    payload = b64(json.dumps({"sub": "attacker", "role": "admin", "namespace": ""}).encode())
    signing_input = f"{header}.{payload}".encode()
    # The classic attack: HMAC with the public key as the "secret".
    sig = b64(hmac.new(oidc_on["pub_pem"].encode(), signing_input, hashlib.sha256).digest())
    forged = f"{header}.{payload}.{sig}"
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(forged))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_legacy_hs256_still_accepted_during_migration(oidc_on) -> None:
    """With oidc_enabled AND legacy_hs256_enabled, a real api_secret_key HS256 token still works."""
    token = jwt.encode(
        {"sub": "svc", "role": "admin", "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )
    user = await auth_mod.get_current_user(_creds(token))
    assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_hs256_rejected_when_legacy_disabled(oidc_on, monkeypatch) -> None:
    monkeypatch.setattr(settings, "legacy_hs256_enabled", False)
    token = jwt.encode({"sub": "svc", "role": "admin"}, settings.api_secret_key, algorithm="HS256")
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_rs256_token_rejected_on_hs256_only_path(rsa_keys, monkeypatch) -> None:
    """PyJWT-swap regression: a validly-signed RS256 token must NOT be accepted when OIDC is off
    (legacy-HS256-only mode) — the two paths stay mutually exclusive after the jose->PyJWT swap."""
    monkeypatch.setattr(settings, "oidc_enabled", False)
    monkeypatch.setattr(settings, "legacy_hs256_enabled", True)
    token = _mint(rsa_keys["priv_pem"], {"sub": "attacker", "role": "admin"})
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(token))
    assert getattr(exc.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_alg_none_rejected(oidc_on) -> None:
    """`alg: none` (the classic unsigned-token forgery) must never validate on either path."""

    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "attacker", "role": "admin", "namespace": ""}).encode())
    forged = f"{header}.{payload}."  # no signature segment, as `alg: none` prescribes
    with pytest.raises(Exception) as exc:
        await auth_mod.get_current_user(_creds(forged))
    assert getattr(exc.value, "status_code", None) == 401


# --- JwksClient itself: caching + bounded refresh + fail-closed fetch ---


class _FakeResp:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)

    def json(self) -> dict:
        return self._payload


class _FakeHttp:
    def __init__(self, payload: dict, fail: bool = False) -> None:
        self.payload = payload
        self.fail = fail
        self.calls = 0

    async def get(self, url: str) -> _FakeResp:
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("down")
        return _FakeResp(self.payload)


@pytest.mark.asyncio
async def test_jwks_client_caches_and_serves_key(rsa_keys) -> None:
    http = _FakeHttp({"keys": [rsa_keys["jwk"]]})
    client = JwksClient(jwks_url="https://idp/jwks", ttl_s=300, min_refresh_s=30, http_client=http)
    k1 = await client.get_key(_KID)
    k2 = await client.get_key(_KID)
    assert k1["kid"] == _KID and k2["kid"] == _KID
    assert http.calls == 1  # second lookup served from cache


@pytest.mark.asyncio
async def test_jwks_client_fetch_failure_fails_closed(rsa_keys) -> None:
    http = _FakeHttp({"keys": []}, fail=True)
    client = JwksClient(jwks_url="https://idp/jwks", http_client=http)
    with pytest.raises(JWTError):
        await client.get_key(_KID)


@pytest.mark.asyncio
async def test_jwks_client_unknown_kid_bounded_refresh(rsa_keys) -> None:
    http = _FakeHttp({"keys": [rsa_keys["jwk"]]})
    client = JwksClient(jwks_url="https://idp/jwks", ttl_s=300, min_refresh_s=10_000, http_client=http)
    with pytest.raises(JWTError):
        await client.get_key("nope")  # one initial fetch + one forced refetch, still absent
    assert http.calls <= 2  # the min_refresh floor prevents unbounded refetch storms
