# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""auto-mTLS: RemoteEvaluator.connect() builds a mutual-TLS ssl context only when the feature is on.

Feature OFF (or an http URL) must be byte-identical to the prior plaintext behavior: httpx.AsyncClient
is created with NO ``verify`` kwarg. Feature ON + https + the three PEMs -> a PROTOCOL_TLS_CLIENT
context with verify_mode == CERT_REQUIRED and the client cert loaded (a mismatched key would raise,
so a clean build proves the chain loaded). The test CA + client cert are generated hermetically.
"""

from __future__ import annotations

import datetime
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from norviq.sidecar import remote_evaluator
from norviq.sidecar.remote_evaluator import RemoteEvaluator, _build_mtls_context


def _gen_ca_and_client() -> tuple[str, str, str]:
    """Return (ca_pem, client_cert_pem, client_key_pem) — a self-signed CA + a clientAuth leaf."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "norviq-internal-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, "norviq-sidecar"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "default"),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = client_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return ca_pem, cert_pem, key_pem


class _CapturingClient:
    """Stand-in for httpx.AsyncClient that records the kwargs it was constructed with."""

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs


def test_build_mtls_context_requires_cert() -> None:
    """The helper yields a PROTOCOL_TLS_CLIENT context that mandates a verified peer cert."""
    ca_pem, cert_pem, key_pem = _gen_ca_and_client()
    ctx = _build_mtls_context(ca_pem, cert_pem, key_pem)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # The CA we trusted is present; a client cert we couldn't chain/load would have raised above.
    assert len(ctx.get_ca_certs()) == 1


@pytest.mark.asyncio
async def test_connect_http_off_no_ssl_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Feature OFF: no verify kwarg passed to httpx (byte-identical to prior plaintext behavior)."""
    monkeypatch.setattr(remote_evaluator.settings, "internal_tls", False, raising=False)
    monkeypatch.setattr(remote_evaluator.httpx, "AsyncClient", _CapturingClient)

    ev = RemoteEvaluator(api_url="http://norviq-api:8080", api_token="tok")
    await ev.connect()
    assert isinstance(ev._client, _CapturingClient)
    assert "verify" not in ev._client.kwargs


@pytest.mark.asyncio
async def test_connect_https_flag_off_no_ssl_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even on an https URL, feature OFF passes no ssl context (unchanged behavior)."""
    monkeypatch.setattr(remote_evaluator.settings, "internal_tls", False, raising=False)
    monkeypatch.setattr(remote_evaluator.httpx, "AsyncClient", _CapturingClient)

    ev = RemoteEvaluator(api_url="https://norviq-api:8443", api_token="tok")
    await ev.connect()
    assert "verify" not in ev._client.kwargs


@pytest.mark.asyncio
async def test_connect_http_flag_on_no_ssl_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Flag ON but a plaintext http URL still passes no ssl context (gated on https)."""
    ca_pem, cert_pem, key_pem = _gen_ca_and_client()
    monkeypatch.setattr(remote_evaluator.settings, "internal_tls", True, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_api_ca_pem", ca_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_client_cert_pem", cert_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_client_key_pem", key_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.httpx, "AsyncClient", _CapturingClient)

    ev = RemoteEvaluator(api_url="http://norviq-api:8080", api_token="tok")
    await ev.connect()
    assert "verify" not in ev._client.kwargs


@pytest.mark.asyncio
async def test_connect_https_flag_on_builds_mtls_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """Feature ON + https + the 3 PEMs -> a CERT_REQUIRED ssl context is passed to httpx; token kept."""
    ca_pem, cert_pem, key_pem = _gen_ca_and_client()
    monkeypatch.setattr(remote_evaluator.settings, "internal_tls", True, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_api_ca_pem", ca_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_client_cert_pem", cert_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.settings, "internal_client_key_pem", key_pem, raising=False)
    monkeypatch.setattr(remote_evaluator.httpx, "AsyncClient", _CapturingClient)

    ev = RemoteEvaluator(api_url="https://norviq-api:8443", api_token="tok")
    await ev.connect()

    kwargs = ev._client.kwargs
    assert "verify" in kwargs
    ctx = kwargs["verify"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    # Bearer token header preserved alongside mTLS (defense in depth).
    assert kwargs["headers"]["Authorization"] == "Bearer tok"
