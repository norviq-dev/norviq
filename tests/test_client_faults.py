# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A fault the client can tell is its own blocks; a failure that looks like the network keeps the fallback.

Both data-plane clients are covered: `PolicyEngineClient` (SDK and MCP Gate B) and the sidecar's
`RemoteEvaluator`.

Table (i) is the faults each client can tell deterministically are its own: each must block under
``allow`` without asking the engine, name the code, and keep the token out of the logs. Table (ii)
is failures that look the same whether the engine is down or the client's network is wrong, made
with real sockets: each must follow the fallback in both modes with the same number of attempts as
before, which is the documented residual.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable, Iterator

import httpx
import pytest
import structlog
from pydantic import ValidationError

from norviq.bearer import REDACTED, bearer_token_problem, redact_credentials
from norviq.config import NorviqSettings, settings
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sidecar.remote_evaluator import RemoteEvaluator

SDK_RULE, SDK_CODE = "engine_client_misconfigured", "NRVQ-SDK-1018"
SDC_RULE, SDC_CODE = "thin_proxy_client_misconfigured", "NRVQ-SDC-3049"
ALLOW = {"decision": "allow", "rule_id": "engine_allowed", "trust_score": 0.9}


def _token() -> str:
    """A throwaway token with no 8-character run in common with any log text by accident."""
    return "tk" + os.urandom(20).hex()


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="issue_refund",
        tool_params={"amount": 25},
        agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/agent", namespace="default",
                                     agent_class="support"),
        session_id="s",
        framework="test",
    )


def _assert_no_token(text: str, token: str) -> None:
    secret = token.strip()
    for i in range(len(secret) - 7):
        assert secret[i:i + 8] not in text, f"8-character piece of the token at offset {i} is in the logs"


@pytest.fixture(autouse=True)
def _fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sdk_retry_backoff_base_ms", 1, raising=False)
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
                 "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def allow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sdk_fallback_mode", "allow", raising=False)


# ---------------------------------------------------------------------------------------------------
# Real sockets
# ---------------------------------------------------------------------------------------------------


class _Server:
    """A TCP server on 127.0.0.1 that runs `handle(conn)` for every connection and counts them."""

    def __init__(self, handle: Callable[[socket.socket], None], tls: ssl.SSLContext | None = None) -> None:
        self.hits = 0
        self._handle = handle
        self._tls = tls
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.hits += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            if self._tls is not None:
                conn = self._tls.wrap_socket(conn, server_side=True)
            self._handle(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._sock.close()


def _read_request(conn: socket.socket) -> None:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            return
        body += chunk


def _respond(status: str, body: bytes, extra: str = "") -> Callable[[socket.socket], None]:
    def handle(conn: socket.socket) -> None:
        _read_request(conn)
        conn.sendall(f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                     f"{extra}Connection: close\r\n\r\n".encode() + body)
    return handle


def _allow_engine(conn: socket.socket) -> None:
    _respond("200 OK", json.dumps(ALLOW).encode())(conn)


def _reset(conn: socket.socket) -> None:
    _read_request(conn)
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def _hang(conn: socket.socket) -> None:
    _read_request(conn)
    time.sleep(1.5)


def _close_mid_response(conn: socket.socket) -> None:
    _read_request(conn)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"deci")


def _plain_http(conn: socket.socket) -> None:
    conn.recv(65536)  # a ClientHello, answered as plain HTTP
    conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")


def _drop(conn: socket.socket) -> None:
    conn.recv(65536)  # the ClientHello, then nothing


def _proxy(status: str) -> Callable[[socket.socket], None]:
    def handle(conn: socket.socket) -> None:
        _read_request(conn)
        conn.sendall(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n".encode())
    return handle


@pytest.fixture
def servers() -> Iterator[Callable[..., _Server]]:
    made: list[_Server] = []

    def make(handle: Callable[[socket.socket], None], tls: ssl.SSLContext | None = None) -> _Server:
        made.append(_Server(handle, tls))
        return made[-1]

    yield make
    for server in made:
        server.close()


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory: pytest.TempPathFactory) -> ssl.SSLContext:
    """A server context with a certificate no client trusts."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
    folder = tmp_path_factory.mktemp("tls")
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(folder / "cert.pem", folder / "key.pem")
    return ctx


class _Counting(httpx.AsyncHTTPTransport):
    """A real transport that counts the requests handed to it."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return await super().handle_async_request(request)


class _Mock(httpx.MockTransport):
    def __init__(self, reply: Callable[[httpx.Request], httpx.Response]) -> None:
        self.calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            return reply(request)

        super().__init__(handler)


def _raise(exc: BaseException) -> Callable[[httpx.Request], httpx.Response]:
    def reply(_: httpx.Request) -> httpx.Response:
        raise exc
    return reply


# ---------------------------------------------------------------------------------------------------
# The two clients, driven the same way
# ---------------------------------------------------------------------------------------------------


async def _sdk(url: str, token: str, transport: httpx.AsyncBaseTransport | None = None,
               timeout_ms: int = 1000):
    client = PolicyEngineClient(base_url=url, timeout_ms=timeout_ms, token=token)
    if transport is not None:
        client._client = httpx.AsyncClient(base_url=url, transport=transport,  # noqa: SLF001
                                           headers={"Authorization": f"Bearer {token}"},
                                           timeout=timeout_ms / 1000)
    try:
        return await client.evaluate(_event())
    finally:
        await client.close()


async def _sidecar(url: str, token: str, transport: httpx.AsyncBaseTransport | None = None,
                   timeout_ms: int = 1000):
    ev = RemoteEvaluator(api_url=url, api_token=token)
    if transport is not None:
        ev._client = httpx.AsyncClient(base_url=url, transport=transport,  # noqa: SLF001
                                       headers={"Authorization": f"Bearer {token}"},
                                       timeout=timeout_ms / 1000)
    try:
        return await ev.evaluate(_event())
    finally:
        await ev.close()


CLIENTS = {"sdk": (_sdk, SDK_RULE, SDK_CODE), "sidecar": (_sidecar, SDC_RULE, SDC_CODE)}


async def _run(which: str, url: str, token: str, transport: httpx.AsyncBaseTransport | None = None,
               timeout_ms: int = 1000):
    call = CLIENTS[which][0]
    with structlog.testing.capture_logs() as logs:
        decision = await call(url, token, transport, timeout_ms)
    return decision, logs


# ---------------------------------------------------------------------------------------------------
# (i) Faults the client can tell are its own: blocked under fallback=allow
# ---------------------------------------------------------------------------------------------------

# 1. A token that cannot be a header value, passed to the client directly (settings strip it).
BAD_TOKENS = {
    "trailing_newline": lambda t: t + "\n",
    "leading_space": lambda t: " " + t,
    "embedded_cr": lambda t: t[:10] + "\r" + t[10:],
    "embedded_lf": lambda t: t[:10] + "\n" + t[10:],
    "nul": lambda t: t[:10] + "\x00" + t[10:],
    "control": lambda t: t[:10] + "\x01" + t[10:],
    "non_latin1": lambda t: t[:10] + "€" + t[10:],
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("make", BAD_TOKENS.values(), ids=BAD_TOKENS.keys())
async def test_a_token_that_cannot_be_sent_blocks_without_a_request(allow, servers, which, make) -> None:
    engine = servers(_allow_engine)
    token = make(_token())
    decision, logs = await _run(which, f"http://127.0.0.1:{engine.port}", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert engine.hits == 0
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


@pytest.mark.parametrize("make", BAD_TOKENS.values(), ids=BAD_TOKENS.keys())
async def test_the_sidecar_starts_with_a_token_it_cannot_send_and_blocks_each_call(allow, servers, make) -> None:
    """`connect()` runs at sidecar startup; it must neither crash nor build a client with the token."""
    engine = servers(_allow_engine)
    token = make(_token())
    ev = RemoteEvaluator(api_url=f"http://127.0.0.1:{engine.port}", api_token=token)
    with structlog.testing.capture_logs() as logs:
        await ev.connect()
        decision = await ev.evaluate(_event())
    await ev.close()
    assert decision.decision == "block" and decision.rule_id == SDC_RULE
    assert engine.hits == 0
    assert [e.get("code") for e in logs if e.get("code") == SDC_CODE] == [SDC_CODE, SDC_CODE], logs
    _assert_no_token(repr(logs) + decision.reason, token)


# 2. An engine URL that cannot work. `{port}` is a live engine that would allow the call.
BAD_URLS = {
    "no_scheme": "127.0.0.1:{port}",
    "unsupported_scheme": "ftp://127.0.0.1:{port}",
    "no_host": "http://:{port}",
    "port_zero": "http://127.0.0.1:0",
    "port_too_large": "http://127.0.0.1:70000",
    "unparseable": "http://[::1:{port}",
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("url", BAD_URLS.values(), ids=BAD_URLS.keys())
async def test_an_unusable_engine_url_blocks_without_a_request(allow, servers, which, url) -> None:
    engine = servers(_allow_engine)
    token = _token()
    decision, logs = await _run(which, url.format(port=engine.port), token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert engine.hits == 0
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


# 3. Impossible client settings, past the Settings constraints (set on the live object).
# The sidecar's timeout and pool size are constants; it reads only the retry count.
BAD_SETTINGS = [
    ("sdk", "sdk_retry_max_attempts", -1),
    ("sidecar", "sdk_retry_max_attempts", -1),
    ("sdk", "sdk_http_max_connections", 0),
]


@pytest.mark.parametrize("which,name,value", BAD_SETTINGS)
async def test_impossible_client_settings_block_without_a_request(allow, servers, monkeypatch, which, name,
                                                                  value) -> None:
    monkeypatch.setattr(settings, name, value, raising=False)
    engine = servers(_allow_engine)
    decision, logs = await _run(which, f"http://127.0.0.1:{engine.port}", _token())
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert engine.hits == 0
    assert any(entry.get("code") == code for entry in logs), logs


async def test_a_non_positive_timeout_blocks_without_a_request(allow, servers) -> None:
    engine = servers(_allow_engine)
    decision, logs = await _run("sdk", f"http://127.0.0.1:{engine.port}", _token(), timeout_ms=-5)
    assert decision.decision == "block" and decision.rule_id == SDK_RULE
    assert engine.hits == 0


# 4. Errors httpx raises before anything is sent, and a client that cannot be built.
LOCAL_ERRORS = {
    "local_protocol_error": lambda token: httpx.LocalProtocolError(f"Illegal header value b'Bearer {token}\\n'"),
    "unsupported_protocol": lambda token: httpx.UnsupportedProtocol("Request URL has an unsupported protocol"),
    "invalid_url": lambda token: httpx.InvalidURL("Invalid port"),
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("make", LOCAL_ERRORS.values(), ids=LOCAL_ERRORS.keys())
async def test_an_error_raised_before_sending_blocks_and_is_not_retried(allow, which, make) -> None:
    token = _token()
    transport = _Mock(_raise(make(token)))
    decision, logs = await _run(which, "http://engine.test", token, transport)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert transport.calls == 1
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


@pytest.mark.parametrize("which", CLIENTS)
async def test_a_client_that_cannot_be_built_blocks(allow, servers, which) -> None:
    # Latin-1 passes the token check; httpx encodes headers as ASCII when the client is built.
    engine = servers(_allow_engine)
    token = _token()[:10] + "é" + _token()
    decision, logs = await _run(which, f"http://127.0.0.1:{engine.port}", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert engine.hits == 0
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


# 5. TLS: a certificate this client does not trust, and an https URL whose server does not speak TLS.
@pytest.mark.parametrize("which", CLIENTS)
async def test_an_untrusted_engine_certificate_blocks_and_is_not_retried(allow, servers, self_signed,
                                                                         which) -> None:
    engine = servers(_allow_engine, tls=self_signed)
    token = _token()
    decision, logs = await _run(which, f"https://127.0.0.1:{engine.port}", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert "certificate" in decision.reason
    assert engine.hits == 1
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


@pytest.fixture(scope="module")
def client_cert_pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """A CA, an engine certificate it signed, and client certificates the engine accepts or refuses."""
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    def make(cn: str, issuer: tuple | None = None, ca: bool = False, days: tuple[int, int] = (-1, 1),
             ip: str | None = None) -> tuple:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        issuer_name, issuer_key = (issuer[0].subject, issuer[1]) if issuer else (name, key)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now + datetime.timedelta(days=days[0]))
                   .not_valid_after(now + datetime.timedelta(days=days[1]))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if ip:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        return builder.sign(issuer_key, hashes.SHA256()), key

    def pem(cert: object) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def key_pem(key: object) -> str:
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()

    ca, other_ca = make("ca", ca=True), make("other", ca=True)
    engine = make("engine", issuer=ca, ip="127.0.0.1")
    folder = tmp_path_factory.mktemp("mtls")
    (folder / "ca.pem").write_text(pem(ca[0]))
    (folder / "engine.pem").write_text(pem(engine[0]))
    (folder / "engine.key").write_text(key_pem(engine[1]))
    # TLS 1.2, so the refusal arrives as an alert during the handshake. Over TLS 1.3 the client has
    # finished its side first, and the refusal usually reaches it as a broken pipe: the residual.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(folder / "engine.pem", folder / "engine.key")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(folder / "ca.pem")
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    clients = {"good": make("client", issuer=ca), "foreign_ca": make("client", issuer=other_ca),
               "expired": make("client", issuer=ca, days=(-60, -30))}
    plain = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # the same engine, asking for no client certificate
    plain.load_cert_chain(folder / "engine.pem", folder / "engine.key")
    return {"server": ctx, "plain": plain, "ca_file": str(folder / "ca.pem"), "ca_pem": pem(ca[0]),
            "clients": {k: (pem(c), key_pem(k_)) for k, (c, k_) in clients.items()}}


def _present(monkeypatch: pytest.MonkeyPatch, pki: dict, which: str, client: str | None) -> None:
    """Trust the engine's CA, and have the client present `client`'s certificate, or none."""
    monkeypatch.setenv("SSL_CERT_FILE", pki["ca_file"])
    if which == "sidecar":
        cert, key = pki["clients"][client] if client else ("", "")
        monkeypatch.setattr(settings, "internal_tls", True, raising=False)
        monkeypatch.setattr(settings, "internal_api_ca_pem", pki["ca_pem"], raising=False)
        monkeypatch.setattr(settings, "internal_client_cert_pem", cert, raising=False)
        monkeypatch.setattr(settings, "internal_client_key_pem", key, raising=False)


# The sidecar presents a certificate the engine does not accept. (The SDK client presents none; over
# TLS 1.2 that draws the generic HANDSHAKE_FAILURE, which follows the fallback: see table (ii).)
REFUSED_CERTS = [("sidecar", "foreign_ca", "UNKNOWN_CA"), ("sidecar", "expired", "CERTIFICATE_EXPIRED")]


@pytest.mark.parametrize(("which", "client", "alert"), REFUSED_CERTS, ids=[f"{w}-{c}" for w, c, _ in REFUSED_CERTS])
async def test_a_client_certificate_the_engine_refuses_blocks_and_is_not_retried(
        allow, servers, monkeypatch, client_cert_pki, which, client, alert) -> None:
    _present(monkeypatch, client_cert_pki, which, client)
    engine = servers(_allow_engine, tls=client_cert_pki["server"])
    token = _token()
    decision, logs = await _run(which, f"https://127.0.0.1:{engine.port}", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule, decision
    assert alert in decision.reason
    assert engine.hits == 1
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


async def test_a_client_certificate_the_engine_accepts_still_gets_a_decision(
        allow, servers, monkeypatch, client_cert_pki) -> None:
    """The control for the refusal rows: the same engine, with a certificate it accepts."""
    _present(monkeypatch, client_cert_pki, "sidecar", "good")
    engine = servers(_allow_engine, tls=client_cert_pki["server"])
    decision, _ = await _run("sidecar", f"https://127.0.0.1:{engine.port}", _token())
    assert decision.decision == "allow" and decision.rule_id == "engine_allowed", decision
    assert engine.hits == 1


@pytest.mark.parametrize("which", CLIENTS)
async def test_https_to_a_server_without_tls_blocks_and_is_not_retried(allow, servers, which) -> None:
    engine = servers(_plain_http)
    token = _token()
    decision, logs = await _run(which, f"https://127.0.0.1:{engine.port}", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert engine.hits == 1
    assert any(entry.get("code") == code for entry in logs), logs


# 6. A forward proxy that refuses the CONNECT with a non-5xx status. Its reason phrase is not echoed.
@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("status", ["407 Proxy Authentication Required", "403 Forbidden", "600 Odd",
                                    "999 Request denied"])
async def test_a_proxy_refusing_the_connect_blocks_and_is_not_retried(allow, servers, monkeypatch, which,
                                                                      status) -> None:
    phrase = "proxyphrase" + os.urandom(6).hex()
    proxy = servers(_proxy(f"{status} {phrase}"))
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{proxy.port}")
    token = _token()
    decision, logs = await _run(which, "https://engine.test", token)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert status.split()[0] in decision.reason
    assert proxy.hits == 1
    assert any(entry.get("code") == code for entry in logs), logs
    assert phrase not in repr(logs) + decision.reason
    _assert_no_token(repr(logs) + decision.reason, token)


# 7. Something answered, but not with a decision.
NOT_A_DECISION = {
    "redirect": lambda _: httpx.Response(302, headers={"Location": "https://elsewhere.test/"}),
    "not_modified": lambda _: httpx.Response(304),
    "not_json": lambda _: httpx.Response(200, text="<html>ok</html>"),
    "not_an_object": lambda _: httpx.Response(200, json=["allow"]),
    "no_decision": lambda _: httpx.Response(200, json={"rule_id": "x"}),
    "unknown_decision": lambda _: httpx.Response(200, json={"decision": "maybe"}),
    "status_600": lambda _: httpx.Response(600, json={"detail": "x"}),
    "status_999": lambda _: httpx.Response(999),
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("reply", NOT_A_DECISION.values(), ids=NOT_A_DECISION.keys())
async def test_an_answer_that_is_not_a_decision_blocks_and_is_not_retried(allow, which, reply) -> None:
    transport = _Mock(reply)
    token = _token()
    decision, logs = await _run(which, "http://engine.test", token, transport)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert transport.calls == 1
    assert any(entry.get("code") == code for entry in logs), logs


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("status", ["600 Odd", "999 Request denied"])
async def test_a_status_outside_the_standard_range_blocks_over_a_real_socket(servers, allow, which, status) -> None:
    """Only 500-599 is an engine outage; any other non-4xx status is not a decision."""
    url = f"http://127.0.0.1:{servers(_respond(status, b'{}')).port}"
    transport, token = _Counting(), _token()
    decision, logs = await _run(which, url, token, transport)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert transport.calls == 1
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


# 8. Anything that is not a transport error: unknown means block.
UNKNOWN = {
    "runtime_error": lambda token: RuntimeError(f"Bearer {token}"),
    "key_error": lambda token: KeyError("decision"),
    "decoding_error": lambda token: httpx.DecodingError("bad gzip"),
    "too_many_redirects": lambda token: httpx.TooManyRedirects("loop"),
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("make", UNKNOWN.values(), ids=UNKNOWN.keys())
async def test_an_unknown_error_blocks_and_is_not_retried(allow, which, make) -> None:
    token = _token()
    transport = _Mock(_raise(make(token)))
    decision, logs = await _run(which, "http://engine.test", token, transport)
    _, rule, code = CLIENTS[which]
    assert decision.decision == "block" and decision.rule_id == rule
    assert transport.calls == 1
    assert any(entry.get("code") == code for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


@pytest.mark.parametrize("reply", [_raise(httpx.LocalProtocolError("refused")), lambda _: httpx.Response(600)],
                         ids=["local_protocol_error", "status_600"])
async def test_a_local_fault_does_not_open_the_circuit(allow, reply) -> None:
    """Only a silent engine counts toward the breaker; otherwise the next calls would take the fallback."""
    client = PolicyEngineClient(base_url="http://engine.test", timeout_ms=1000, token="")
    transport = _Mock(reply)
    client._client = httpx.AsyncClient(base_url="http://engine.test", transport=transport)  # noqa: SLF001
    for _ in range(settings.sdk_circuit_fail_threshold + 2):
        decision = await client.evaluate(_event())
        assert decision.rule_id == SDK_RULE
    assert transport.calls == settings.sdk_circuit_fail_threshold + 2
    await client.close()


# ---------------------------------------------------------------------------------------------------
# (ii) Failures that look like the network: the fallback, in both modes, with the same attempts
# ---------------------------------------------------------------------------------------------------

FALLBACK = {
    "sdk": {"allow": ("allow", "engine_unavailable_fallback"), "block": ("block", "engine_unavailable_fallback")},
    "sidecar": {"allow": ("allow", "thin_proxy_fail_open"), "block": ("block", "thin_proxy_fail_closed")},
}


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# name -> (server handler, None for a closed port or a proxy status line, scheme, attempts on the SDK path)
# The SDK client does not retry a 5xx; the sidecar retries everything here.
NETWORK = {
    "closed_port": (None, "http", "retried"),
    "reset": (_reset, "http", "retried"),
    "hang": (_hang, "http", "retried"),
    "close_mid_response": (_close_mid_response, "http", "retried"),
    "503": (_respond("503 Service Unavailable", b'{"detail":"down"}'), "http", "once"),
    "599": (_respond("599 Network Timeout", b"{}"), "http", "once"),
    "tls_handshake_dropped": (_drop, "https", "retried"),
    "proxy_502": ("502 Bad Gateway", "https", "retried"),
    "proxy_599": ("599 Network Timeout", "https", "retried"),
}


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("mode", ["allow", "block"])
@pytest.mark.parametrize("case", NETWORK.values(), ids=NETWORK.keys())
async def test_a_network_shaped_failure_follows_the_fallback(servers, monkeypatch, which, mode, case) -> None:
    monkeypatch.setattr(settings, "sdk_fallback_mode", mode, raising=False)
    handler, scheme, sdk_attempts = case
    if handler is None:
        url, transport = f"{scheme}://127.0.0.1:{_closed_port()}", _Counting()
    elif isinstance(handler, str):
        proxy = servers(_proxy(handler))
        url, transport = "https://engine.test", _Counting(proxy=f"http://127.0.0.1:{proxy.port}")
    else:
        url, transport = f"{scheme}://127.0.0.1:{servers(handler).port}", _Counting()
    token = _token()
    decision, logs = await _run(which, url, token, transport, timeout_ms=300)
    assert (decision.decision, decision.rule_id) == FALLBACK[which][mode]
    retried = settings.sdk_retry_max_attempts + 1
    assert transport.calls == (1 if which == "sdk" and sdk_attempts == "once" else retried)
    assert not any(entry.get("code") in (SDK_CODE, SDC_CODE) for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


def _garbage_record(conn: socket.socket) -> None:
    """Read the request over TLS, then write a record that does not decrypt, past the TLS layer."""
    _read_request(conn)
    os.write(conn.fileno(), b"\x17\x03\x03\x00\x20" + os.urandom(32))


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("mode", ["allow", "block"])
async def test_a_tls_error_after_the_handshake_follows_the_fallback(servers, monkeypatch, client_cert_pki,
                                                                     which, mode) -> None:
    """httpcore wraps TLS errors from the handshake only; one after it reaches the client as a bare
    ssl.SSLError. It names no certificate, so it is the network's, and is not retried, as before."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", mode, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", client_cert_pki["ca_file"])
    engine = servers(_garbage_record, tls=client_cert_pki["plain"])
    token = _token()
    decision, logs = await _run(which, f"https://127.0.0.1:{engine.port}", token)
    assert (decision.decision, decision.rule_id) == FALLBACK[which][mode], decision
    assert engine.hits == 1
    assert not any(entry.get("code") in (SDK_CODE, SDC_CODE) for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


@pytest.mark.parametrize("which", CLIENTS)
@pytest.mark.parametrize("mode", ["allow", "block"])
async def test_a_generic_handshake_failure_follows_the_fallback(servers, monkeypatch, which, mode) -> None:
    """A TLS 1.2 server with no certificate of its own ends the handshake with handshake_failure, the
    same alert a missing client certificate draws. It does not say whose fault it is."""
    monkeypatch.setattr(settings, "sdk_fallback_mode", mode, raising=False)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    engine = servers(_allow_engine, tls=ctx)
    token = _token()
    decision, logs = await _run(which, f"https://127.0.0.1:{engine.port}", token)
    assert (decision.decision, decision.rule_id) == FALLBACK[which][mode], decision
    assert engine.hits == settings.sdk_retry_max_attempts + 1
    assert not any(entry.get("code") in (SDK_CODE, SDC_CODE) for entry in logs), logs
    _assert_no_token(repr(logs) + decision.reason, token)


# ---------------------------------------------------------------------------------------------------
# (iii) Settings
# ---------------------------------------------------------------------------------------------------


def test_the_api_token_is_stripped_when_settings_load(monkeypatch: pytest.MonkeyPatch) -> None:
    token = _token()
    monkeypatch.setenv("NRVQ_API_TOKEN", f"  {token}\r\n")
    assert NorviqSettings().api_token == token
    assert NorviqSettings(api_token=f"{token}\n").api_token == token


@pytest.mark.parametrize("field,value", [
    ("sdk_timeout_ms", 0), ("sdk_timeout_ms", -1),
    ("sdk_http_max_connections", 0), ("sdk_http_max_connections", -3),
    ("sdk_retry_max_attempts", -1),
])
def test_impossible_client_settings_are_refused_at_load(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        NorviqSettings(**{field: value})


def test_possible_client_settings_still_load() -> None:
    s = NorviqSettings(sdk_timeout_ms=1, sdk_http_max_connections=1, sdk_retry_max_attempts=0)
    assert (s.sdk_timeout_ms, s.sdk_http_max_connections, s.sdk_retry_max_attempts) == (1, 1, 0)


# ---------------------------------------------------------------------------------------------------
# (iv) Redaction
# ---------------------------------------------------------------------------------------------------


def test_the_token_check_never_quotes_the_token() -> None:
    token = _token()
    for make in BAD_TOKENS.values():
        problem = bearer_token_problem(make(token))
        assert problem is not None
        _assert_no_token(problem, token)
    assert bearer_token_problem(token) is None
    assert bearer_token_problem("") is None


@pytest.mark.parametrize("message", [
    "Illegal header value b'Bearer {t}\\n'",
    "Invalid header value b'Bearer {t}\\r\\nX: y'",
    "request failed: Authorization: Bearer {t}",
    "{t}",
])
def test_redaction_removes_the_token_from_error_text(message: str) -> None:
    token = _token()
    text = message.format(t=token)
    assert token[:8] in text  # the control: the planted token is there before redaction
    redacted = redact_credentials(text, token)
    assert REDACTED in redacted
    _assert_no_token(redacted, token)


def test_redaction_without_the_token_still_removes_a_bearer_value() -> None:
    token = _token()
    redacted = redact_credentials(f"Illegal header value b'Bearer {token}\\n'")
    _assert_no_token(redacted, token)


async def test_the_mcp_stores_name_a_local_fault_and_never_log_the_token(servers) -> None:
    from norviq.mcp.pins import ControlPlanePinStore
    from norviq.mcp.servers import ControlPlaneServerStore

    api = servers(_respond("200 OK", b"[]"))
    url, token = f"http://127.0.0.1:{api.port}", _token() + "\n"
    servers_store = ControlPlaneServerStore(namespace="default", api_url=url, token=token)
    pins_store = ControlPlanePinStore(namespace="default", server_id="srv", api_url=url, token=token)
    with structlog.testing.capture_logs() as logs:
        assert await servers_store.load() is False
        await pins_store.load()
    assert servers_store.degraded and pins_store.degraded  # the same degrade as an outage
    assert api.hits == 0
    assert [e.get("code") for e in logs] == ["NRVQ-MCP-5095", "NRVQ-MCP-5095"], logs
    _assert_no_token(repr(logs), token)


async def test_the_mcp_stores_still_degrade_on_an_outage(servers) -> None:
    from norviq.mcp.servers import ControlPlaneServerStore

    store = ControlPlaneServerStore(namespace="default", api_url=f"http://127.0.0.1:{_closed_port()}",
                                    token=_token())
    with structlog.testing.capture_logs() as logs:
        assert await store.load() is False
    assert store.degraded
    assert [e.get("code") for e in logs] == ["NRVQ-MCP-5077"], logs
