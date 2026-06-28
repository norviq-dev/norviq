# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for sidecar proxy socket and HTTP fallback."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sidecar import __main__ as sidecar_main
from norviq.sidecar.http_fallback import create_http_fallback
from norviq.sidecar.proxy import SidecarProxy

HAS_UNIX_SOCKETS = hasattr(asyncio, "start_unix_server") and hasattr(asyncio, "open_unix_connection")


def _load_dotenv_if_present() -> None:
    """Load environment values from local .env if present."""
    env_file = Path(".env")
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#") or "=" not in item:
            continue
        key, value = item.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@pytest.fixture(scope="module", autouse=True)
def _env_bootstrap() -> None:
    """Ensure tests pick up local env values."""
    _load_dotenv_if_present()


@pytest.fixture
def redis_url() -> str:
    """Return configured Redis URL for integration tests."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for sidecar tests")
    return value


@pytest.fixture
def socket_path() -> str:
    """Return unique Unix socket path for each test."""
    base = os.getenv("NRVQ_SOCKET_PATH", "/tmp/norviq-proxy-test.sock")
    return f"{base}.{uuid4().hex}"


@pytest.fixture
async def proxy(socket_path: str, monkeypatch: pytest.MonkeyPatch, redis_url: str) -> AsyncIterator[SidecarProxy]:
    """Create and run sidecar proxy with isolated resources."""
    if not HAS_UNIX_SOCKETS:
        pytest.skip("Unix sockets are not supported on this platform")
    cache = RedisCache(url=redis_url)
    monkeypatch.setattr("norviq.sidecar.proxy.RedisCache", lambda: cache)
    monkeypatch.setattr("norviq.sidecar.proxy.AuditEmitter.init", _noop_emit_init)
    sidecar = SidecarProxy(socket_path=socket_path)
    await sidecar.start()
    monkeypatch.setattr(sidecar._emitter, "_do_emit", _noop_emit)
    yield sidecar
    await sidecar.stop()


async def _noop_emit(*_: object, **__: object) -> None:
    """Skip audit network and DB writes in sidecar tests."""
    return None


async def _noop_emit_init(self: AuditEmitter) -> None:
    """Skip OTel global tracer initialization in tests."""
    self._tracer = None


async def _send_socket_request(path: str, payload: dict) -> dict:
    """Send one JSONL request to sidecar Unix socket."""
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()
    response = await reader.readline()
    writer.close()
    await writer.wait_closed()
    return json.loads(response.decode("utf-8"))


def _event_payload(query: str, tool_name: str = "search_kb") -> dict:
    """Build standard test payload."""
    return {"tool_name": tool_name, "tool_params": {"query": query}, "session_id": f"sess-{uuid4().hex}"}


async def test_unix_socket_allows_safe_call(proxy: SidecarProxy, socket_path: str) -> None:
    """Safe socket request should return forward action."""
    result = await _send_socket_request(socket_path, _event_payload("hello"))
    assert result["action"] == "forward"
    assert result["decision"]["decision"] in {"allow", "audit"}


async def test_unix_socket_blocks_sql_injection(proxy: SidecarProxy, socket_path: str) -> None:
    """SQL injection payload should return drop action."""
    payload = _event_payload("DROP TABLE users", tool_name="execute_sql")
    result = await _send_socket_request(socket_path, payload)
    assert result["action"] == "drop"
    assert result["decision"]["rule_id"] == "deny_sql_injection"


async def test_http_fallback_allows_safe_tool(redis_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP fallback should forward safe requests."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    resolver = SPIFFEResolver()
    interceptor = ToolInterceptor(evaluator, resolver)
    emitter = AuditEmitter()
    monkeypatch.setattr(emitter, "_do_emit", _noop_emit)
    app = create_http_fallback(interceptor, emitter, resolver)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/evaluate", json=_event_payload("hello"))
    assert response.status_code == 200
    assert response.json()["action"] == "forward"
    await evaluator.close()
    await cache.close()


async def test_http_fallback_blocks_sql_injection(redis_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP fallback should drop blocked requests."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    resolver = SPIFFEResolver()
    interceptor = ToolInterceptor(evaluator, resolver)
    emitter = AuditEmitter()
    monkeypatch.setattr(emitter, "_do_emit", _noop_emit)
    app = create_http_fallback(interceptor, emitter, resolver)
    transport = httpx.ASGITransport(app=app)
    payload = _event_payload("DROP TABLE users", tool_name="execute_sql")
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/evaluate", json=payload)
    assert response.status_code == 200
    assert response.json()["action"] == "drop"
    await evaluator.close()
    await cache.close()


async def test_health_endpoint(redis_url: str) -> None:
    """Health check endpoint should return ok."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    resolver = SPIFFEResolver()
    app = create_http_fallback(ToolInterceptor(evaluator, resolver), AuditEmitter(), resolver)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    await evaluator.close()
    await cache.close()


async def test_malformed_socket_request_fails_closed(proxy: SidecarProxy, socket_path: str) -> None:
    """Malformed JSON must fail CLOSED (drop), not forward — no enforcement bypass on errors."""
    reader, writer = await asyncio.open_unix_connection(socket_path)
    writer.write(b"not-json\n")
    await writer.drain()
    response = await reader.readline()
    writer.close()
    await writer.wait_closed()
    body = json.loads(response.decode("utf-8"))
    assert body["action"] == "drop"
    assert "error" in body


async def test_graceful_shutdown_closes_server(socket_path: str, monkeypatch: pytest.MonkeyPatch, redis_url: str) -> None:
    """Proxy should stop cleanly and close socket listener."""
    if not HAS_UNIX_SOCKETS:
        pytest.skip("Unix sockets are not supported on this platform")
    cache = RedisCache(url=redis_url)
    monkeypatch.setattr("norviq.sidecar.proxy.RedisCache", lambda: cache)
    monkeypatch.setattr("norviq.sidecar.proxy.AuditEmitter.init", _noop_emit_init)
    proxy = SidecarProxy(socket_path=socket_path)
    await proxy.start()
    monkeypatch.setattr(proxy._emitter, "_do_emit", _noop_emit)
    await _send_socket_request(socket_path, _event_payload("hello"))
    await proxy.stop()
    with pytest.raises((ConnectionRefusedError, FileNotFoundError)):
        await asyncio.open_unix_connection(socket_path)


async def test_sidecar_main_starts_proxy_and_http_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Main entrypoint should start Unix proxy and HTTP fallback server."""

    class StubProxy:
        def __init__(self) -> None:
            self._interceptor = object()
            self._emitter = object()
            self._resolver = object()
            self.started = False
            self.stopped = False

        async def start(self) -> None:
            self.started = True

        async def stop(self) -> None:
            self.stopped = True

    class StubServer:
        def __init__(self, _: object) -> None:
            self.served = False

        async def serve(self) -> None:
            self.served = True
            return None

    created: dict[str, object] = {}

    def _proxy_factory() -> StubProxy:
        proxy = StubProxy()
        created["proxy"] = proxy
        return proxy

    def _create_http_fallback(interceptor: object, emitter: object, resolver: object) -> object:
        created["interceptor"] = interceptor
        created["emitter"] = emitter
        created["resolver"] = resolver
        created["app"] = object()
        return created["app"]

    monkeypatch.setattr(sidecar_main, "SidecarProxy", _proxy_factory)
    monkeypatch.setattr(sidecar_main, "create_http_fallback", _create_http_fallback)
    monkeypatch.setattr(sidecar_main.uvicorn, "Config", lambda app, **kwargs: {"app": app, **kwargs})
    monkeypatch.setattr(sidecar_main.uvicorn, "Server", lambda config: StubServer(config))

    await sidecar_main.main()

    proxy = created["proxy"]
    assert isinstance(proxy, StubProxy)
    assert proxy.started is True
    assert proxy.stopped is True
    assert created["app"] is not None
    assert created["interceptor"] is proxy._interceptor
    assert created["emitter"] is proxy._emitter
    assert created["resolver"] is proxy._resolver


async def test_http_fallback_malformed_json_fails_closed() -> None:
    """Malformed HTTP body must fail CLOSED (drop), not forward."""

    class StubDecision:
        def is_allowed(self) -> bool:
            return True

        def model_dump(self, mode: str = "json") -> dict[str, str]:
            return {"decision": "allow"}

    class StubInterceptor:
        async def intercept(self, *_: object, **__: object) -> StubDecision:
            return StubDecision()

    class StubResolver:
        async def resolve(self) -> object:
            class _Identity:
                trust_domain = "example.org"
                namespace = "default"
                service_account = "sa"

            return _Identity()

    class StubEmitter:
        def emit(self, *_: object, **__: object) -> None:
            return None

    app = create_http_fallback(StubInterceptor(), StubEmitter(), StubResolver())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/v1/evaluate", content="not-json", headers={"content-type": "application/json"})
    assert response.status_code == 200
    assert response.json()["action"] == "drop"
    assert response.json()["error"] == "invalid_json_body"
