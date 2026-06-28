# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async client for a long-lived OPA server (replaces the per-call `opa eval` fork).

Two connection models:
  * `NRVQ_OPA_URL` set  -> talk to that base URL (the in-pod OPA sidecar at localhost:8181).
  * `NRVQ_OPA_URL` empty -> spawn ONE managed `opa run --server --v0-compatible` per process
    (local/dev/tests) and reuse it across every OpaClient instance.

Policies are pushed (mirrored) into OPA; evaluation is a `POST /v1/data/<pkg-path>` with the input
document. The evaluator owns one OpaClient and fails CLOSED on any OPA error (see evaluator.py).
"""

from __future__ import annotations

import asyncio
import atexit
import re
import shutil

import httpx
import structlog

from norviq.config import settings

log = structlog.get_logger()

_PACKAGE_RE = re.compile(r"(?m)^\s*package\s+[A-Za-z0-9_.]+\s*$")
_SANITIZE_RE = re.compile(r"[^A-Za-z0-9]+")


def sanitize_key(key: str) -> str:
    """Turn a '<ns>:<class>' policy key into a valid Rego identifier segment."""
    cleaned = _SANITIZE_RE.sub("_", key).strip("_")
    return cleaned or "default"


def managed_package(key: str) -> str:
    """Unique per-policy package so distinct policies never merge in the shared server."""
    return f"norviq.managed.{sanitize_key(key)}"


def rewrite_package(rego_source: str, package_name: str) -> str:
    """Replace the policy's `package` declaration with `package_name` (isolation, parity-safe)."""
    if _PACKAGE_RE.search(rego_source):
        return _PACKAGE_RE.sub(f"package {package_name}", rego_source, count=1)
    return f"package {package_name}\n{rego_source}"


def data_path(package_name: str) -> str:
    """Convert a dotted package to the OPA Data API path (dots -> slashes)."""
    return package_name.replace(".", "/")


class _ManagedServer:
    """Process-wide singleton wrapping one spawned `opa run --server` (shared by all clients)."""

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def ensure(self, addr: str) -> None:
        """Spawn the managed OPA server once and wait until it is healthy (idempotent)."""
        if self._proc is not None and self._proc.returncode is None:
            return
        async with self._lock:
            if self._proc is not None and self._proc.returncode is None:
                return
            if shutil.which("opa") is None:
                raise RuntimeError("opa binary not found on PATH (required for managed OPA server)")
            host, _, port = addr.partition(":")
            self._proc = await asyncio.create_subprocess_exec(
                "opa", "run", "--server", "--v0-compatible",
                "--addr", addr, "--log-level", "error",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await self._wait_healthy(f"http://{host or '127.0.0.1'}:{port or '8181'}")
            log.info("nrvq.opa.server_started", addr=addr, pid=self._proc.pid, code="NRVQ-ENG-2052")

    async def _wait_healthy(self, base_url: str, attempts: int = 50) -> None:
        """Poll /health until the spawned server answers (≈5s budget)."""
        async with httpx.AsyncClient(base_url=base_url, timeout=1.0) as probe:
            for _ in range(attempts):
                if self._proc is not None and self._proc.returncode is not None:
                    raise RuntimeError("managed OPA server exited during startup")
                try:
                    resp = await probe.get("/health")
                    if resp.status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.1)
        raise RuntimeError("managed OPA server did not become healthy in time")

    def terminate(self) -> None:
        """Best-effort synchronous kill for atexit / shutdown."""
        if self._proc is not None and self._proc.returncode is None:
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass


_MANAGED = _ManagedServer()
atexit.register(_MANAGED.terminate)


class OpaClient:
    """Push policies to and evaluate against a long-lived OPA server."""

    def __init__(self) -> None:
        """Resolve the base URL and whether we manage the server lifecycle."""
        self._managed = not settings.opa_url
        self._base_url = (settings.opa_url or f"http://{settings.opa_addr}").rstrip("/")
        self._timeout = settings.opa_timeout_ms / 1000.0
        self._client: httpx.AsyncClient | None = None
        self._start_lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        """Resolved OPA base URL."""
        return self._base_url

    async def start(self) -> None:
        """Ensure the managed server (if any) is up and the HTTP client exists (idempotent)."""
        async with self._start_lock:
            if self._managed:
                await _MANAGED.ensure(settings.opa_addr)
            if self._client is None:
                limits = httpx.Limits(max_connections=64, max_keepalive_connections=32)
                self._client = httpx.AsyncClient(base_url=self._base_url, timeout=self._timeout, limits=limits)

    async def _ensure(self) -> httpx.AsyncClient:
        """Lazy-start so directly-instantiated evaluators work without lifespan wiring."""
        if self._client is None or (self._managed and (_MANAGED._proc is None or _MANAGED._proc.returncode is not None)):
            await self.start()
        assert self._client is not None
        return self._client

    async def push_policy(self, module_id: str, rego_source: str) -> None:
        """Mirror a (already package-rewritten) policy module into OPA via the Policy API."""
        client = await self._ensure()
        resp = await client.put(f"/v1/policies/{module_id}", content=rego_source.encode("utf-8"),
                                headers={"Content-Type": "text/plain"})
        if resp.status_code >= 300:
            log.error("nrvq.opa.push_failed", module_id=module_id, status=resp.status_code,
                      body=resp.text[:300], code="NRVQ-ENG-2054")
            raise RuntimeError(f"OPA policy push failed for {module_id}: {resp.status_code}")
        log.info("nrvq.opa.policy_pushed", module_id=module_id, code="NRVQ-ENG-2053")

    async def delete_policy(self, module_id: str) -> None:
        """Remove a policy module from OPA (best-effort)."""
        client = await self._ensure()
        try:
            await client.delete(f"/v1/policies/{module_id}")
        except httpx.HTTPError as exc:  # pragma: no cover - best effort
            log.error("nrvq.opa.delete_failed", module_id=module_id, error=str(exc), code="NRVQ-ENG-2054")

    async def query(self, package_name: str, opa_input: dict) -> dict | None:
        """Evaluate input against a package; returns the decision object or None if undefined."""
        client = await self._ensure()
        resp = await client.post(f"/v1/data/{data_path(package_name)}", json={"input": opa_input})
        resp.raise_for_status()
        body = resp.json()
        return body.get("result") if isinstance(body, dict) else None

    async def health(self) -> bool:
        """Return True when the OPA server answers /health with 200."""
        try:
            client = await self._ensure()
            resp = await client.get("/health")
            return resp.status_code == 200
        except Exception:  # pragma: no cover - readiness probe path
            return False

    async def stop(self) -> None:
        """Close the HTTP client. Leaves the shared managed server for other clients / atexit."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def shutdown_managed_opa() -> None:
    """Terminate the process-wide managed OPA server (called from API lifespan shutdown)."""
    _MANAGED.terminate()
