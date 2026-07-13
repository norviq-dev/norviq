# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SPIFFE identity resolution for runtime workloads."""

from __future__ import annotations

import asyncio
import os
import time

import structlog

from norviq.config import settings
from norviq.sdk.core.events import AgentIdentity

# pyspiffe is an optional extra (`pip install '.[spiffe]'`); only the workload-api mode needs it.
# Import-guarded so mock mode (default) imports cleanly without it installed (CI/dev/attack venvs).
try:  # pragma: no cover - exercised only where pyspiffe is installed
    from spiffe import WorkloadApiClient  # type: ignore

    _PYSPIFFE_AVAILABLE = True
except ImportError:  # pragma: no cover
    WorkloadApiClient = None  # type: ignore
    _PYSPIFFE_AVAILABLE = False

log = structlog.get_logger()
_CACHE_TTL = settings.spiffe_cache_ttl_s
_TRUST_DOMAIN = "norviq"


class SpiffeResolutionError(RuntimeError):
    """Raised in workload-api mode when an SVID cannot be fetched/validated (fail-closed)."""


def _parse_norviq_spiffe_id(spiffe_id: str) -> tuple[str, str] | None:
    """Parse spiffe://norviq/ns/<ns>/sa/<sa> -> (namespace, service_account); None if not ours."""
    prefix = f"spiffe://{_TRUST_DOMAIN}/"
    if not spiffe_id.startswith(prefix):
        return None
    parts = spiffe_id[len(prefix):].split("/")
    if len(parts) == 4 and parts[0] == "ns" and parts[2] == "sa" and parts[1] and parts[3]:
        return parts[1], parts[3]
    return None


class SPIFFEResolver:
    """Resolves workload identity via SPIFFE Workload API or mock."""

    def __init__(self, socket_path: str | None = None) -> None:
        self._socket_path = socket_path or settings.spiffe_socket
        self._cache: dict[str, tuple[AgentIdentity, float]] = {}
        self._lock = asyncio.Lock()

    async def resolve(self) -> AgentIdentity:
        """Resolve the current workload's SPIFFE identity."""
        cached = self._get_cached()
        if cached is not None:
            log.debug("nrvq.identity.cache_hit", spiffe_id=cached.spiffe_id, code="NRVQ-IDT-10001")
            return cached
        async with self._lock:
            cached = self._get_cached()
            if cached is not None:
                log.debug("nrvq.identity.cache_hit", spiffe_id=cached.spiffe_id, code="NRVQ-IDT-10001")
                return cached
            identity = await self._resolve_from_socket()
            self._cache[identity.spiffe_id] = (identity, time.monotonic())
            log.info("nrvq.identity.resolved", spiffe_id=identity.spiffe_id, code="NRVQ-IDT-10000")
            return identity

    def _get_cached(self) -> AgentIdentity | None:
        """Return cached identity if still valid."""
        now = time.monotonic()
        for spiffe_id, (identity, ts) in tuple(self._cache.items()):
            if now - ts < _CACHE_TTL:
                return identity
            del self._cache[spiffe_id]
        return None

    async def _resolve_from_socket(self) -> AgentIdentity:
        """Resolve identity by mode: real Workload API SVID (fail-closed) or env-var mock."""
        if settings.spiffe_mode == "workload-api":
            return self._resolve_workload_api()  # FAIL-CLOSED: raises on any error, no fallback
        try:
            return self._mock_resolve()
        except Exception as exc:
            log.error("nrvq.identity.resolve_failed", error=str(exc), code="NRVQ-IDT-10002")
            return self._fallback_identity()

    def _svid_source(self):
        """Return a SPIFFE Workload API client (the unit-test seam — monkeypatch to inject a fake)."""
        if not _PYSPIFFE_AVAILABLE:
            raise SpiffeResolutionError("pyspiffe not installed; install the 'spiffe' extra for workload-api mode")
        # pyspiffe requires the `unix://` scheme; accept a bare path in config and normalize here.
        sock = self._socket_path if "://" in self._socket_path else f"unix://{self._socket_path}"
        return WorkloadApiClient(socket_path=sock)

    def _resolve_workload_api(self) -> AgentIdentity:
        """Fetch + validate the X509-SVID. SVID wins over env (spoof-resistant); fail-closed on error."""
        source = None
        try:
            source = self._svid_source()
            svid = source.fetch_x509_svid()
            spiffe_id = str(svid.spiffe_id)  # X509Svid.spiffe_id is a property returning a SpiffeId
        except SpiffeResolutionError:
            raise
        except Exception as exc:
            log.error("nrvq.identity.socket_unreachable", error=str(exc), code="NRVQ-IDT-10006")
            raise SpiffeResolutionError(f"Workload API unreachable: {exc}") from exc
        finally:
            close = getattr(source, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # pragma: no cover - best-effort channel cleanup
                    pass
        parsed = _parse_norviq_spiffe_id(spiffe_id)
        if parsed is None:
            log.error("nrvq.identity.svid_invalid", spiffe_id=spiffe_id, code="NRVQ-IDT-10005")
            raise SpiffeResolutionError(f"SVID not in trust domain '{_TRUST_DOMAIN}': {spiffe_id}")
        namespace, service_account = parsed  # from the attested SVID ONLY — env is never read here
        log.info("nrvq.identity.workload_resolved", spiffe_id=spiffe_id, code="NRVQ-IDT-10004")
        return AgentIdentity(
            spiffe_id=spiffe_id,
            namespace=namespace,
            service_account=service_account,
            agent_class=os.environ.get("NRVQ_AGENT_CLASS", "default"),
            pod_name=os.environ.get("HOSTNAME", "unknown-pod"),
        )

    def _mock_resolve(self) -> AgentIdentity:
        """MVP mock: generate identity from environment/config."""
        namespace = os.environ.get("NRVQ_NAMESPACE", "default")
        service_account = os.environ.get("NRVQ_SERVICE_ACCOUNT", "default")
        pod_name = os.environ.get("HOSTNAME", "unknown-pod")
        agent_class = os.environ.get("NRVQ_AGENT_CLASS", "default")
        spiffe_id = f"spiffe://norviq/ns/{namespace}/sa/{service_account}"
        return AgentIdentity(
            spiffe_id=spiffe_id,
            namespace=namespace,
            service_account=service_account,
            agent_class=agent_class,
            pod_name=pod_name,
        )

    def _fallback_identity(self) -> AgentIdentity:
        """Return a minimal identity when resolution fails."""
        log.warning("nrvq.identity.fallback", code="NRVQ-IDT-10003")
        return AgentIdentity(spiffe_id="spiffe://norviq/ns/unknown/sa/unknown", namespace="unknown")

    def clear_cache(self) -> None:
        """Clear the identity cache."""
        self._cache.clear()
