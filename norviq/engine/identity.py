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

log = structlog.get_logger()
_CACHE_TTL = settings.spiffe_cache_ttl_s


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
        """Connect to SPIFFE Workload API Unix socket and get SVID."""
        try:
            return self._mock_resolve()
        except Exception as exc:
            log.error("nrvq.identity.resolve_failed", error=str(exc), code="NRVQ-IDT-10002")
            return self._fallback_identity()

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
