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
# Hard ceiling on how long an identity may be reused without re-consulting the Workload API. Shorter
# than any plausible SVID lifetime, so this cache can never be the reason a rotation or revocation is
# missed. See SPIFFEResolver._cache_ttl for why this is clamped rather than trusted.
_MAX_CACHE_TTL = 300
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

    def _cache_ttl(self) -> int:
        """How long a resolved identity may be reused, BOUNDED.

        Two problems this replaces, both invisible until you look for them.

        1. `_CACHE_TTL` was a module constant bound at import, so `NRVQ_SPIFFE_CACHE_TTL_S` had no
           effect on a process that had already imported this module — the knob silently did nothing.
        2. The value was unbounded. An operator raising it to an hour or a day does not get a faster
           cache; they get SVID ROTATION TURNED OFF. The Workload API is never consulted again for the
           whole window, so a workload whose SVID has rotated — or been REVOKED — keeps enforcing under
           its previous identity, which is what every policy decision, trust score and the
           `agent_frozen` kill-switch are keyed on.

        The ceiling is deliberately shorter than any plausible SVID lifetime (SPIRE issues in minutes
        to an hour and rotates at half-life), so the cache can never be the reason a rotation is
        missed. Clamping rather than refusing: an over-long TTL is a misconfiguration, and failing a
        workload's identity resolution over it would be a worse outcome than quietly enforcing a safe
        bound and saying so.
        """
        configured = int(getattr(settings, "spiffe_cache_ttl_s", _CACHE_TTL) or _CACHE_TTL)
        if configured > _MAX_CACHE_TTL:
            log.warning(
                "nrvq.identity.cache_ttl_clamped",
                configured_s=configured,
                enforced_s=_MAX_CACHE_TTL,
                code="NRVQ-IDT-10007",
            )
            return _MAX_CACHE_TTL
        return max(0, configured)

    def _get_cached(self) -> AgentIdentity | None:
        """Return cached identity if still valid.

        Drops EVERY expired entry before answering, and answers only when exactly one live identity
        remains. The previous form returned the first entry inside its window while iterating a dict
        keyed by spiffe_id — the key was never consulted, so with two identities present the answer
        depended on insertion order. One attested identity per workload is the invariant; anything else
        means the workload's identity changed under us, and the honest response is to re-resolve rather
        than to pick one.
        """
        now = time.monotonic()
        ttl = self._cache_ttl()
        for spiffe_id, (_identity, ts) in tuple(self._cache.items()):
            if now - ts >= ttl:
                del self._cache[spiffe_id]
        if len(self._cache) != 1:
            return None
        return next(iter(self._cache.values()))[0]

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
            # The Deployment this pod belongs to, injected as NRVQ_WORKLOAD by the admission webhook
            # (workloadFromPod, webhook/injector.go) from the pod's OWNER reference — not from its name.
            # Nothing set this before, on any production path, so `_collect_candidates`' workload tier
            # (`<ns>:deployment:<workload>`) never matched a single call while the console, the CRD and
            # the CLI all offered workload-scoped policies and reported them Active. Absent when the pod
            # has no resolvable owner, in which case the tier correctly does not apply.
            workload=os.environ.get("NRVQ_WORKLOAD", ""),
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
            workload=os.environ.get("NRVQ_WORKLOAD", ""),
        )

    def _fallback_identity(self) -> AgentIdentity:
        """Return a minimal identity when resolution fails."""
        log.warning("nrvq.identity.fallback", code="NRVQ-IDT-10003")
        return AgentIdentity(spiffe_id="spiffe://norviq/ns/unknown/sa/unknown", namespace="unknown")

    def clear_cache(self) -> None:
        """Clear the identity cache."""
        self._cache.clear()
