# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Spoke-side fleet relay (F045): periodically pushes agent + audit ROLLUPS to the hub fleet-api.

Mirrors the SIEM AuditForwarder exactly. Runs in-process in the spoke API as a background task, gated
by `fleet_enabled`. STRICTLY off the enforce hot path and fire-and-forget: any failure (DB read, token,
hub 5xx/timeout) is only logged — a hub outage NEVER affects local enforcement; fleet views degrade.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from jose import jwt
from sqlalchemy import func, select

from norviq.api.db.models import AgentRegistryEntry, AuditLogEntry
from norviq.api.db.session import get_session
from norviq.config import settings
from norviq.fleet.oidc_cc import ClientCredentialsToken

log = structlog.get_logger()

# Re-aggregate a trailing window each cycle so a dropped POST self-heals (hub upsert is SET-absolute).
_AUDIT_WINDOW_HOURS = 2


class FleetRelayForwarder:
    """Periodically heartbeats + pushes agent/audit rollups to the hub (no-op unless fleet_enabled)."""

    def __init__(self, session_factory=get_session, client: httpx.AsyncClient | None = None) -> None:
        self._session_factory = session_factory
        self._client = client
        self._owns_client = client is None
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._token: ClientCredentialsToken | None = None

    async def start(self) -> None:
        """Launch the relay loop when enabled + configured (else a no-op)."""
        if self._task is not None and not self._task.done():
            return  # idempotent: already running
        if not settings.fleet_enabled:
            return
        if not (settings.fleet_api_url and settings.fleet_cluster_id):
            log.warning("nrvq.fleet.relay_not_configured", code="NRVQ-FLT-15010")
            return
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        if settings.fleet_oidc_token_url:
            self._token = ClientCredentialsToken(self._client)
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info("nrvq.fleet.relay_started", url=settings.fleet_api_url, cluster=settings.fleet_cluster_id,
                 code="NRVQ-FLT-15000")

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await self.relay_once()
            except Exception as exc:  # pragma: no cover - network/DB transient; fire-and-forget
                log.error("nrvq.fleet.relay_failed", error=str(exc), code="NRVQ-FLT-15001")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.fleet_relay_interval_s)
            except asyncio.TimeoutError:
                pass

    async def _bearer(self) -> str:
        """Hub auth: OIDC client-credentials if configured, else a self-minted HS256 service token."""
        if self._token is not None:
            return await self._token.bearer()
        if settings.legacy_hs256_enabled:
            now = datetime.now(timezone.utc)
            claims = {"sub": "norviq-relay", "role": "service", "cluster": settings.fleet_cluster_id,
                      "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=1)).timestamp())}
            return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")
        return ""

    def _base(self) -> str:
        return settings.fleet_api_url.rstrip("/") + f"/api/v1/fleet/clusters/{settings.fleet_cluster_id}"

    async def _spiffe_id(self) -> str:
        """S3: this spoke's attested SPIFFE id (workload-api mode only; mock id is not bindable)."""
        if settings.spiffe_mode != "workload-api":
            return ""
        try:
            from norviq.engine.identity import SPIFFEResolver
            return (await SPIFFEResolver().resolve()).spiffe_id
        except Exception:  # pragma: no cover - SVID unavailable -> just skip the binding (bearer still auths)
            return ""

    async def relay_once(self) -> dict:
        """Heartbeat + push agent/audit rollups. Returns the rollup counts."""
        headers = {"Authorization": f"Bearer {await self._bearer()}"}
        # (a) heartbeat (advertise labels for policy targeting, residency, and the attested SPIFFE identity)
        hb = await self._client.post(f"{self._base()}/heartbeat", headers=headers, json={
            "name": settings.fleet_cluster_name, "endpoint": settings.fleet_cluster_endpoint,
            "region": settings.fleet_cluster_region, "labels": settings.fleet_cluster_labels,
            "residency": settings.fleet_residency, "spiffe_id": await self._spiffe_id(),
            "console_url": settings.fleet_cluster_console_url,  # F-69: advertise this cluster's own console URL
        })
        hb.raise_for_status()
        log.debug("nrvq.fleet.heartbeat_sent", code="NRVQ-FLT-15002")
        # (b) + (c) aggregate from the SPOKE DB
        agents, audit = await self._aggregate()
        resp = await self._client.post(f"{self._base()}/rollup", headers=headers, json={"agents": agents, "audit": audit})
        resp.raise_for_status()
        log.info("nrvq.fleet.relay_pushed", agents=len(agents), audit=len(audit), code="NRVQ-FLT-15000")
        return {"agents": len(agents), "audit": len(audit)}

    async def _aggregate(self) -> tuple[list[dict], list[dict]]:
        """Read agent_registry rows + aggregate audit_log into hourly decision counters."""
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            agents = [{
                "spiffe_id": e.spiffe_id, "namespace": e.namespace, "agent_class": e.agent_class,
                "trust_score": e.trust_score, "trust_category": e.trust_category,
                "last_seen": e.last_seen.isoformat() if e.last_seen else None,
            } for e in (await session.execute(select(AgentRegistryEntry))).scalars().all()]

            bucket = func.date_trunc("hour", AuditLogEntry.timestamp_utc).label("bucket_ts")
            since = datetime.now(timezone.utc) - timedelta(hours=_AUDIT_WINDOW_HOURS)
            stmt = (
                select(AuditLogEntry.namespace, bucket, AuditLogEntry.decision, func.count(AuditLogEntry.id).label("count"))
                .where(AuditLogEntry.timestamp_utc >= since)
                .group_by(AuditLogEntry.namespace, bucket, AuditLogEntry.decision)
            )
            audit = [{
                "namespace": ns, "bucket_ts": b.isoformat(), "decision": d, "count": int(cnt),
            } for ns, b, d, cnt in (await session.execute(stmt)).all()]
            return agents, audit
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

    async def stop(self) -> None:
        """Signal the loop to stop, await it, and close an owned HTTP client."""
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
