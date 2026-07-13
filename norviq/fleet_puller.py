# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Spoke-side signed-bundle puller (F045 P2). Pulls the per-cluster bundle from the hub, VERIFIES its
signature against the trust-root pubkey, and applies it to local enforcement via the PolicyLoader.

FAIL-CLOSED + fire-and-forget: any failure (bad signature, tamper, expired, older version, malformed,
hub down) is logged and the loop RETURNS before touching enforcement — the last good bundle stays
applied, never downgraded, never opened up. Strictly off the evaluate/OPA hot path."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from jose import jwt
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from norviq.api.db.models import FleetBundleState
from norviq.api.db.session import get_session
from norviq.config import settings
from norviq.fleet.bundle import BundleVerifyError, canonical_bytes, parse_rfc3339, verify_bundle
from norviq.fleet.oidc_cc import ClientCredentialsToken

log = structlog.get_logger()


class FleetPolicyPuller:
    """Periodically pull+verify+apply the signed fleet policy bundle (no-op unless configured)."""

    def __init__(self, loader=None, session_factory=get_session, client: httpx.AsyncClient | None = None) -> None:
        self._loader = loader
        self._session_factory = session_factory
        self._client = client
        self._owns_client = client is None
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._token: ClientCredentialsToken | None = None

    async def start(self) -> None:
        """Launch the pull loop. No-op unless fleet is enabled, configured, AND a trust-root pubkey is set."""
        if self._task is not None and not self._task.done():
            return  # idempotent: already running (e.g. a second `norviq fleet join`)
        if not settings.fleet_enabled:
            return
        if not (settings.fleet_api_url and settings.fleet_cluster_id):
            return
        if not settings.fleet_bundle_pubkey:
            # FAIL-CLOSED: no trust root -> never apply any bundle (do not "trust the hub").
            log.warning("nrvq.fleet.puller_no_trust_root", code="NRVQ-FLT-15016")
            return
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)
        if settings.fleet_oidc_token_url:
            self._token = ClientCredentialsToken(self._client)
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info("nrvq.fleet.puller_started", cluster=settings.fleet_cluster_id, code="NRVQ-FLT-15016")

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await self.pull_once()
            except Exception as exc:  # pragma: no cover - network/DB transient; fire-and-forget
                log.error("nrvq.fleet.pull_failed", error=str(exc), code="NRVQ-FLT-15016")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=settings.fleet_pull_interval_s)
            except asyncio.TimeoutError:
                pass

    async def _bearer(self) -> str:
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

    async def pull_once(self) -> dict:
        """Pull -> verify -> temporal -> version -> apply -> persist -> report. Returns the outcome."""
        headers = {"Authorization": f"Bearer {await self._bearer()}"}
        resp = await self._client.get(f"{self._base()}/bundle", headers=headers)
        resp.raise_for_status()  # hub down/5xx -> raise -> _run logs, last-good kept, enforcement unaffected
        body = resp.json()

        # (1)+(2) signature + payload integrity (fail-closed on ANY failure)
        try:
            payload = verify_bundle(body, settings.fleet_bundle_pubkey)
        except BundleVerifyError as exc:
            log.warning("nrvq.fleet.bundle_verify_failed", error=str(exc), code="NRVQ-FLT-15018")
            return {"applied": False, "reason": "verify_failed"}
        if payload.get("cluster_id") != settings.fleet_cluster_id:
            log.warning("nrvq.fleet.bundle_wrong_cluster", code="NRVQ-FLT-15018")
            return {"applied": False, "reason": "wrong_cluster"}

        # (3) temporal window
        now = datetime.now(timezone.utc)
        if now < parse_rfc3339(payload["not_before"]):
            log.warning("nrvq.fleet.bundle_not_yet_valid", code="NRVQ-FLT-15019")
            return {"applied": False, "reason": "not_before"}
        if now > parse_rfc3339(payload["expires_at"]):
            log.warning("nrvq.fleet.bundle_expired", code="NRVQ-FLT-15019")
            return {"applied": False, "reason": "expired"}

        # (4) monotonic / replay-rollback
        version = int(payload["bundle_version"])
        last = await self._last_applied()
        if version <= last:
            log.debug("nrvq.fleet.bundle_not_newer", version=version, last=last, code="NRVQ-FLT-15017")
            return {"applied": False, "reason": "not_newer"}

        # (5) APPLY — only now do we touch enforcement. A per-policy failure -> report failed, do NOT bump.
        new_manifest = sorted(f"{p['namespace']}:{p['agent_class']}" for p in payload["policies"])
        try:
            for p in payload["policies"]:
                await self._loader.create(p["namespace"], p["agent_class"], p["rego_source"],
                                          saved_by=f"fleet:bundle:{version}", priority=p.get("priority", 100),
                                          enforcement_mode=p.get("enforcement_mode", "block"))
            # F-52 RECONCILE: a policy that was applied from a prior bundle but is no longer present has been
            # RETRACTED — delete it from the spoke so a push is reversible (was: dropped policies persisted forever).
            for key in await self._dropped_keys(new_manifest):
                ns, _, ac = key.partition(":")
                await self._loader.delete(ns, ac)
                log.info("nrvq.fleet.bundle_retracted", key=key, version=version, code="NRVQ-FLT-15028")
        except Exception as exc:
            log.error("nrvq.fleet.bundle_apply_failed", error=str(exc), code="NRVQ-FLT-15022")
            await self._report(version, "failed", last, str(exc)[:200])
            return {"applied": False, "reason": "apply_failed"}

        # (6) persist version + manifest ONLY after the full apply+reconcile succeeds (partial -> re-applies next cycle)
        await self._persist(version, hashlib.sha256(canonical_bytes(payload)).hexdigest(), new_manifest)
        log.info("nrvq.fleet.bundle_applied", version=version, policies=len(payload["policies"]), code="NRVQ-FLT-15022")
        await self._report(version, "applied", version, "")
        return {"applied": True, "version": version}

    async def _dropped_keys(self, new_manifest: list[str]) -> list[str]:
        """F-52: keys applied from the LAST bundle that are absent from the new one (i.e. retracted)."""
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            row = (await session.execute(
                select(FleetBundleState).where(FleetBundleState.cluster_id == settings.fleet_cluster_id)
            )).scalar_one_or_none()
            prior = json.loads(row.last_manifest) if row and row.last_manifest else []
            return [k for k in prior if k not in set(new_manifest)]
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

    async def _last_applied(self) -> int:
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            row = (await session.execute(
                select(FleetBundleState).where(FleetBundleState.cluster_id == settings.fleet_cluster_id)
            )).scalar_one_or_none()
            return row.last_applied_version if row else 0
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

    async def _persist(self, version: int, sha: str, manifest: list[str]) -> None:
        provider = self._session_factory()
        session = await provider.__anext__()
        try:
            now = datetime.now(timezone.utc)
            man = json.dumps(manifest)
            await session.execute(insert(FleetBundleState).values(
                cluster_id=settings.fleet_cluster_id, last_applied_version=version, applied_at=now,
                last_bundle_sha256=sha, last_manifest=man,
            ).on_conflict_do_update(
                index_elements=["cluster_id"],
                set_={"last_applied_version": version, "applied_at": now, "last_bundle_sha256": sha, "last_manifest": man},
            ))
            await session.commit()
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

    async def _report(self, version: int, state: str, applied_version: int, detail: str) -> None:
        try:
            headers = {"Authorization": f"Bearer {await self._bearer()}"}
            await self._client.post(f"{self._base()}/rollout", headers=headers, json={
                "bundle_version": version, "state": state, "applied_version": applied_version, "detail": detail,
            })
            log.debug("nrvq.fleet.rollout_reported", state=state, code="NRVQ-FLT-15020")
        except Exception as exc:  # pragma: no cover - best-effort
            log.debug("nrvq.fleet.rollout_report_failed", error=str(exc), code="NRVQ-FLT-15020")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
