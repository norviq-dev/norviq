# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Spoke-side fleet ENROLLMENT (single-cluster-first). A plain single-cluster install enrolls into a fleet with one
action — `norviq fleet join <token>` -> POST /api/v1/fleet/join — instead of per-spoke Helm `--set` wiring. The token
(minted by the hub) carries the hub endpoint + cluster_id + bundle PUBLIC key (trust root). Join persists the config
to FleetJoinState (read again at startup) and (re)starts the relay+puller LIVE; leave stops them and sheds any
pushed policy via the F-52 reconcile path. Admin only."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import FleetBundleState, FleetJoinState
from norviq.api.db.session import get_session
from norviq.config import settings
from norviq.fleet.join_token import verify_join_token

log = structlog.get_logger()
router = APIRouter()


class JoinBody(BaseModel):
    token: str


def _apply_settings(*, enabled: bool, cluster_id: str, hub_url: str, pubkey: str) -> None:
    """Mutate the runtime settings the relay/puller read each cycle (config is otherwise env-sourced at startup)."""
    settings.fleet_enabled = enabled
    settings.fleet_cluster_id = cluster_id
    settings.fleet_api_url = hub_url
    settings.fleet_bundle_pubkey = pubkey


async def configure_from_join_state(session: AsyncSession) -> bool:
    """Startup hook: if a join row exists, apply it over env so a token-joined spoke re-enrolls across restarts.
    Returns True if fleet was enabled by the join state."""
    row = (await session.execute(select(FleetJoinState).where(FleetJoinState.id == 1))).scalar_one_or_none()
    if row is None:
        return False
    _apply_settings(enabled=row.enabled, cluster_id=row.cluster_id, hub_url=row.hub_url, pubkey=row.bundle_pubkey)
    return bool(row.enabled)


def _service_token(cluster_id: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": "norviq-join", "role": "service", "cluster": cluster_id,
              "iat": int(now.timestamp()), "exp": int((now + timedelta(minutes=2)).timestamp())}
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


@router.get("/fleet/status")
async def fleet_status(
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """The spoke's current enrollment (single-cluster by default)."""
    _ = user
    row = (await session.execute(select(FleetJoinState).where(FleetJoinState.id == 1))).scalar_one_or_none()
    return {
        "enrolled": bool(row and row.enabled),
        "cluster_id": (row.cluster_id if row else "") or settings.fleet_cluster_id,
        "hub_url": (row.hub_url if row else "") or settings.fleet_api_url,
        "mode": "fleet" if (row and row.enabled) or settings.fleet_enabled else "single-cluster",
    }


@router.post("/fleet/join")
async def fleet_join(
    body: JoinBody,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Enroll this spoke from a hub-minted join token (admin). Verifies the token, claims it single-use at the hub,
    persists the config, and starts the relay+puller live."""
    require_admin(user)
    try:
        payload = verify_join_token(body.token, settings.api_secret_key)
    except ValueError as exc:
        log.warning("nrvq.fleet.join_rejected", error=str(exc), code="NRVQ-FLT-15033")
        raise HTTPException(status_code=422, detail=f"invalid join token: {exc}") from exc
    cluster_id, hub_url, pubkey, jti = payload["cid"], payload["hub"], payload["pub"], payload["jti"]
    # single-use: claim the jti at the hub before we enroll (rejected if expired/already used/wrong cluster).
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                f"{hub_url.rstrip('/')}/api/v1/fleet/clusters/join-token/claim",
                headers={"Authorization": f"Bearer {_service_token(cluster_id)}"},
                json={"jti": jti, "cluster_id": cluster_id},
            )
        if r.status_code != 200:
            raise HTTPException(status_code=409, detail=f"join token claim failed at hub ({r.status_code}): {r.text[:120]}")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"could not reach hub to claim token: {exc}") from exc
    # persist + apply + start.
    row = (await session.execute(select(FleetJoinState).where(FleetJoinState.id == 1))).scalar_one_or_none()
    if row is None:
        row = FleetJoinState(id=1)
        session.add(row)
    row.enabled, row.cluster_id, row.hub_url, row.bundle_pubkey = True, cluster_id, hub_url, pubkey
    # A fresh enrollment must start a CLEAN version lineage: zero any stale last-applied bundle version so the first
    # pull from the (re)joined hub is accepted even if the hub's per-cluster version restarted lower than what this
    # spoke last applied (e.g. the cluster was removed at the hub, resetting its counter, then rejoined). Without this
    # the anti-rollback guard (version <= last_applied -> skip) would reject every bundle and the cluster stays stuck
    # "pending" forever. The puller's F-52 reconcile still drops any policy no longer in the new hub's bundle.
    for stale in (await session.execute(select(FleetBundleState))).scalars().all():
        stale.last_applied_version = 0
        stale.last_bundle_sha256 = ""
    await session.commit()
    _apply_settings(enabled=True, cluster_id=cluster_id, hub_url=hub_url, pubkey=pubkey)
    await request.app.state.fleet_relay.start()
    await request.app.state.fleet_puller.start()
    log.info("nrvq.fleet.joined", cluster_id=cluster_id, hub=hub_url, actor=user.get("sub"), code="NRVQ-FLT-15034")
    return {"enrolled": True, "cluster_id": cluster_id, "hub_url": hub_url}


@router.post("/fleet/leave")
async def fleet_leave(
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """De-enroll this spoke: stop the relay+puller and SHED any fleet-pushed policy (reuse the F-52 reconcile path),
    so it returns to single-cluster AND stops enforcing pushed policy — across restarts (FleetJoinState.enabled=False
    overrides any env fleet config)."""
    require_admin(user)
    row = (await session.execute(select(FleetJoinState).where(FleetJoinState.id == 1))).scalar_one_or_none()
    if row is None:
        row = FleetJoinState(id=1)
        session.add(row)
    row.enabled = False
    # Shed fleet-applied policies recorded in the spoke manifest (F-52 reconcile machinery) AND reset the bundle
    # version lineage: detaching from the fleet must FORGET the last-applied version, so a later re-enrollment is not
    # permanently rejected by the anti-rollback guard if the hub's per-cluster version restarted lower (remove->
    # rejoin). Iterate every row (a spoke may carry state for more than one cluster id across re-enrollments).
    bundles = (await session.execute(select(FleetBundleState))).scalars().all()
    shed = []
    for bundle in bundles:
        if bundle.last_manifest:
            for key in json.loads(bundle.last_manifest):
                ns, _, ac = key.partition(":")
                if await request.app.state.loader.delete(ns, ac):
                    shed.append(key)
        bundle.last_manifest = json.dumps([])
        bundle.last_applied_version = 0
        bundle.last_bundle_sha256 = ""
    await session.commit()
    _apply_settings(enabled=False, cluster_id="", hub_url="", pubkey="")
    await request.app.state.fleet_puller.stop()
    await request.app.state.fleet_relay.stop()
    log.info("nrvq.fleet.left", shed=shed, actor=user.get("sub"), code="NRVQ-FLT-15035")
    return {"enrolled": False, "shed_policies": shed}
