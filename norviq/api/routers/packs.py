# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F047 sector starter policy packs — catalog + enable/disable.

GET  /policy-packs            -> the bundled catalog (from policies/sector/packs.json) with per-namespace
                                 enabled state.
POST /policy-packs/{id}/enable   (admin) -> materialize the namespace's enabled packs as its
                                 (namespace,'__pack__') policy via the normal policy-create path.
POST /policy-packs/{id}/disable  (admin) -> remove the pack; re-materialize (or delete if none left).

Default-OFF: no (ns,__pack__) policy exists until an admin enables a pack, so the single-cluster path
and the attack namespaces are unchanged unless a pack is enabled for that namespace.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api import packs as pack_lib
from norviq.api.auth import get_current_user, require_admin, scoped_namespace
from norviq.api.routers.settings_router import assert_apply_allowed  # F-51: shared dry-run-only gate
from norviq.api.db.models import NamespacePack
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()

_PACK_KEY = "__pack__"


class PackAction(BaseModel):
    """Enable/disable target namespace."""

    namespace: str = "default"


async def _enabled_ids(session: AsyncSession, namespace: str) -> list[str]:
    """Pack ids currently enabled for a namespace (known packs only)."""
    rows = (
        await session.execute(select(NamespacePack.pack_id).where(NamespacePack.namespace == namespace))
    ).scalars().all()
    return [pid for pid in rows if pack_lib.is_known(pid)]


async def _materialize(request: Request, namespace: str, session: AsyncSession) -> list[str]:
    """Rebuild the (namespace,__pack__) policy from the namespace's enabled packs. Returns the ids."""
    ids = sorted(await _enabled_ids(session, namespace))
    loader = request.app.state.loader
    if ids:
        combined = pack_lib.combine(ids)
        await loader.create(
            namespace,
            _PACK_KEY,
            combined,
            saved_by="sector-pack",
            priority=pack_lib.pack_priority(),
            enforcement_mode="block",
            policy_name="sector-packs:" + ",".join(ids),
        )
    else:
        await loader.delete(namespace, _PACK_KEY)
    # A pack affects EVERY agent class in the namespace, so invalidate the whole namespace's eval cache
    # (loader.create/delete only clears the (ns,__pack__) scope) — the change takes effect immediately.
    cache = getattr(loader, "_cache", None)
    if cache is not None:
        await cache.invalidate_eval_scope(namespace)
    return ids


@router.get("/policy-packs")
async def list_packs(
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """The sector-pack catalog with enabled-per-namespace state (RBAC-scoped)."""
    namespace = scoped_namespace(user, namespace) or "default"
    enabled = set(await _enabled_ids(session, namespace))
    rows = [{**row, "enabled": row["id"] in enabled, "namespace": namespace} for row in pack_lib.catalog()]
    log.info("nrvq.api.packs.listed", namespace=namespace, count=len(rows), enabled=len(enabled),
             code="NRVQ-API-7094")
    return rows


@router.post("/policy-packs/{pack_id}/enable")
async def enable_pack(
    pack_id: str,
    body: PackAction,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Enable a sector pack for a namespace (admin-only, idempotent, audited)."""
    require_admin(user)
    if not pack_lib.is_known(pack_id):
        log.warning("nrvq.api.pack.error", pack_id=pack_id, reason="unknown", code="NRVQ-API-7097")
        raise HTTPException(status_code=404, detail="Unknown pack id")
    namespace = scoped_namespace(user, body.namespace) or "default"
    await assert_apply_allowed(session, namespace)  # F-51: a dry-run-only namespace rejects pack applies too
    existing = (
        await session.execute(
            select(NamespacePack).where(NamespacePack.namespace == namespace, NamespacePack.pack_id == pack_id)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(NamespacePack(namespace=namespace, pack_id=pack_id, enabled_by=str(user.get("sub", ""))))
        await session.commit()
    ids = await _materialize(request, namespace, session)
    log.info("nrvq.api.pack.enabled", namespace=namespace, pack_id=pack_id, enabled=ids,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7095")
    return {"namespace": namespace, "pack_id": pack_id, "enabled": True, "enabled_packs": ids}


@router.post("/policy-packs/{pack_id}/disable")
async def disable_pack(
    pack_id: str,
    body: PackAction,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Disable a sector pack for a namespace (admin-only, idempotent, audited)."""
    require_admin(user)
    namespace = scoped_namespace(user, body.namespace) or "default"
    await session.execute(
        sql_delete(NamespacePack).where(NamespacePack.namespace == namespace, NamespacePack.pack_id == pack_id)
    )
    await session.commit()
    ids = await _materialize(request, namespace, session)
    log.info("nrvq.api.pack.disabled", namespace=namespace, pack_id=pack_id, enabled=ids,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7096")
    return {"namespace": namespace, "pack_id": pack_id, "enabled": False, "enabled_packs": ids}
