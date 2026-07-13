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
from norviq.api.auth import get_current_user, require_admin, require_target_cluster, scoped_namespace
from norviq.api.routers.policies import validate_rego_source
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
    _target: None = Depends(require_target_cluster),
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
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Disable a sector pack for a namespace (admin-only, idempotent, audited)."""
    require_admin(user)
    namespace = scoped_namespace(user, body.namespace) or "default"
    # L1: disabling a pack REMOVES its blocks — an enforcement-posture change — so it must respect the
    # dry-run-only gate exactly like enable/override (was ungated: a dry-run-only ns could still relax).
    await assert_apply_allowed(session, namespace)
    await session.execute(
        sql_delete(NamespacePack).where(NamespacePack.namespace == namespace, NamespacePack.pack_id == pack_id)
    )
    await session.commit()
    ids = await _materialize(request, namespace, session)
    log.info("nrvq.api.pack.disabled", namespace=namespace, pack_id=pack_id, enabled=ids,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7096")
    return {"namespace": namespace, "pack_id": pack_id, "enabled": False, "enabled_packs": ids}


# --- F-54: view a pack's rego + author a per-namespace tighten-only OVERRIDE (revertable) ---

_OVERRIDE_KEY = "__pack_override__"
_WEAKEN_KEY = "__pack_weaken__"


class PackOverrideBody(BaseModel):
    """Per-namespace pack override. Default = a tighten-only overlay (never weakens a pack's block). With
    allow_weaken=true (the loud, audited Advanced opt-in) it is stored as a WEAKEN overlay that may RELAX a pack's
    added restriction — still floored by the comprehensive baseline (the engine never drops below it)."""

    namespace: str = "default"
    rego_source: str
    allow_weaken: bool = False  # fleet-mgmt: explicit "allow weakening this pack" opt-in (admin; audited)


@router.get("/policy-packs/{pack_id}/rego")
async def get_pack_rego(pack_id: str, user: dict = Depends(get_current_user)) -> dict:
    """F-54: the pack's actual rego source (read-only) so an operator can see what they're customizing."""
    _ = user
    if not pack_lib.is_known(pack_id):
        raise HTTPException(status_code=404, detail="Unknown pack id")
    return {"pack_id": pack_id, "rego": pack_lib.read_rego(pack_id)}


@router.get("/policy-packs/override")
async def get_pack_override(
    namespace: str = Query("default"),
    request: Request = None,
    user: dict = Depends(get_current_user),
) -> dict:
    """F-54: the namespace's current pack override/weaken (empty string if none)."""
    # Scope the read: a non-admin naming another tenant's namespace is refused (403) — the override rego is a
    # tenant's authored policy and must not leak cross-tenant. Parity with the PUT/DELETE override routes, which
    # already scope. (Admin / '*' claim / service-no-claim resolve to the requested namespace unchanged.)
    namespace = scoped_namespace(user, namespace) or "default"
    weaken = request.app.state.loader.get_current(namespace, _WEAKEN_KEY) or ""
    rego = weaken or request.app.state.loader.get_current(namespace, _OVERRIDE_KEY) or ""
    return {"namespace": namespace, "rego_source": rego, "active": bool(rego),
            "mode": "weaken" if weaken else "tighten-only"}


@router.put("/policy-packs/override")
async def put_pack_override(
    body: PackOverrideBody,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """F-54: author/replace the namespace's pack override. It is a TIGHTEN-ONLY overlay (the evaluator caps it so
    it can only make a decision stricter, never weaken/remove a pack's block). Admin; honors the F-51 apply gate;
    validated by compiling against OPA before it goes live."""
    require_admin(user)
    namespace = scoped_namespace(user, body.namespace) or "default"
    await assert_apply_allowed(session, namespace)  # F-51: a dry-run-only namespace rejects override applies too
    # S1/S12: an override is caller-authored rego that reaches the SAME shared OPA server dry-run/create do —
    # it must pass the same size/line/regex caps and forbidden-builtin/cross-package reject (S1), which this
    # endpoint previously skipped entirely. Also covers P1-2 (the decision-resolver shape check): a bare
    # partial-set (no resolver) is rejected here with a specific message instead of silently no-op'ing at
    # runtime — the probe below only fires the override's rules on a matching input.
    validate_rego_source(body.rego_source or "", "block")
    # Validate the rego compiles + yields a decision (reuse the dry-run probe) before it can affect enforcement.
    evaluator = request.app.state.evaluator
    probe = {"tool_name": "____probe____", "tool_params": {}, "agent": {"namespace": namespace, "agent_class": "x"},
             "trust_score": 1.0, "call_depth": 0}
    # The weaken overlay and the tighten-only override are mutually exclusive — clear the other so a save replaces it.
    key = _WEAKEN_KEY if body.allow_weaken else _OVERRIDE_KEY
    other = _OVERRIDE_KEY if body.allow_weaken else _WEAKEN_KEY
    try:
        res = await evaluator._evaluate_opa(f"override-validate:{namespace}", namespace, key, probe, body.rego_source)
        if res.get("rule_id") == "evaluator_invalid_payload":
            # The engine now fail-closes a decision-less module here (P1-2 Q6) — surface it as a specific,
            # actionable error instead of silently accepting an override that would never enforce.
            raise ValueError("rego produced no `decision` (append the canonical resolver, or author a "
                             "complete `decision = \"block\" { ... }` rule)")
    except Exception as exc:
        # httpx timeouts stringify to "" — never surface the empty "override rego is invalid: " (P1-2).
        detail = str(exc)[:160] or f"{type(exc).__name__}: OPA request timed out"
        raise HTTPException(status_code=422, detail=f"override rego is invalid: {detail}") from exc
    await request.app.state.loader.delete(namespace, other)
    await request.app.state.loader.create(
        namespace, key, body.rego_source, saved_by=str(user.get("sub", "")),
        priority=pack_lib.pack_priority() + 5, enforcement_mode="block",
        policy_name="pack-weaken" if body.allow_weaken else "pack-override",
    )
    cache = getattr(request.app.state.loader, "_cache", None)
    if cache is not None:
        await cache.invalidate_eval_scope(namespace)
    if body.allow_weaken:
        # LOUD audit: this namespace now lets a pack edit RELAX a pack block (bounded by the comprehensive floor).
        log.warning("nrvq.api.pack.weaken_applied", namespace=namespace, actor=user.get("sub"), code="NRVQ-API-7099")
    else:
        log.info("nrvq.api.pack.override_saved", namespace=namespace, actor=user.get("sub"), code="NRVQ-API-7098")
    return {"namespace": namespace, "active": True, "mode": "weaken" if body.allow_weaken else "tighten-only"}


@router.delete("/policy-packs/override")
async def delete_pack_override(
    namespace: str = Query("default"),
    request: Request = None,
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """F-54: REVERT — delete the override so the original pack is cleanly restored (no 'permanent' trap)."""
    require_admin(user)
    namespace = scoped_namespace(user, namespace) or "default"
    # Revert clears BOTH the tighten-only override and the weaken overlay — the shipped pack is cleanly restored.
    removed = await request.app.state.loader.delete(namespace, _OVERRIDE_KEY)
    removed_weaken = await request.app.state.loader.delete(namespace, _WEAKEN_KEY)
    cache = getattr(request.app.state.loader, "_cache", None)
    if cache is not None:
        await cache.invalidate_eval_scope(namespace)
    log.info("nrvq.api.pack.override_reverted", namespace=namespace, removed=removed or removed_weaken,
             actor=user.get("sub"), code="NRVQ-API-7098")
    return {"namespace": namespace, "active": False, "reverted": removed or removed_weaken}
