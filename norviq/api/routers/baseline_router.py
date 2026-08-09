# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Baseline controls — read the shipped detectors and set each one to off / monitor / deny.

GET /baseline/controls?namespace=  -> every control, what it catches, its false-positive caveat, and
                                      its current effect in that namespace.
PUT /baseline/controls   (admin)   -> set effects, recompile, materialize as (namespace,'__baseline__').

The shape deliberately mirrors `routers/packs.py`: read a per-namespace table, recompile a rego module
from it, write it to a reserved scope through the normal loader path, invalidate the namespace's eval
cache. Nothing new is introduced into the precedence model — `__baseline__` is the same scope the
chart's cluster baseline already uses.

Every control ships at `monitor`, so a fresh namespace evaluates everything and drops nothing. This
route is how a customer promotes a control to `deny` once they can see, in the compliance view, what
that promotion would actually cost them.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api import baseline as baseline_lib
from norviq.api.auth import get_current_user, require_admin, require_target_cluster, scoped_namespace
from norviq.api.db.models import NamespaceBaselineControl
from norviq.api.db.session import get_session
from norviq.api.routers.settings_router import assert_apply_allowed  # shared dry-run-only gate

log = structlog.get_logger()
router = APIRouter()

_BASELINE_KEY = "__baseline__"
_DEFAULT_PRESET = "strict"

# Matches the chart's baseline (helm/norviq/values.yaml: baselineClusterPolicy.clusterPriority is the
# AUTHORIZATION token; the controller forces the stored priority to 1). A baseline is a floor that any
# authored policy can outrank, not a ceiling — see evaluator._resolve_precedence.
_BASELINE_PRIORITY = 1


class ControlEffects(BaseModel):
    """A sparse map of control_id -> off|monitor|deny. Unlisted controls keep the shipped default."""

    namespace: str = "default"
    preset: str = _DEFAULT_PRESET
    effects: dict[str, str] = Field(default_factory=dict)


async def _stored_effects(session: AsyncSession, namespace: str) -> dict[str, str]:
    """The namespace's non-default control effects. Absent rows mean 'still at the default'."""
    rows = (
        await session.execute(
            select(NamespaceBaselineControl.control_id, NamespaceBaselineControl.effect).where(
                NamespaceBaselineControl.namespace == namespace
            )
        )
    ).all()
    return {row.control_id: row.effect for row in rows}


async def _materialize(request: Request, namespace: str, preset: str, effects: dict[str, str]) -> str:
    """Recompile the namespace's baseline and write it through the normal loader path."""
    rego = baseline_lib.compile(preset, effects)
    loader = request.app.state.loader
    await loader.create(
        namespace,
        _BASELINE_KEY,
        rego,
        saved_by="baseline-controls",
        priority=_BASELINE_PRIORITY,
        # The MODULE carries each control's effect now, so the policy itself always runs in block
        # mode. A control set to `monitor` registers as an `audits[...]` head and already decides
        # "audit" on its own; softening the whole policy on top would make `deny` unreachable and
        # collapse the three effects into two.
        enforcement_mode="block",
        policy_name=f"baseline-controls:{preset}",
    )
    # A baseline applies to EVERY agent class in the namespace, so clear the whole namespace's eval
    # cache — loader.create only invalidates the (ns,__baseline__) scope, and a cached decision from
    # before the change would keep enforcing the old effect for up to redis_ttl_eval_s.
    cache = getattr(loader, "_cache", None)
    if cache is not None:
        await cache.invalidate_eval_scope(namespace)
    return rego


@router.get("/baseline/controls")
async def list_controls(
    namespace: str = Query("default"),
    preset: str = Query(_DEFAULT_PRESET),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Every baseline control with its current effect in this namespace (RBAC-scoped)."""
    namespace = scoped_namespace(user, namespace) or "default"
    try:
        controls = baseline_lib.describe(preset, await _stored_effects(session, namespace))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        # A stored control id that no longer exists in the preset — a downgrade, or a control removed
        # by a release. Reported rather than swallowed: the operator's saved setting is not being
        # honoured and they need to know which one.
        raise HTTPException(status_code=409, detail=f"stored baseline is stale: {exc}") from exc
    counts = {effect: sum(1 for c in controls if c["effect"] == effect) for effect in baseline_lib.EFFECTS}
    log.info("nrvq.api.baseline.listed", namespace=namespace, preset=preset, **counts, code="NRVQ-API-7111")
    return {
        "namespace": namespace,
        "preset": preset,
        "default_effect": baseline_lib.DEFAULT_EFFECT,
        "effects": list(baseline_lib.EFFECTS),
        "counts": counts,
        "controls": controls,
    }


@router.put("/baseline/controls")
async def set_controls(
    body: ControlEffects,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Set control effects for a namespace and materialize the baseline (admin-only, audited)."""
    require_admin(user)
    namespace = scoped_namespace(user, body.namespace) or "default"
    await assert_apply_allowed(session, namespace)

    # Validate BEFORE writing anything. An unknown control id or a bad effect must not leave the table
    # half-updated with a baseline that no longer matches what the operator was shown.
    try:
        resolved = baseline_lib.normalize_effects(body.preset, body.effects)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await session.execute(
        sql_delete(NamespaceBaselineControl).where(NamespaceBaselineControl.namespace == namespace)
    )
    actor = str(user.get("sub", ""))
    for control_id, effect in sorted(resolved.items()):
        # Only persist deviations. A namespace running entirely at the default keeps zero rows, so a
        # future release that changes a default reaches it instead of being masked by a stored copy.
        if effect == baseline_lib.DEFAULT_EFFECT:
            continue
        session.add(
            NamespaceBaselineControl(
                namespace=namespace, control_id=control_id, effect=effect,
                preset=body.preset, set_by=actor,
            )
        )
    await session.commit()

    rego = await _materialize(request, namespace, body.preset, resolved)
    promoted = sorted(cid for cid, eff in resolved.items() if eff == "deny")
    disabled = sorted(cid for cid, eff in resolved.items() if eff == "off")
    log.info(
        "nrvq.api.baseline.updated",
        namespace=namespace, preset=body.preset, deny=promoted, off=disabled,
        actor=actor, actor_role=user.get("role"), code="NRVQ-API-7112",
    )
    return {
        "namespace": namespace,
        "preset": body.preset,
        "effects": resolved,
        "enforcing": promoted,
        "disabled": disabled,
        "rego_lines": len(rego.splitlines()),
    }
