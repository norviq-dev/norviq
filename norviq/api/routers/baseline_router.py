# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Baseline controls — read the shipped detectors and set each one to off / monitor / deny.

GET /baseline/controls?namespace=  -> every control, what it catches, its false-positive caveat, and
                                      its current effect in that namespace.
PUT /baseline/controls   (admin)   -> set effects, recompile, materialize as (namespace,'__controls__').

The shape deliberately mirrors `routers/packs.py`: read a per-namespace table, recompile a rego module
from it, write it to a reserved scope through the normal loader path, invalidate the namespace's eval
cache. It gets its OWN reserved scope, `__controls__` — sharing the chart's `__baseline__` key meant a
helm upgrade silently reverted the customer. The engine collects it as a floor and, once saved, lets
it REPLACE the chart's `<ns>:__baseline__` (evaluator._apply_controls_supersede), so Off and Monitor
relax a control the chart enforces. Two floors alone combine strictest-wins, and the switch could only
ever tighten.

Every control defaults to what the chart's preset does with it (baseline.shipped_default), so saving
changes only what the operator changed. This route is how a customer relaxes a control to `monitor` or
`off`, or promotes one, once they can see in the compliance view what that would cost them.
"""

from __future__ import annotations

import contextlib

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api import baseline as baseline_lib
from norviq.api.auth import get_current_user, require_admin, require_target_cluster, scoped_namespace
from norviq.api.db.models import NamespaceBaselineControl
from norviq.api.db.session import get_session
from norviq.api.routers.settings_router import assert_apply_allowed  # shared dry-run-only gate

log = structlog.get_logger()
router = APIRouter()

# The customer's tuned controls live on their OWN key, not on `__baseline__`.
#
# Both wrote `__baseline__` at first, which read as elegant — "the same reserved scope the chart
# already uses, so precedence gains no new concepts" — and was wrong, because the chart already OWNS
# that key. Its NrvqPolicy CR is reconciled by the webhook controller, so a `helm upgrade` or any CR
# resync silently reverted every control a customer had tuned. Worse, the two writers set different
# `enforcement_mode` values on one key, so the same probe returned a prefixed rule_id on one run and a
# bare one on the next — non-reproducible enforcement, which is harder to trust than either behaviour.
_CONTROLS_KEY = "__controls__"
_DEFAULT_PRESET = "strict"
# The policy name every module this router writes carries, so the startup re-render can tell its own
# modules from anything else at the key and recover the preset they were compiled from.
_POLICY_NAME_PREFIX = "baseline-controls:"

# One above the chart's baseline, which the controller forces to priority 1.
#
# This number no longer decides precedence. The controls were a base tier when it was chosen, and base
# tiers resolve by highest priority outright; they are a floor now, which ranks by decision, and they
# replace the chart's baseline by superseding it rather than by outranking it. It still breaks ties
# between floors and orders the console's resolution table. Deliberately NOT in the cluster band
# (>=500): this is a namespace's own tuning, not a cluster-wide floor.
_CONTROLS_PRIORITY = 2


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
    return await _write_controls(request.app.state.loader, namespace, preset, effects)


@contextlib.asynccontextmanager
async def _controls_lock(loader, namespace: str):
    """Serialise writers of one namespace's `__controls__` across processes and replicas.

    Two writers exist: PUT, and the startup re-render below, which every API worker of every replica
    runs at once. Without the lock a re-render could read the stored effects, lose the race to a PUT,
    and then write a module compiled from the effects the PUT just replaced. A Postgres advisory lock,
    held on its own connection, like the remediation overlay's read-merge-write in policies.py. A
    loader with no database (the router's unit-test double) has nothing to race and takes no lock.
    """
    engine_factory = getattr(loader, "_db_engine", None)
    if engine_factory is None:
        yield
        return
    key = f"nrvq:baseline-controls:{namespace}"
    async with engine_factory().connect() as conn:
        await conn.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": key})
        try:
            yield
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": key})


async def rematerialize_controls(loader, namespaces: list[str] | None = None) -> int:
    """Re-render every namespace's saved controls from its STORED effects with THIS release's compiler.

    `__controls__` is a compiled artefact, and before this only PUT ever wrote it. So a module saved by
    an earlier release kept deciding after an upgrade, and with the controls now able to supersede the
    chart's baseline that matters twice over. A v0.2.5 module carries v0.2.5's defaults (it compiled
    strict_default_block, llm02_data_leakage and base64_decoded_threat at monitor); and a release that
    changes a default without touching the preset leaves a module enforcing the old default while
    GET /baseline/controls shows the new one, because only deviations are stored.

    Runs at API startup. Idempotent: a namespace is rewritten only when the module the current compiler
    produces differs from the stored one, so concurrent workers write it once (`_controls_lock`, then a
    DB-authoritative re-read). Only modules the baseline router wrote (policy name
    `baseline-controls:<preset>`) are touched. One namespace failing is logged and skipped, never
    raised; a module another compiler rendered still cannot supersede the chart (baseline.covers).
    `namespaces` narrows the run (tests share one database); startup passes None, meaning all.
    """
    async with loader._db_engine().begin() as conn:
        rows = (await conn.execute(text(
            "SELECT namespace, name FROM policies WHERE agent_class = :ac"), {"ac": _CONTROLS_KEY}
        )).mappings().all()
    rewritten = 0
    for row in rows:
        namespace, name = str(row["namespace"]), str(row["name"] or "")
        if namespaces is not None and namespace not in namespaces:
            continue
        if not name.startswith(_POLICY_NAME_PREFIX):
            log.warning("nrvq.api.baseline.rematerialize_skipped_foreign", namespace=namespace, name=name,
                        code="NRVQ-API-7141")
            continue
        preset = name[len(_POLICY_NAME_PREFIX):] or _DEFAULT_PRESET
        try:
            async with _controls_lock(loader, namespace):
                async with loader._db_engine().begin() as conn:
                    stored = {str(r["control_id"]): str(r["effect"]) for r in (await conn.execute(text(
                        "SELECT control_id, effect FROM namespace_baseline_controls WHERE namespace = :ns"),
                        {"ns": namespace})).mappings().all()}
                wanted = baseline_lib.compile(preset, stored)
                current = await loader.load_from_db(namespace, _CONTROLS_KEY)
                if (current and current["rego"] == wanted and current.get("enforcement_mode") == "block"
                        and int(current.get("priority", 0)) == _CONTROLS_PRIORITY):
                    continue
                await _write_controls(loader, namespace, preset, stored, saved_by="baseline-controls:startup")
                rewritten += 1
                log.info("nrvq.api.baseline.rematerialized", namespace=namespace, preset=preset,
                         code="NRVQ-API-7139")
        except Exception as exc:  # noqa: BLE001 — one namespace must not stop the rest, or startup
            log.error("nrvq.api.baseline.rematerialize_failed", namespace=namespace, error=str(exc),
                      code="NRVQ-API-7140")
    return rewritten


async def _write_controls(loader, namespace: str, preset: str, effects: dict[str, str],
                          saved_by: str = "baseline-controls") -> str:
    """Compile and write one namespace's `__controls__`; shared by PUT and the startup re-render."""
    rego = baseline_lib.compile(preset, effects)
    await loader.create(
        namespace,
        _CONTROLS_KEY,
        rego,
        saved_by=saved_by,
        priority=_CONTROLS_PRIORITY,
        # The MODULE carries each control's effect now, so the policy itself always runs in block
        # mode. A control set to `monitor` registers as an `audits[...]` head and already decides
        # "audit" on its own; softening the whole policy on top would make `deny` unreachable and
        # collapse the three effects into two.
        enforcement_mode="block",
        policy_name=f"{_POLICY_NAME_PREFIX}{preset}",
    )
    # The controls apply to EVERY agent class in the namespace, so clear the whole namespace's eval
    # cache — loader.create only invalidates the (ns,__controls__) scope, and a cached decision from
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

    # Rows and module under one lock, so the startup re-render can never interleave a module compiled
    # from the rows this request is replacing (_controls_lock).
    async with _controls_lock(request.app.state.loader, namespace):
        await session.execute(
            sql_delete(NamespaceBaselineControl).where(NamespaceBaselineControl.namespace == namespace)
        )
        actor = str(user.get("sub", ""))
        for control_id, effect in sorted(resolved.items()):
            # Only persist deviations. A namespace running entirely at the default keeps zero rows, so a
            # future release that changes a default reaches it instead of being masked by a stored copy.
            #
            # Compared against THIS control's shipped default, not the global one. Defaults are per control
            # now, and the global comparison broke the stated property in both directions: a control sitting
            # at its own `deny` default was written as a deviation (masking exactly the future change this
            # comment protects), and an operator's deliberate choice to hold a `deny`-default control at
            # `monitor` was read as "that's the default" and silently dropped — discarding a de-escalation
            # somebody made on purpose.
            if effect == baseline_lib.shipped_default(control_id, body.preset):
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
