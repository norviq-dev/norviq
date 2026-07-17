# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Runtime settings routes (F046) — GET returns the REAL effective settings (config defaults merged
with persisted per-namespace overrides); PUT persists overrides (admin-only, validated, audited).

Replaces the console's hardcoded settings defaults + localStorage-only persistence.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_target_cluster, scoped_namespace
from norviq.api.db.models import NamespaceSettings
from norviq.api.db.session import get_session
from norviq.config import settings as app_settings

log = structlog.get_logger()
router = APIRouter()

# CFG-SETTINGS-INERT-01: the RAW per-ns fields the engine hot path consumes for posture. Mirrored into Redis
# (nulls preserved) so the evaluator resolves per-ns enforcement_mode / trust_threshold / rate_limit with per-field
# fallback to the global config. apply_mode is API-side only (assert_apply_allowed) and not needed by the engine.
_ENGINE_POSTURE_FIELDS = ("enforcement_mode", "trust_threshold", "rate_limit")


def _posture_mirror(row: NamespaceSettings | None) -> dict:
    """The RAW engine-facing posture fields for one settings row (nulls preserved for per-field fallback)."""
    return {f: getattr(row, f, None) for f in _ENGINE_POSTURE_FIELDS}


async def warm_ns_settings(cache, session_factory=get_session) -> None:
    """Startup: seed the Redis posture mirror from every persisted NamespaceSettings row so a row that predates
    this fix (or a Redis flush) is not silently stale. Best-effort — the evaluator falls back to global config."""
    if cache is None:
        return
    provider = session_factory()
    session = await provider.__anext__()
    try:
        rows = (await session.execute(select(NamespaceSettings))).scalars().all()
        for row in rows:
            await cache.set_ns_settings(row.namespace, _posture_mirror(row))
        log.info("nrvq.api.settings.warmed", count=len(rows), code="NRVQ-API-7063")
    finally:
        await provider.aclose()


class SettingsUpdate(BaseModel):
    """Per-namespace settings override. Every field optional; omitted fields keep their current value."""

    enforcement_mode: str | None = Field(default=None, pattern="^(block|audit)$")
    trust_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    # NOTE: no per-namespace violation_penalty — it never reached the engine (_ENGINE_POSTURE_FIELDS
    # carries only enforcement_mode/trust_threshold/rate_limit) so a value set here was inert. The knob
    # was removed from the settings surface; the SDK's in-process decay still uses the global
    # settings.trust_violation_penalty.
    rate_limit: int | None = Field(default=None, ge=1, le=100000)
    sector: str | None = Field(default=None, max_length=64)  # F047: org sector hint (pack suggestions)
    apply_mode: str | None = Field(default=None, pattern="^(enforce|dry_run_only)$")  # F-51: apply governance


async def assert_apply_allowed(session: AsyncSession, namespace: str) -> None:
    """F-51: raise 409 if the namespace is in dry_run_only mode (the API must reject policy applies for it).
    Server-enforced so a direct API call is gated, not just the console. dry-run + drafts stay allowed."""
    row = (
        await session.execute(select(NamespaceSettings).where(NamespaceSettings.namespace == namespace))
    ).scalar_one_or_none()
    if row is not None and getattr(row, "apply_mode", None) == "dry_run_only":
        log.warning("nrvq.api.apply.blocked_dry_run_only", namespace=namespace, code="NRVQ-API-7087")
        raise HTTPException(
            status_code=409,
            detail=f"namespace '{namespace}' is in dry-run-only mode — policy applies are disabled "
                   "(dry-run and draft saves are still allowed). An admin can re-enable enforcement in Settings.",
        )


def _effective(row: NamespaceSettings | None) -> dict:
    """Merge the live config defaults with any persisted override row."""
    return {
        "apply_mode": (getattr(row, "apply_mode", None) if row and getattr(row, "apply_mode", None) else "enforce"),
        "enforcement_mode": (row.enforcement_mode if row and row.enforcement_mode else app_settings.enforcement_mode),
        "trust_threshold": (
            row.trust_threshold if row and row.trust_threshold is not None else app_settings.trust_threshold
        ),
        "rate_limit": (
            row.rate_limit if row and row.rate_limit is not None else app_settings.evaluator_rate_limit_per_window
        ),
        "sector": (getattr(row, "sector", None) if row else None),
    }


@router.get("/settings/retention")
async def get_retention_settings(user: dict = Depends(get_current_user)) -> dict:
    """RETENTION: the cluster's effective data-retention windows, read-only (adjust via Helm/env — a
    UI write here could silently shorten audit evidence, so mutation stays operator-only). Non-secret
    config values; any authenticated user may read them. Drives the Settings page's retention card."""
    return {
        "audit_retention_days": int(app_settings.audit_retention_days),
        "coverage_snapshot_retention_days": int(app_settings.coverage_snapshot_retention_days),
        "graph_snapshot_keep_per_namespace": int(app_settings.graph_snapshot_keep_per_namespace),
        "agent_registry_retention_days": int(app_settings.agent_registry_retention_days),
        "api_key_default_ttl_days": int(app_settings.api_key_default_ttl_days),
        "draft_ttl_days": int(app_settings.draft_ttl_days),
        "draft_ttl_test_hours": int(app_settings.draft_ttl_test_hours),
        "draft_cap_per_namespace": int(app_settings.draft_cap_per_namespace),
        "policy_version_keep_count": int(app_settings.policy_version_keep_count),
        "policy_version_keep_days": int(app_settings.policy_version_keep_days),
        "redteam_detail_keep_runs": int(app_settings.redteam_detail_keep_runs),
        "redteam_detail_keep_days": int(app_settings.redteam_detail_keep_days),
        "redteam_summary_keep_runs": int(app_settings.redteam_summary_keep_runs),
        "redteam_summary_keep_days": int(app_settings.redteam_summary_keep_days),
    }


@router.get("/settings")
async def get_settings(
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Return the effective settings for a namespace (config defaults + persisted overrides)."""
    namespace = scoped_namespace(user, namespace) or "default"
    row = (
        await session.execute(select(NamespaceSettings).where(NamespaceSettings.namespace == namespace))
    ).scalar_one_or_none()
    log.debug("nrvq.api.settings.served", namespace=namespace, persisted=row is not None, code="NRVQ-API-7084")
    return {"namespace": namespace, **_effective(row)}


@router.put("/settings")
async def put_settings(
    body: SettingsUpdate,
    request: Request,
    namespace: str = Query("default"),
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Persist a per-namespace settings override (admin-only, validated, audited)."""
    require_admin(user)
    namespace = scoped_namespace(user, namespace) or "default"
    if namespace == "all":
        raise HTTPException(status_code=400, detail="Pick a concrete namespace to save settings")

    row = (
        await session.execute(select(NamespaceSettings).where(NamespaceSettings.namespace == namespace))
    ).scalar_one_or_none()
    if row is None:
        row = NamespaceSettings(namespace=namespace)
        session.add(row)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(row, field, value)
    await session.commit()
    # CFG-SETTINGS-INERT-01: mirror the RAW engine-facing posture into Redis so the evaluator enforces it live
    # (source of truth remains the DB row above). Best-effort — a mirror failure just means the engine keeps the
    # prior/global posture until the next warm/PUT; it never fails the save.
    cache = getattr(getattr(request.app, "state", None), "cache", None)
    if cache is not None:
        try:
            await cache.set_ns_settings(namespace, _posture_mirror(row))
        except Exception as exc:  # noqa: BLE001 — the DB write is the source of truth; the mirror is advisory
            log.error("nrvq.api.settings.mirror_failed", namespace=namespace, error=str(exc), code="NRVQ-API-7063")
    log.info(
        "nrvq.api.settings.saved",
        namespace=namespace,
        fields=sorted(body.model_dump(exclude_none=True).keys()),
        actor=user.get("sub"),
        code="NRVQ-API-7085",
    )
    return {"namespace": namespace, **_effective(row)}
