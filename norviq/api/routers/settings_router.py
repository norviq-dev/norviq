# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Runtime settings routes (F046) — GET returns the REAL effective settings (config defaults merged
with persisted per-namespace overrides); PUT persists overrides (admin-only, validated, audited).

Replaces the console's hardcoded settings defaults + localStorage-only persistence.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_target_cluster, scoped_namespace
from norviq.api.db.models import NamespaceSettings
from norviq.api.db.session import get_session
from norviq.config import settings as app_settings

log = structlog.get_logger()
router = APIRouter()


class SettingsUpdate(BaseModel):
    """Per-namespace settings override. Every field optional; omitted fields keep their current value."""

    enforcement_mode: str | None = Field(default=None, pattern="^(block|audit)$")
    trust_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    violation_penalty: float | None = Field(default=None, ge=0.0, le=1.0)
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
        "violation_penalty": (
            row.violation_penalty
            if row and row.violation_penalty is not None
            else app_settings.trust_violation_penalty
        ),
        "rate_limit": (
            row.rate_limit if row and row.rate_limit is not None else app_settings.evaluator_rate_limit_per_window
        ),
        "sector": (getattr(row, "sector", None) if row else None),
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
    log.info(
        "nrvq.api.settings.saved",
        namespace=namespace,
        fields=sorted(body.model_dump(exclude_none=True).keys()),
        actor=user.get("sub"),
        code="NRVQ-API-7085",
    )
    return {"namespace": namespace, **_effective(row)}
