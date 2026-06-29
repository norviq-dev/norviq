# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API-key management routes (F046) — issue / list / revoke. Admin-only, audited. The secret is
returned exactly once (on create); the store only ever holds its hash. Replaces the API Keys stub."""

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.api_keys import generate_key, new_id
from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import ApiKey
from norviq.api.db.session import get_session

log = structlog.get_logger()
router = APIRouter()


class KeyCreate(BaseModel):
    """Request to issue a new API key with a scoped role + namespace."""

    name: str = Field(min_length=1, max_length=255)
    namespace: str = Field(default="default", max_length=255)
    role: str = Field(default="viewer", pattern="^(admin|service|viewer)$")


def _public(row: ApiKey) -> dict:
    """Serialize a key WITHOUT its hash/secret."""
    return {
        "id": row.id,
        "prefix": row.prefix,
        "name": row.name,
        "namespace": row.namespace,
        "role": row.role,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "revoked": row.revoked,
    }


@router.get("/keys")
async def list_keys(
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """List issued API keys (no secrets). Admin-only."""
    require_admin(user)
    rows = (await session.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))).scalars().all()
    log.debug("nrvq.api.keys.listed", count=len(rows), code="NRVQ-API-7091")
    return [_public(row) for row in rows]


@router.post("/keys")
async def create_key(
    body: KeyCreate,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Issue a new API key. Returns the secret ONCE; only its hash is stored. Admin-only, audited."""
    require_admin(user)
    full, prefix, key_hash = generate_key()
    row = ApiKey(
        id=new_id(),
        prefix=prefix,
        key_hash=key_hash,
        name=body.name,
        namespace=body.namespace,
        role=body.role,
        created_by=str(user.get("sub") or ""),
    )
    session.add(row)
    await session.commit()
    log.info(
        "nrvq.api.keys.created",
        prefix=prefix,
        role=body.role,
        namespace=body.namespace,
        actor=user.get("sub"),
        code="NRVQ-API-7092",
    )
    # `key` is the only time the secret is ever returned.
    return {**_public(row), "key": full}


@router.delete("/keys/{key_id}")
async def revoke_key(
    key_id: str,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Revoke (disable) an API key. Admin-only, audited."""
    require_admin(user)
    row = (await session.execute(select(ApiKey).where(ApiKey.id == key_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")
    row.revoked = True
    await session.commit()
    log.info("nrvq.api.keys.revoked", prefix=row.prefix, actor=user.get("sub"), code="NRVQ-API-7093")
    return _public(row)
