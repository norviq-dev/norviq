# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API-key issuance + verification (F046). Standalone (no auth import) so auth.py can call
authenticate_api_key without a circular import. Keys are high-entropy random secrets; only their
SHA-256 hash is stored. A presented key authenticates as a scoped principal (role + namespace)."""

import hashlib
import secrets
import uuid

import structlog
from sqlalchemy import select

from norviq.api.db.models import ApiKey
from norviq.api.db.session import get_session

log = structlog.get_logger()

_PREFIX = "nrvq_"


def hash_key(raw: str) -> str:
    """SHA-256 of the raw key (the secret is high-entropy, so a fast hash is appropriate)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def generate_key() -> tuple[str, str, str]:
    """Return (full_secret, display_prefix, key_hash). full_secret is shown to the user exactly once."""
    full = _PREFIX + secrets.token_urlsafe(32)
    return full, full[: len(_PREFIX) + 8], hash_key(full)


def new_id() -> str:
    """A fresh key row id."""
    return str(uuid.uuid4())


async def authenticate_api_key(raw: str, session_factory=get_session) -> dict | None:
    """Resolve a presented API key to a scoped principal, or None. Updates last_used_at on success.

    `session_factory` is injectable for tests (defaults to the real get_session); the function opens
    its own session because the caller (get_current_user) has no DB dependency of its own.
    """
    if not raw.startswith(_PREFIX):
        return None
    digest = hash_key(raw)
    provider = session_factory()
    session = await provider.__anext__()
    try:
        row = (
            await session.execute(select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.revoked.is_(False)))
        ).scalar_one_or_none()
        if row is None:
            return None
        from datetime import datetime, timezone

        row.last_used_at = datetime.now(timezone.utc)
        await session.commit()
        log.info("nrvq.api.apikey.authenticated", prefix=row.prefix, code="NRVQ-API-7090")
        return {"sub": f"apikey:{row.prefix}", "role": row.role, "namespace": row.namespace, "name": row.name}
    finally:
        await provider.aclose()
