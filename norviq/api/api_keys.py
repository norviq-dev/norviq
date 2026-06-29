# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""API-key issuance + verification (F046). Standalone (no auth import) so auth.py can call
authenticate_api_key without a circular import. Keys are high-entropy random secrets; only their
SHA-256 hash is stored. A presented key authenticates as a scoped principal (role + namespace)."""

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select

from norviq.api.db.models import ApiKey
from norviq.api.db.session import get_session

log = structlog.get_logger()

_PREFIX = "nrvq_"
# F-03: log (and surface) when one display-prefix accumulates this many failed nrvq_ auths in the window.
_AUTHFAIL_THRESHOLD = 10
_AUTHFAIL_WINDOW_S = 60


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


async def _record_authfail(cache, prefix: str) -> None:
    """F-03: count + audit repeated nrvq_ auth failures per display-prefix (best-effort; never raises)."""
    if cache is None:
        return
    try:
        count = await cache.incr_call_count(f"apikey-authfail:{prefix}", window_s=_AUTHFAIL_WINDOW_S)
        if count >= _AUTHFAIL_THRESHOLD:
            log.warning("nrvq.auth.apikey_failed", prefix=prefix, attempts=int(count), code="NRVQ-AUTH-14006")
    except Exception:  # pragma: no cover - throttle/audit must never break auth
        pass


async def authenticate_api_key(raw: str, session_factory=get_session, cache=None) -> dict | None:
    """Resolve a presented API key to a scoped principal, or None. Updates last_used_at on success.

    `session_factory` is injectable for tests (defaults to the real get_session); the function opens
    its own session because the caller (get_current_user) has no DB dependency of its own.
    """
    if not raw.startswith(_PREFIX):
        return None
    prefix = raw[: len(_PREFIX) + 8]
    digest = hash_key(raw)
    provider = session_factory()
    session = await provider.__anext__()
    try:
        row = (
            await session.execute(select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.revoked.is_(False)))
        ).scalar_one_or_none()
        # F-03: constant-time comparison of the stored hash (defense-in-depth atop the indexed lookup), and
        # throttle/audit repeated failures so an online guessing campaign is rate-limited + visible.
        if row is None or not hmac.compare_digest(row.key_hash, digest):
            await _record_authfail(cache, prefix)
            return None
        row.last_used_at = datetime.now(timezone.utc)
        await session.commit()
        log.info("nrvq.api.apikey.authenticated", prefix=row.prefix, code="NRVQ-API-7090")
        return {"sub": f"apikey:{row.prefix}", "role": row.role, "namespace": row.namespace, "name": row.name}
    finally:
        await provider.aclose()
