# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Current-user route — the server's normalized view of the caller's identity (IDENTITY epic A3).

The console calls this after OIDC login to render the user + the role/namespace the SERVER resolved
(group mapping already applied), rather than trusting a client-side JWT decode.
"""

import structlog
from fastapi import APIRouter, Depends

from norviq.api.auth import get_current_user

log = structlog.get_logger()
router = APIRouter()


@router.get("/me")
async def me(user: dict = Depends(get_current_user)) -> dict:
    """Return the authenticated caller's normalized claims (sub, role, namespace)."""
    sub = user.get("sub")
    role = str(user.get("role", "") or "")
    namespace = str(user.get("namespace", "") or "")
    log.info("nrvq.api.me.served", sub=sub, role=role, code="NRVQ-API-7061")
    return {
        "sub": sub,
        "role": role,
        "namespace": namespace,
        "email": user.get("email"),
        "name": user.get("name") or user.get("preferred_username"),
    }
