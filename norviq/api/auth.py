# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""JWT auth helpers for API endpoints."""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from norviq.config import settings

security = HTTPBearer(auto_error=False)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Validate HS256 token and return claims."""
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        return dict(jwt.decode(creds.credentials, settings.api_secret_key, algorithms=["HS256"]))
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


def require_admin(user: dict) -> None:
    """Require admin role in token claims."""
    role = str(user.get("role", "")).lower()
    if role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


def require_admin_or_service(user: dict) -> None:
    """Allow a human admin OR a machine 'service' identity (e.g. the webhook CRD controller).

    The webhook controller mints a short-lived service-role JWT to sync NrvqPolicy CRDs to the API;
    least-privilege — only the controller's create/delete policy endpoints accept the service role,
    everything else (rollback/apply/manual writes) stays admin-only via require_admin.
    """
    role = str(user.get("role", "")).lower()
    if role not in {"admin", "service"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin or service role required")


def scoped_namespace(user: dict, requested: str | None) -> str | None:
    """Restrict a non-admin caller to its own namespace claim.

    Admins may read any namespace (or all, when requested is None). Non-admin tokens may only read
    the namespace in their claim — a request for a different namespace is 403. This stops a token
    scoped to one tenant from reading another tenant's audit/agent/policy data via the query param.
    """
    role = str(user.get("role", "")).lower()
    if role == "admin":
        return requested
    claim_ns = str(user.get("namespace", "") or "")
    if requested and claim_ns and requested != claim_ns:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this namespace")
    return claim_ns or requested


def decode_token(token: str) -> dict:
    """Decode an HS256 token outside the HTTP dependency (e.g. websocket query param). Raises JWTError."""
    return dict(jwt.decode(token, settings.api_secret_key, algorithms=["HS256"]))
