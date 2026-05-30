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
