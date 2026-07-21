# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Version route — the single source of truth for the build version shown in the console.

The version comes from the installed package metadata (pyproject [project].version), so there is
exactly one place it is defined.
"""

import os
from importlib import metadata

import structlog
from fastapi import APIRouter, Depends

from norviq.api.auth import get_current_user

log = structlog.get_logger()
router = APIRouter()


def _version() -> str:
    """Resolve the installed norviq package version; '0.0.0+unknown' if metadata is unavailable."""
    try:
        return metadata.version("norviq")
    except metadata.PackageNotFoundError:  # pragma: no cover - only when running from a non-installed tree
        return "0.0.0+unknown"


@router.get("/version")
async def version(user: dict = Depends(get_current_user)) -> dict:
    """Return the product version + license for the About page."""
    _ = user
    ver = _version()
    build_sha = os.getenv("NRVQ_BUILD_GIT_SHA", "unknown")
    log.debug("nrvq.api.version.served", version=ver, code="NRVQ-API-7086")
    return {"version": ver, "build_git_sha": build_sha, "license": "Apache-2.0"}
