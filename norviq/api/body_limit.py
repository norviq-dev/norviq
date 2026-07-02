# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""PERF-1: request-body size limit middleware.

Rejects requests whose body exceeds ``settings.max_request_body_bytes`` with 413 BEFORE they reach the
evaluator. This bounds the worst-case cost of the base64 fan-out (a pathological large payload was a ~40x
eval-CPU amplifier) and generic memory abuse. Enforced on the declared Content-Length and, for chunked
bodies with no length, on the actually-read size.
"""

from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from norviq.config import settings

log = structlog.get_logger()

_TOO_LARGE = JSONResponse({"detail": "Request body too large"}, status_code=413)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject over-large request bodies with 413 (NRVQ-API-7050)."""

    async def dispatch(self, request: Request, call_next):
        """Enforce the configured max body size on Content-Length and the buffered body."""
        max_bytes = settings.max_request_body_bytes
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > max_bytes:
                    log.warning("nrvq.api.body_too_large", declared=content_length, limit=max_bytes, code="NRVQ-API-7050")
                    return _TOO_LARGE
            except ValueError:
                pass  # malformed header -> fall through to the read-time check below
        # Chunked / no declared length: buffer and check the real size, then re-inject so downstream can read it.
        body = await request.body()
        if len(body) > max_bytes:
            log.warning("nrvq.api.body_too_large", read=len(body), limit=max_bytes, code="NRVQ-API-7050")
            return _TOO_LARGE

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = receive
        return await call_next(request)
