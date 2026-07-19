# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Request-body size limit middleware (pure ASGI).

Rejects requests whose body exceeds ``settings.max_request_body_bytes`` with 413 BEFORE they reach the
evaluator. This bounds the worst-case cost of the base64 fan-out (a pathological large payload was a ~40x
eval-CPU amplifier) and generic memory abuse. Enforced on the declared Content-Length and, for chunked
bodies with no length, on the actually-read size (early-reject once the accumulated bytes exceed the cap).

This MUST be a pure ASGI middleware, NOT ``BaseHTTPMiddleware``. Starlette's
``BaseHTTPMiddleware`` runs the downstream response inside its own anyio task group and re-emits it; that
is incompatible with a ``StreamingResponse`` (the request-body re-injection races the response stream and
Starlette raises ``RuntimeError: Unexpected message received: http.request``). The only streaming endpoint
(``GET /api/v1/audit/export``) therefore returned **HTTP 200 with an empty body** — SIEM/compliance audit
pulls silently got nothing. A pure ASGI middleware only wraps ``receive`` (to bound the request body) and
passes ``send`` through untouched, so streaming responses are unaffected.
"""

from __future__ import annotations

import structlog

from norviq.config import settings

log = structlog.get_logger()

_TOO_LARGE_BODY = b'{"detail":"Request body too large"}'


async def _reject_413(send) -> None:
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_TOO_LARGE_BODY)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": _TOO_LARGE_BODY})


class BodySizeLimitMiddleware:
    """Reject over-large request bodies with 413 (NRVQ-API-7050) — pure ASGI (streaming-safe)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        max_bytes = settings.max_request_body_bytes

        # Declared Content-Length short-circuit (rejects before reading a single body byte).
        for name, value in scope.get("headers") or []:
            if name == b"content-length":
                try:
                    if int(value) > max_bytes:
                        log.warning("nrvq.api.body_too_large", declared=value.decode(errors="replace"),
                                    limit=max_bytes, code="NRVQ-API-7050")
                        await _reject_413(send)
                        return
                except ValueError:
                    pass  # malformed header -> fall through to the read-time check
                break

        # Buffer + enforce the real body size (chunked / no declared length), early-rejecting as soon as the
        # accumulated bytes exceed the cap (never buffering the whole pathological payload), then replay the
        # buffered body to the app. `send` is passed through UNTOUCHED — this is what keeps StreamingResponse
        # working (the BaseHTTPMiddleware wrapping was the audit-export bug).
        body = bytearray()
        while True:
            message = await receive()
            mtype = message.get("type")
            if mtype == "http.request":
                body.extend(message.get("body", b""))
                if len(body) > max_bytes:
                    log.warning("nrvq.api.body_too_large", read=len(body), limit=max_bytes, code="NRVQ-API-7050")
                    await _reject_413(send)
                    return
                if not message.get("more_body", False):
                    break
            elif mtype == "http.disconnect":
                return

        replayed = False
        buffered = bytes(body)

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
