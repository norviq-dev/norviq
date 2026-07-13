# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""REPORT-AUDEXPORT-01 — the body-size-limit middleware must not break StreamingResponse.

The audit-evidence export (`GET /api/v1/audit/export`) is the only StreamingResponse endpoint. When
`BodySizeLimitMiddleware` was a `BaseHTTPMiddleware`, Starlette re-emitted the streamed response inside its
own task group and raised `RuntimeError: Unexpected message received: http.request`, so the export returned
HTTP 200 with an EMPTY body — SIEM/compliance pulls silently got nothing. These tests fail on the old
BaseHTTPMiddleware and pass on the pure-ASGI rewrite; they also pin the 413 body-limit behavior so the fix
cannot regress it.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from norviq.api.body_limit import BodySizeLimitMiddleware
from norviq.config import settings


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware)

    @app.get("/stream")
    async def stream():
        async def gen():
            for i in range(50):  # many chunks — the failure mode is exactly multi-chunk streaming
                yield f"row-{i}\n".encode()
        return StreamingResponse(gen(), media_type="application/x-ndjson")

    @app.post("/echo")
    async def echo(payload: dict):
        return {"ok": True, "n": len(payload.get("blob", ""))}

    return app


def test_streaming_response_body_is_not_truncated_to_empty():
    """The core bug: a StreamingResponse must reach the client with its FULL body, not 200-with-0-bytes."""
    client = TestClient(_app())
    resp = client.get("/stream")
    assert resp.status_code == 200
    body = resp.content
    assert len(body) > 0, "StreamingResponse body was truncated to empty (the audit-export bug)"
    assert body.count(b"\n") == 50, f"expected all 50 streamed rows, got {body.count(b'row-')}"
    assert b"row-0\n" in body and b"row-49\n" in body


def test_oversized_request_body_still_413():
    """Regression: the size limit still rejects an over-cap request body with 413."""
    client = TestClient(_app())
    huge = "A" * (settings.max_request_body_bytes + 1024)
    resp = client.post("/echo", json={"blob": huge})
    assert resp.status_code == 413


def test_normal_request_body_passes():
    """Regression: a normal-size body is unaffected and reaches the handler intact."""
    client = TestClient(_app())
    resp = client.post("/echo", json={"blob": "small"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "n": 5}
