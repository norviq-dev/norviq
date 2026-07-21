# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP fallback endpoint for sidecar interception."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request, Response

from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.identity import SPIFFEResolver
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()


def create_http_fallback(
    interceptor: ToolInterceptor, emitter: AuditEmitter | None, resolver: SPIFFEResolver
) -> FastAPI:
    """Create HTTP fallback app for non-Unix-socket runtimes."""
    app = FastAPI(title="Norviq Sidecar HTTP Fallback")

    @app.post("/v1/evaluate")
    async def evaluate(request: Request) -> dict[str, Any]:
        """Evaluate tool call and return proxy action."""
        try:
            data = await request.json()
        except Exception as exc:
            # Fail CLOSED: an undecodable body must DROP, not forward (no bypass on the error path).
            log.error("nrvq.sidecar.http.decode_error", error=str(exc), code="NRVQ-SDC-3011")
            return {"action": "drop", "error": "invalid_json_body"}
        # Fail CLOSED: valid JSON that is not an object (list/str/number/null) has no .get, so the
        # coercion below would raise AttributeError -> bare 500 (a bypass on the error path). DROP it.
        if not isinstance(data, dict):
            log.error("nrvq.sidecar.http.decode_error", error="non_object_json_body", code="NRVQ-SDC-3011")
            return {"action": "drop", "error": "invalid_json_body"}
        tool_name = str(data.get("tool_name", ""))
        tool_params = data.get("tool_params", {})
        session_id = str(data.get("session_id", ""))
        try:
            decision = await interceptor.intercept(tool_name, tool_params, session_id, framework="sidecar-http")
            identity = await resolver.resolve()
            event = ToolCallEvent(
                tool_name=tool_name,
                tool_params=tool_params if isinstance(tool_params, dict) else {},
                agent_identity=identity,
                session_id=session_id,
                framework="sidecar-http",
            )
            # Proxy mode has no local emitter (the central /evaluate persisted the record); embedded emits here.
            if emitter is not None:
                emitter.emit(event, decision)
        except Exception as exc:
            # Fail CLOSED: an interceptor / identity / validation error must DROP the tool call, never
            # forward it (forwarding here would bypass enforcement on the error path).
            log.error("nrvq.sidecar.http.process_error", error=str(exc), code="NRVQ-SDC-3012")
            return {"action": "drop", "error": "request_processing_failed"}
        action = "forward" if decision.is_allowed() else "drop"
        log.info("nrvq.sidecar.http.processed", tool=tool_name, action=action, code="NRVQ-SDC-3010")
        return {"action": action, "decision": decision.model_dump(mode="json")}

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        """Return sidecar liveness status."""
        return {"status": "ok"}

    @app.get("/readyz")
    async def ready(response: Response) -> dict[str, Any]:
        """Readiness: the interceptor is wired AND the PDP is actually reachable.

        This used to return a constant ``{"status": "ready"}`` — a readiness probe that can never fail,
        which is the same silent-green trap that let a dead data plane look healthy for hours.

        It is now load-bearing: the OPA sidecar binds loopback (its admin API is unauthenticated and
        read-write, so it must not be reachable from another pod), and a kubelet probe dials the POD IP,
        so the kubelet CANNOT health-check OPA directly. This endpoint is where that gating lives for
        this component — reached over localhost, from inside the pod, by the actual consumer. A replica
        that cannot reach its own PDP leaves the Service endpoints instead of advertising an enforcement
        capability it does not have.
        """
        evaluator = getattr(interceptor, "_evaluator", None)
        opa = getattr(evaluator, "opa", None)
        # No OPA handle (subprocess/eval mode) => nothing to gate on; do not invent a failure.
        opa_ok = True if opa is None else bool(await opa.health())
        if not opa_ok:
            response.status_code = 503
            log.error("nrvq.sidecar.readyz.opa_unreachable", code="NRVQ-SDC-3013")
            return {"status": "degraded", "opa": False}
        return {"status": "ready", "opa": True}

    return app
