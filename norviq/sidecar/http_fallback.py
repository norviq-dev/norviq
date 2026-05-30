# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP fallback endpoint for sidecar interception."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request

from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.identity import SPIFFEResolver
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()


def create_http_fallback(interceptor: ToolInterceptor, emitter: AuditEmitter, resolver: SPIFFEResolver) -> FastAPI:
    """Create HTTP fallback app for non-Unix-socket runtimes."""
    app = FastAPI(title="Norviq Sidecar HTTP Fallback")

    @app.post("/v1/evaluate")
    async def evaluate(request: Request) -> dict[str, Any]:
        """Evaluate tool call and return proxy action."""
        data = await request.json()
        tool_name = str(data.get("tool_name", ""))
        tool_params = data.get("tool_params", {})
        session_id = str(data.get("session_id", ""))
        decision = await interceptor.intercept(tool_name, tool_params, session_id, framework="sidecar-http")
        identity = await resolver.resolve()
        event = ToolCallEvent(
            tool_name=tool_name,
            tool_params=tool_params if isinstance(tool_params, dict) else {},
            agent_identity=identity,
            session_id=session_id,
            framework="sidecar-http",
        )
        emitter.emit(event, decision)
        action = "forward" if decision.is_allowed() else "drop"
        log.info("nrvq.sidecar.http.processed", tool=tool_name, action=action, code="NRVQ-SDC-3010")
        return {"action": action, "decision": decision.model_dump(mode="json")}

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        """Return sidecar liveness status."""
        return {"status": "ok"}

    return app
