# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP fallback endpoint for sidecar interception."""

from __future__ import annotations

import ipaddress
from typing import Any

import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.sidecar.proxy import _coerce_depth
from norviq.engine.identity import SPIFFEResolver
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.telemetry.exporter import mount_metrics_endpoint

log = structlog.get_logger()


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


async def _remote_identity(request: Request, body: dict, cache) -> AgentIdentity | JSONResponse:
    """Authenticate an OFF-pod caller, or refuse it. Returns the identity to evaluate under, or the
    response to send. Never evaluates anything itself."""
    peer = request.client.host if request.client else ""
    if str(settings.sidecar_remote_callers).lower() != "token":
        log.warning("nrvq.sidecar.http.remote_refused", peer=peer, code="NRVQ-SDC-3040")
        return JSONResponse(status_code=403, content={"action": "drop", "error": "remote_callers_not_accepted"})
    auth = request.headers.get("authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        log.warning("nrvq.sidecar.http.remote_unauthenticated", peer=peer, code="NRVQ-SDC-3041")
        return JSONResponse(status_code=401, content={"action": "drop", "error": "missing_bearer_token"})
    # Imported here so the injected sidecar, which never takes this branch, does not load the API's auth.
    from norviq.api.auth import bind_caller_identity, decode_token
    try:
        user = await decode_token(token.strip(), cache)
    except Exception as exc:  # noqa: BLE001 — any verification failure is a 401, never an evaluation
        log.warning("nrvq.sidecar.http.remote_token_rejected", peer=peer, error=type(exc).__name__,
                    code="NRVQ-SDC-3042")
        return JSONResponse(status_code=401, content={"action": "drop", "error": "invalid_token"})
    try:
        bound = bind_caller_identity(user, body.get("agent_identity") if isinstance(body.get("agent_identity"), dict) else None)
        return AgentIdentity.model_validate(bound)
    except HTTPException as exc:
        return JSONResponse(status_code=exc.status_code, content={"action": "drop", "error": "identity_not_permitted"})
    except Exception:  # noqa: BLE001 — an identity the credential cannot back is a refusal, not a 500
        return JSONResponse(status_code=422, content={"action": "drop", "error": "invalid_agent_identity"})


def create_http_fallback(
    interceptor: ToolInterceptor, emitter: AuditEmitter | None, resolver: SPIFFEResolver
) -> FastAPI:
    """Create HTTP fallback app for non-Unix-socket runtimes."""
    app = FastAPI(title="Norviq Sidecar HTTP Fallback")
    # The interceptor records what the CALLER waited, and that metric lives in THIS process — the sidecar,
    # not the API. Without a scrape endpoint here it was recorded and unreachable, which is why the
    # caller-observed number had to be derived arithmetically instead of measured.
    mount_metrics_endpoint(app)

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
        # See norviq/sidecar/proxy.py _coerce_depth: this PEP had the same defect.
        call_depth = _coerce_depth(data.get("call_depth"))
        # Off-pod callers are authenticated before anything is evaluated, and evaluated as THEMSELVES.
        # The pod-local app keeps the resolver's identity — the pod's own, which is who it is.
        caller: AgentIdentity | None = None
        peer = request.client.host if request.client else ""
        if not _is_loopback(peer):
            cache = getattr(getattr(interceptor, "_evaluator", None), "_cache", None)
            outcome = await _remote_identity(request, data, cache)
            if isinstance(outcome, JSONResponse):
                return outcome
            caller = outcome
        try:
            decision = await interceptor.intercept(tool_name, tool_params, session_id,
                                                   framework="sidecar-http", call_depth=call_depth,
                                                   identity=caller)
            identity = caller or await resolver.resolve()
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
