# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unix socket sidecar proxy for tool call interception."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.engine.latency import PhaseTimer
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.events import ToolCallEvent
from norviq.telemetry.metrics import record_path_phase
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sidecar.remote_evaluator import RemoteEvaluator

log = structlog.get_logger()



def _is_missing_schema(exc: BaseException) -> bool:
    """True when the failure is "the table isn't there yet", not a real error.

    Matched on the message rather than by importing asyncpg's exception type: SQLAlchemy wraps the
    driver error, the wrapper class differs by driver, and the sidecar must not hard-depend on asyncpg
    being the driver. `UndefinedTable` is Postgres SQLSTATE 42P01.
    """
    for err in (exc, getattr(exc, "orig", None)):
        if err is None:
            continue
        if getattr(err, "sqlstate", None) == "42P01" or type(err).__name__ == "UndefinedTableError":
            return True
        text_ = str(err).lower()
        if "does not exist" in text_ and "relation" in text_:
            return True
    return False


def _coerce_depth(raw: object) -> int:
    """Clamp a caller-reported call depth to a sane non-negative int.

    Never raises: a malformed depth must not fail the call open OR closed on a parse error — it just
    degrades to 0, which is the value every PEP used to send unconditionally.
    """
    if raw is None:
        return 0
    try:
        depth = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # Not silent: a client sending a non-numeric depth is a client bug worth seeing, and the
        # degrade-to-0 below is exactly the value that used to be sent unconditionally, so it can
        # never fail a call open or closed. Logged rather than raised for that reason.
        log.warning("nrvq.sidecar.call_depth_malformed", raw=repr(raw)[:64], code="NRVQ-SDC-3012")
        return 0
    if depth < 0:
        log.warning("nrvq.sidecar.call_depth_negative", raw=depth, code="NRVQ-SDC-3012")
        return 0
    if depth > 1000:
        # Clamped so a hostile value cannot be handed to rego as an unbounded integer.
        log.warning("nrvq.sidecar.call_depth_clamped", raw=depth, code="NRVQ-SDC-3012")
        return 1000
    return depth


class SidecarProxy:
    """Unix socket proxy for tool call interception."""

    def __init__(self, socket_path: str | None = None) -> None:
        """Create sidecar state for shared evaluator resources."""
        self._socket_path = socket_path or settings.socket_path
        self._cache: RedisCache | None = None
        self._evaluator: OPAEvaluator | None = None
        self._loader: PolicyLoader | None = None
        self._resolver: SPIFFEResolver | None = None
        self._interceptor: ToolInterceptor | None = None
        self._emitter: AuditEmitter | None = None
        self._server: asyncio.AbstractServer | None = None
        self._policy_event_task: asyncio.Task | None = None

    # How long an embedded engine waits for the API to create the schema before giving up. Comfortably
    # inside the injected sidecar's startupProbe budget (30 × 3s = 90s, webhook/injector.go), so a pod
    # that is merely waiting is never mistaken for a pod that is wedged.
    _SCHEMA_WAIT_S = 60.0
    _SCHEMA_POLL_S = 2.0

    async def _warm_cache_once_the_schema_exists(self) -> None:
        """Warm the policy cache, tolerating a schema the API has not created YET.

        `warm_cache` SELECTs from `policies`, but only the API creates that table. Nothing orders the two:
        the standalone engine's init containers gate on Postgres and Redis, not on the API. So on a fresh
        install the engine reached the DB first and died:

            asyncpg.exceptions.UndefinedTableError: relation "policies" does not exist

        Kubernetes restarted it and by then the API had caught up, so it self-healed — which is why it
        looked like noise. It is the same nondeterminism as the other fresh-install races: a crash backoff
        can outlast `helm install --wait --atomic` and roll back a healthy install.

        Waiting is strictly better than crashing, and it stays FAIL-CLOSED throughout: `_warmed` is only
        set by a successful `warm_cache`, so until then the evaluator's no-policy path is
        `policy_load_pending` → block, never "no policy matched → allow". If the schema never appears we
        re-raise, preserving the old crash so a genuinely broken deployment is still loud.
        """
        deadline = time.monotonic() + self._SCHEMA_WAIT_S
        attempt = 0
        while True:
            attempt += 1
            try:
                await self._loader.warm_cache()
                if attempt > 1:
                    log.info(
                        "nrvq.sidecar.schema_ready", attempts=attempt, code="NRVQ-SDC-3034",
                    )
                return
            except Exception as exc:  # noqa: BLE001 — narrowed immediately below; anything else re-raises
                if not _is_missing_schema(exc) or time.monotonic() >= deadline:
                    raise
                log.info(
                    "nrvq.sidecar.waiting_for_schema",
                    detail="the API has not created the policy schema yet; blocking fail-closed until it does",
                    attempt=attempt, code="NRVQ-SDC-3035",
                )
                await asyncio.sleep(self._SCHEMA_POLL_S)

    async def start(self) -> None:
        """Initialize dependencies (by mode) and start the Unix socket listener."""
        self._resolver = SPIFFEResolver()
        if settings.sidecar_mode == "embedded":
            # Air-gapped/edge: full local engine (needs NRVQ_REDIS_URL/NRVQ_PG_URL/NRVQ_OPA_* wired in).
            self._cache = RedisCache()
            await self._cache.connect()
            self._evaluator = OPAEvaluator(self._cache)
            self._loader = PolicyLoader(self._cache, self._evaluator)
            await self._warm_cache_once_the_schema_exists()
            self._emitter = AuditEmitter()
            await self._emitter.init()
            self._policy_event_task = asyncio.create_task(self._watch_policy_events())
            log.info("nrvq.sidecar.mode.embedded", code="NRVQ-SDC-3033")
            log.info("nrvq.sidecar.pubsub_watcher_started", code="NRVQ-SDC-3023")
        else:
            # Default: thin proxy to the central engine. No Redis/OPA/Postgres in the pod; the
            # central /evaluate writes the audit record (with framework="sidecar"), so no local emitter.
            self._evaluator = RemoteEvaluator()
            await self._evaluator.connect()
            self._emitter = None
            log.info("nrvq.sidecar.mode.proxy", api_url=settings.api_url, code="NRVQ-SDC-3032")
        self._interceptor = ToolInterceptor(self._evaluator, self._resolver)
        await self._unlink_existing_socket()
        self._server = await asyncio.start_unix_server(self._handle_connection, path=self._socket_path)
        # The injected sidecar runs as uid 65534 while the application container runs as its image's
        # own (different) uid, so the app must be able to connect() to the shared unix socket. Make the
        # socket world-connectable (it lives on a pod-private emptyDir, not exposed outside the pod).
        try:
            os.chmod(self._socket_path, 0o777)  # nosec B103 - unix socket on a pod-private emptyDir; the app container runs as a different uid and MUST connect(), so the socket has to be world-connectable within the pod (not exposed outside it)
        except OSError as exc:  # pragma: no cover - non-fatal; log and continue
            log.warning("nrvq.sidecar.socket_chmod_failed", error=str(exc), code="NRVQ-SDC-3006")
        log.info("nrvq.sidecar.started", socket=self._socket_path, code="NRVQ-SDC-3000")

    async def _watch_policy_events(self) -> None:
        """Refresh local policy state on policy update events."""
        if self._cache is None:
            return
        try:
            await self._cache.listen_policy_events(self._on_policy_invalidated)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("nrvq.sidecar.pubsub_failed", error=str(exc), code="NRVQ-SDC-3020")

    async def _on_policy_invalidated(self, key: str) -> None:
        """Handle policy invalidation event."""
        try:
            parts = key.split(":", 1)
            if len(parts) == 2:
                namespace, agent_class = parts
                if self._evaluator and hasattr(self._evaluator, "_loader") and self._evaluator._loader:
                    await self._evaluator._loader._reload_policy(namespace, agent_class)
                log.info("nrvq.sidecar.policy_reloaded", key=key, code="NRVQ-SDC-3021")
        except Exception as exc:
            log.error("nrvq.sidecar.reload_failed", key=key, error=str(exc), code="NRVQ-SDC-3022")

    async def _unlink_existing_socket(self) -> None:
        """Delete stale Unix socket file before binding."""
        socket = Path(self._socket_path)
        if socket.exists():
            socket.unlink()

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Process JSONL requests from one connection."""
        try:
            while line := await reader.readline():
                payload = line.decode("utf-8").strip()
                response = await self._process_request(payload)
                writer.write((response + "\n").encode("utf-8"))
                await writer.drain()
        except Exception as exc:
            log.error("nrvq.sidecar.connection_error", error=str(exc), code="NRVQ-SDC-3001")
        finally:
            # Teardown must not raise. A client that goes away mid-response (crash, timeout, a
            # fuzzer, or just an abrupt close) makes close()/wait_closed() raise BrokenPipeError or
            # ConnectionResetError — and because this is the asyncio client_connected_cb, an escape
            # here surfaces as an "Unhandled exception in client_connected_cb" traceback per
            # connection. That is log spam an unauthenticated local peer can generate at will, and it
            # buries the real NRVQ-SDC-3001 line above. The decision path is unaffected either way:
            # nothing is forwarded without an allow, so this is robustness, not enforcement.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as exc:  # never let teardown escape the connection callback
                # Debug, not error: a peer vanishing after its decision is ordinary, and the
                # decision itself already succeeded. Still logged rather than swallowed, so a
                # teardown failure is never invisible (tests/engine/test_failures_are_loud.py).
                log.debug("nrvq.sidecar.close_failed", error=str(exc),
                          error_type=type(exc).__name__, code="NRVQ-SDC-3001")

    async def _process_request(self, raw: str) -> str:
        """Evaluate one JSON request and return JSON response.

        Split into phases because this process is ~50% of what the caller waits in proxy mode and none of
        it was measured. `audit` is timed separately for a specific reason: it is awaited BEFORE the
        response is returned, so in embedded mode (where an emitter exists) the caller pays for the audit
        write. In proxy mode `_emit_audit` short-circuits, so the same phase should read ~0 — that
        difference is the measurement, not an assumption.
        """
        timer = PhaseTimer()
        try:
            with timer.phase("parse"):
                data = json.loads(raw)
                tool_name = str(data.get("tool_name", ""))
                tool_params = self._tool_params(data)
                session_id = str(data.get("session_id", ""))
                # call_depth is CALLER-REPORTED, exactly like session_id and tool_params. It was not
                # forwarded at all: every PEP called intercept() positionally and took the parameter's
                # 0 default, so `chain_depth_limit` — shipped ENABLED in the default comprehensive
                # policy and in the strict preset, exercised by the Policy Tester, and reported as
                # PASSED by the red-team suite — could never fire on a real call, and ChainDepthSignal
                # (10% of the trust weight) scored every request as depth 0.
                #
                # Trust level: a cooperative signal, not an attestation. An agent that lies about its
                # depth under-reports, the same way it could lie about session_id. It bounds RUNAWAY
                # RECURSION in a cooperating agent, which is what OWASP LLM08 asks for; it is not a
                # defence against an agent that wants to hide its depth.
                call_depth = _coerce_depth(data.get("call_depth"))
            with timer.phase("evaluate"):
                decision = await self._interceptor.intercept(
                    tool_name, tool_params, session_id, framework="sidecar", call_depth=call_depth
                )
            with timer.phase("serialize"):
                action = "forward" if decision.is_allowed() else "drop"
                response = json.dumps({"action": action, "decision": decision.model_dump(mode="json")})
            try:
                with timer.phase("audit"):
                    await self._emit_audit(tool_name, tool_params, session_id, decision)
            except Exception as exc:
                log.error("nrvq.sidecar.audit_error", error=str(exc), code="NRVQ-SDC-3003")
            log.info("nrvq.sidecar.processed", tool=tool_name, action=action, code="NRVQ-SDC-3002")
            for _phase, _ms in timer.phases_ms().items():
                record_path_phase("sidecar", _phase, _ms)
            record_path_phase("sidecar", "unattributed", timer.unattributed_ms())
            return response
        except Exception as exc:
            # Fail CLOSED: a malformed request / interceptor error must DROP the tool call, never
            # forward it (forwarding here would bypass enforcement on the error path).
            log.error("nrvq.sidecar.process_error", error=str(exc), code="NRVQ-SDC-3003")
            return json.dumps({"action": "drop", "error": "request_processing_failed"})

    def _tool_params(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize tool params from request payload."""
        params = data.get("tool_params", {})
        return params if isinstance(params, dict) else {}

    async def _emit_audit(self, tool_name: str, tool_params: dict[str, Any], session_id: str, decision: Any) -> None:
        """Emit sidecar audit without blocking the response path.

        In proxy mode the central /evaluate already persisted the audit record (framework="sidecar"),
        and this pod has no Postgres — so there is no local emitter and nothing to do here.
        """
        if self._emitter is None:
            return
        identity = await self._resolver.resolve()
        event = ToolCallEvent(
            tool_name=tool_name,
            tool_params=tool_params,
            agent_identity=identity,
            session_id=session_id,
            framework="sidecar",
        )
        self._emitter.emit(event, decision)

    async def stop(self) -> None:
        """Close server and downstream resources gracefully."""
        if self._policy_event_task is not None:
            self._policy_event_task.cancel()
            await asyncio.gather(self._policy_event_task, return_exceptions=True)
            self._policy_event_task = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log.info("nrvq.sidecar.socket_closed", code="NRVQ-SDC-3004")
        if self._emitter is not None:
            await self._emitter.close()
        if self._loader is not None:
            await self._loader.close()
        if self._evaluator is not None:
            await self._evaluator.close()
        if self._cache is not None:
            await self._cache.close()
        await self._unlink_existing_socket()
        log.info("nrvq.sidecar.stopped", code="NRVQ-SDC-3005")
