# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unix socket sidecar proxy for tool call interception."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

from norviq.config import settings
from norviq.engine.audit_emitter import AuditEmitter
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()


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

    async def start(self) -> None:
        """Initialize dependencies and start Unix socket listener."""
        self._cache = RedisCache()
        await self._cache.connect()
        self._evaluator = OPAEvaluator(self._cache)
        self._loader = PolicyLoader(self._cache, self._evaluator)
        await self._loader.load_all_from_redis()
        self._resolver = SPIFFEResolver()
        self._interceptor = ToolInterceptor(self._evaluator, self._resolver)
        self._emitter = AuditEmitter()
        await self._emitter.init()
        self._policy_event_task = asyncio.create_task(self._watch_policy_events())
        await self._unlink_existing_socket()
        self._server = await asyncio.start_unix_server(self._handle_connection, path=self._socket_path)
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
            writer.close()
            await writer.wait_closed()

    async def _process_request(self, raw: str) -> str:
        """Evaluate one JSON request and return JSON response."""
        try:
            data = json.loads(raw)
            tool_name = str(data.get("tool_name", ""))
            tool_params = self._tool_params(data)
            session_id = str(data.get("session_id", ""))
            decision = await self._interceptor.intercept(tool_name, tool_params, session_id, framework="sidecar")
            action = "forward" if decision.is_allowed() else "drop"
            response = json.dumps({"action": action, "decision": decision.model_dump(mode="json")})
            try:
                await self._emit_audit(tool_name, tool_params, session_id, decision)
            except Exception as exc:
                log.error("nrvq.sidecar.audit_error", error=str(exc), code="NRVQ-SDC-3003")
            log.info("nrvq.sidecar.processed", tool=tool_name, action=action, code="NRVQ-SDC-3002")
            return response
        except Exception as exc:
            log.error("nrvq.sidecar.process_error", error=str(exc), code="NRVQ-SDC-3003")
            return json.dumps({"action": "forward", "error": "request_processing_failed"})

    def _tool_params(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize tool params from request payload."""
        params = data.get("tool_params", {})
        return params if isinstance(params, dict) else {}

    async def _emit_audit(self, tool_name: str, tool_params: dict[str, Any], session_id: str, decision: Any) -> None:
        """Emit sidecar audit without blocking the response path."""
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
        if self._evaluator is not None:
            await self._evaluator.close()
        if self._cache is not None:
            await self._cache.close()
        await self._unlink_existing_socket()
        log.info("nrvq.sidecar.stopped", code="NRVQ-SDC-3005")
