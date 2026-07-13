# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async policy engine client for SDK enforcement decisions."""

from __future__ import annotations

import asyncio
from time import monotonic

import httpx
import structlog

from norviq.config import settings
from norviq.exceptions import NorviqError, NorviqTimeoutError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()


class PolicyEngineClient:
    """Async client for the Norviq policy engine."""

    def __init__(self, base_url: str | None = None, timeout_ms: int | None = None, token: str | None = None) -> None:
        self._base_url = base_url or settings.policy_engine_url
        # /api/v1/evaluate requires a bearer token (service or human); same knob the thin-proxy
        # sidecar uses (NRVQ_API_TOKEN). Empty -> no Authorization header (local dev/test servers).
        self._token = token if token is not None else settings.api_token
        self._timeout_ms = timeout_ms or settings.sdk_timeout_ms
        self._max_retries = settings.sdk_retry_max_attempts
        self._backoff_base_ms = settings.sdk_retry_backoff_base_ms
        self._fail_threshold = settings.sdk_circuit_fail_threshold
        self._reset_after_ms = settings.sdk_circuit_reset_after_ms
        self._client: httpx.AsyncClient | None = None
        self._failure_count = 0
        self._circuit_open_until = 0.0

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init httpx client with connection pooling."""
        if self._client is None:
            headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers=headers,
                timeout=httpx.Timeout(self._timeout_ms / 1000),
                limits=httpx.Limits(
                    max_connections=settings.sdk_http_max_connections,
                    max_keepalive_connections=settings.sdk_http_max_keepalive_connections,
                ),
            )
        return self._client

    def _is_circuit_open(self) -> bool:
        """Check whether the circuit breaker is currently open."""
        return monotonic() < self._circuit_open_until

    def _record_failure(self) -> None:
        """Track failures and open circuit when threshold is reached."""
        self._failure_count += 1
        if self._failure_count >= self._fail_threshold:
            self._circuit_open_until = monotonic() + (self._reset_after_ms / 1000)

    def _record_success(self) -> None:
        """Reset failure tracking after a successful call."""
        self._failure_count = 0
        self._circuit_open_until = 0.0

    async def _post(self, event: ToolCallEvent) -> dict:
        """POST event payload with retry and exponential backoff."""
        client = await self._get_client()
        for attempt in range(self._max_retries + 1):
            try:
                # The central API mounts the evaluate router at /api/v1 (norviq/api/main.py) — same
                # endpoint + auth contract the thin-proxy sidecar's RemoteEvaluator uses.
                response = await client.post("/api/v1/evaluate", json=event.model_dump(mode="json"))
                response.raise_for_status()
                self._record_success()
                return response.json()
            except httpx.HTTPStatusError:
                self._record_failure()
                raise
            except httpx.TimeoutException as exc:
                self._record_failure()
                if attempt >= self._max_retries:
                    raise NorviqTimeoutError(timeout_ms=self._timeout_ms) from exc
                await asyncio.sleep((self._backoff_base_ms * (2**attempt)) / 1000)
            except httpx.RequestError:
                self._record_failure()
                if attempt >= self._max_retries:
                    raise
                await asyncio.sleep((self._backoff_base_ms * (2**attempt)) / 1000)
        raise NorviqError("Policy engine request failed", code="NRVQ-SDK-1000")

    def _log_success(self, event_id: str, decision: str) -> None:
        """Log successful evaluation."""
        log.info("nrvq.sdk.evaluate.ok", event_id=event_id, decision=decision, code="NRVQ-SDK-1010")

    def _handle_timeout(self, event: ToolCallEvent, exc: NorviqTimeoutError) -> PolicyDecision:
        """Handle timeout path and return fallback decision."""
        log.warning(
            "nrvq.sdk.evaluate.timeout",
            event_id=event.event_id,
            timeout_ms=self._timeout_ms,
            error=str(exc),
            code="NRVQ-SDK-1011",
        )
        return self._fallback_decision(event)

    def _handle_http_error(self, event: ToolCallEvent, exc: httpx.HTTPStatusError) -> PolicyDecision:
        """Handle HTTP error path and return fallback decision."""
        log.error(
            "nrvq.sdk.evaluate.http_error",
            event_id=event.event_id,
            status=exc.response.status_code,
            code="NRVQ-SDK-1012",
        )
        return self._fallback_decision(event)

    def _handle_unknown_error(self, event: ToolCallEvent, exc: Exception) -> PolicyDecision:
        """Handle unexpected error path and return fallback decision."""
        log.error("nrvq.sdk.evaluate.error", event_id=event.event_id, error=str(exc), code="NRVQ-SDK-1000")
        return self._fallback_decision(event)

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Send ToolCallEvent to engine and return PolicyDecision."""
        if self._is_circuit_open():
            log.warning("nrvq.sdk.evaluate.circuit_open", event_id=event.event_id, code="NRVQ-SDK-1013")
            return self._fallback_decision(event)
        try:
            decision = PolicyDecision(**(await self._post(event)))
            self._log_success(event.event_id, decision.decision)
            return decision
        except NorviqTimeoutError as exc:
            return self._handle_timeout(event, exc)
        except httpx.HTTPStatusError as exc:
            return self._handle_http_error(event, exc)
        except Exception as exc:
            return self._handle_unknown_error(event, exc)

    def _fallback_decision(self, event: ToolCallEvent) -> PolicyDecision:
        """Return fallback decision when engine is unavailable."""
        mode = settings.sdk_fallback_mode
        log.warning("nrvq.sdk.fallback", event_id=event.event_id, mode=mode, code="NRVQ-SDK-1013")
        return PolicyDecision(
            decision=mode,
            reason=f"Engine unavailable, fallback={mode}",
            event_id=event.event_id,
        )

    async def close(self) -> None:
        """Close the HTTP client connection pool."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
