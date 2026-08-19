# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async policy engine client for SDK enforcement decisions."""

from __future__ import annotations

import asyncio
import weakref
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
        # Explicit injection point (tests/mocks). When set it is used verbatim on every loop.
        self._client: httpx.AsyncClient | None = None
        # Per-event-loop clients: an httpx connection pool is bound to the loop it was created on,
        # and adapter sync wrappers (_run_sync) evaluate on a background loop while async wrappers
        # use the caller's loop — reusing one pool across loops crashes and turns healthy traffic
        # into fail-closed fallback blocks. Weak keys: a GC'd loop drops its client with it.
        self._loop_clients: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, httpx.AsyncClient]" = (
            weakref.WeakKeyDictionary()
        )
        self._failure_count = 0
        self._circuit_open_until = 0.0

    def _build_client(self) -> httpx.AsyncClient:
        """Construct a pooled httpx client for the current event loop."""
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        return httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(self._timeout_ms / 1000),
            limits=httpx.Limits(
                max_connections=settings.sdk_http_max_connections,
                max_keepalive_connections=settings.sdk_http_max_keepalive_connections,
            ),
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Return the injected client, or the pooled client for the CURRENT event loop."""
        if self._client is not None:
            return self._client
        loop = asyncio.get_running_loop()
        client = self._loop_clients.get(loop)
        if client is None or client.is_closed:
            client = self._build_client()
            self._loop_clients[loop] = client
        return client

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
            except httpx.HTTPStatusError as exc:
                # Only a SILENT engine may trip the breaker. A 4xx is the engine answering, and
                # `_handle_http_error` is what turns it into a block — but the breaker is checked at
                # the TOP of `evaluate()`, so letting a 4xx count here meant the Nth consecutive 401
                # opened the circuit and every later call short-circuited to `_fallback_decision()`,
                # never reaching the 4xx rule. With the shipped defaults that flipped an expired
                # credential from fail-CLOSED to fail-OPEN, which is the exact bypass that rule exists
                # to prevent. Worse, the breaker only resets on a SUCCESS, so a permanently bad
                # credential never recovered — it settled into a mostly-ungoverned state, and the
                # 30-day sidecar credential cliff produces precisely that 401 storm.
                if exc.response.status_code >= 500:
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
        """Handle HTTP error path.

        A 4xx is NOT an outage: the engine answered, and it refused the request. Treating it as one is
        both a bad diagnostic (operators chase healthy engine pods when the real cause is an expired
        token) and a bypass: with ``sdk_fallback_mode=allow`` — the setting an operator reaches for to
        keep agents running through an outage — every 401/403 would become an ALLOW, so a revoked
        credential silently turns into a total governance bypass. A 4xx an attacker can *provoke* is
        worse still: influence a tool param into a 422 and the same fallback allows the call.

        So 4xx always blocks, whatever the fallback mode. Only 5xx/timeout/connect errors — the engine
        genuinely not answering — honour the operator's configured posture.
        """
        status = exc.response.status_code
        if 400 <= status < 500:
            log.error(
                "nrvq.sdk.evaluate.rejected",
                event_id=event.event_id,
                status=status,
                code="NRVQ-SDK-1014",
            )
            return PolicyDecision(
                decision="block",
                rule_id="engine_rejected_request",
                reason=(
                    f"Policy engine rejected the request (HTTP {status}) — this is a credential or "
                    "request error, not an engine outage; fail-open does not apply."
                ),
                event_id=event.event_id,
            )
        log.error(
            "nrvq.sdk.evaluate.http_error",
            event_id=event.event_id,
            status=status,
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
        """Return the configured fallback decision when the engine is genuinely unavailable.

        An unrecognised mode is coerced to ``block`` rather than passed through: ``PolicyDecision``
        constrains ``decision`` to a Literal, so a typo'd ``NRVQ_SDK_FALLBACK_MODE`` would raise a
        ValidationError *inside this handler* — the one path that only executes while the engine is
        already down. Failing safe beats crashing the data plane during an outage.
        """
        mode = settings.sdk_fallback_mode
        if mode not in ("allow", "block"):
            log.error(
                "nrvq.sdk.fallback.invalid_mode",
                event_id=event.event_id,
                configured=mode,
                code="NRVQ-SDK-1015",
            )
            mode = "block"
        log.warning("nrvq.sdk.fallback", event_id=event.event_id, mode=mode, code="NRVQ-SDK-1013")
        # Carry a rule_id. This used to be left at its "" default, which made a fail-OPEN fallback
        # indistinguishable from a policy that genuinely allowed the call — the audit trail recorded an
        # allow with no rule, and nothing could count how many calls went unjudged during an outage.
        # Since `sdk_fallback_mode` now defaults to "allow", that anonymity would be the difference
        # between a documented trade-off and a silent governance hole: the whole argument for the
        # default is that an operator can see, count and alert on exactly these calls.
        #
        # Emitted in BOTH modes on purpose. The block case is equally worth attributing — an operator
        # staring at blocked agents needs to know the cause was an engine outage, not their policy.
        return PolicyDecision(
            decision=mode,
            rule_id="engine_unavailable_fallback",
            reason=f"Engine unavailable, fallback={mode}",
            event_id=event.event_id,
        )

    async def close(self) -> None:
        """Close the injected client and the current loop's pooled client.

        Clients living on OTHER loops cannot be aclosed from here (cross-loop); their references
        are dropped and the pools are reclaimed with their loops.
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        loop = asyncio.get_running_loop()
        current = self._loop_clients.pop(loop, None)
        if current is not None and not current.is_closed:
            await current.aclose()
        self._loop_clients.clear()
