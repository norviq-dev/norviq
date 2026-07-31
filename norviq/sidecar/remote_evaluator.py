# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Thin-proxy evaluator.

In proxy mode the injected sidecar does NOT run its own OPA/Redis/Postgres. It resolves identity
locally, then POSTs the tool call to the central norviq-api ``/api/v1/evaluate`` with a
namespace-scoped service JWT and maps the response to a ``PolicyDecision``. Every failure path
(network error, non-2xx, timeout, bad body) fails **closed** — returns a block decision so the
sidecar drops the tool call rather than forwarding it.
"""

from __future__ import annotations

from time import perf_counter

import asyncio
import os
import ssl
import tempfile

import httpx
import structlog

from norviq.engine.latency import PhaseTimer
from norviq.telemetry.metrics import record_interception_latency, record_path_phase
from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()

# Reason surfaced when the central API is unreachable/unhealthy — distinct from a policy block.
_FAIL_CLOSED_REASON = "Thin-proxy sidecar could not reach the central policy engine (fail-closed)"
# The engine ANSWERED and refused us: a credential/request problem, not an outage. Kept separate so
# operators are not sent to debug healthy engine pods, and so it is auditable as distinct from an outage.
_ENGINE_REFUSED_REASON = (
    "Central policy engine rejected the sidecar's request (credential or request error, not an outage)"
)
# Only reachable when the operator has explicitly chosen availability over enforcement.
_FAIL_OPEN_REASON = (
    "Thin-proxy sidecar could not reach the central policy engine; forwarding UNGOVERNED because "
    "the configured fallback posture is allow"
)


def _build_mtls_context(ca_pem: str, cert_pem: str, key_pem: str) -> ssl.SSLContext:
    """Build a client-side mutual-TLS context from in-memory PEM strings.

    Trusts ONLY the internal CA (``cadata``) and presents the injected client cert/key. Hostname
    verification stays ON (the internal serving cert's SANs cover norviq-api / .norviq.svc). The
    stdlib ``load_cert_chain`` can only read from files, so the client cert + key are written to
    0600 temp files (unlinked immediately after load — the loaded context keeps its own copy).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca_pem)

    cert_path = key_path = None
    try:
        cert_fd, cert_path = tempfile.mkstemp(suffix=".crt")
        key_fd, key_path = tempfile.mkstemp(suffix=".key")
        os.fchmod(cert_fd, 0o600)
        os.fchmod(key_fd, 0o600)
        with os.fdopen(cert_fd, "w") as f:
            f.write(cert_pem)
        with os.fdopen(key_fd, "w") as f:
            f.write(key_pem)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        # The context retains the loaded material; the transient files must not linger on disk.
        for path in (cert_path, key_path):
            if path is not None:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    return ctx


class RemoteEvaluator:
    """Evaluate tool calls by delegating to the central norviq-api /evaluate endpoint."""

    def __init__(self, api_url: str | None = None, api_token: str | None = None) -> None:
        """Store the central API base URL + service token; create a keep-alive client."""
        self._api_url = (api_url or settings.api_url).rstrip("/")
        self._api_token = api_token if api_token is not None else settings.api_token
        self._client: httpx.AsyncClient | None = None
        # Shared with the SDK client so both data-plane paths retry identically.
        self._max_retries = settings.sdk_retry_max_attempts
        self._backoff_base_ms = settings.sdk_retry_backoff_base_ms

    async def connect(self) -> None:
        """Open the shared keep-alive HTTP client (a small bounded pool, hot-path safe).

        When internal_tls is enabled AND the API URL is https, present a mutual-TLS client context
        (trusts the internal CA + sends the injected client cert). The bearer token header is kept
        (defense in depth). When the feature is off OR the URL is http, this is byte-identical to the
        prior plaintext behavior (no verify kwarg passed to httpx at all).
        """
        headers = {"Content-Type": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        client_kwargs: dict = {
            "base_url": self._api_url,
            "headers": headers,
            "timeout": httpx.Timeout(2.0, connect=1.0),
            "limits": httpx.Limits(max_keepalive_connections=8, max_connections=16),
        }
        if settings.internal_tls and self._api_url.startswith("https"):
            client_kwargs["verify"] = _build_mtls_context(
                settings.internal_api_ca_pem,
                settings.internal_client_cert_pem,
                settings.internal_client_key_pem,
            )
            log.info("nrvq.sidecar.remote_evaluator.mtls_enabled", api_url=self._api_url, code="NRVQ-SDC-3032")
        self._client = httpx.AsyncClient(**client_kwargs)
        log.info("nrvq.sidecar.remote_evaluator.ready", api_url=self._api_url, code="NRVQ-SDC-3030")

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Time the upstream call, then delegate. See `_evaluate_upstream` for the logic.

        A thin wrapper rather than a timer inside the body on purpose: that body has three return sites
        (success, fail-open, fail-closed) plus retry arms, so timing it inline would mean four call sites
        to keep in sync and a future `return` would silently stop being measured. `finally` covers every
        path including an exception, and it keeps this diff off the enforcement logic entirely.

        `total - upstream` (from the interceptor's own metric) isolates the sidecar's local cost from the
        cross-pod round trip — the whole question in proxy mode, where the engine reports single-digit ms
        while the caller may wait far longer, and nothing said which side of the wire the tail was on.
        """
        _t0 = perf_counter()
        try:
            return await self._evaluate_upstream(event)
        finally:
            record_interception_latency("sidecar_proxy", "upstream", (perf_counter() - _t0) * 1000.0)

    async def _evaluate_upstream(self, event: ToolCallEvent) -> PolicyDecision:
        """POST the event to the central engine; fail CLOSED (block) on any error."""
        if self._client is None:
            await self.connect()
        # Split payload / post / parse: the gap between what this client waits and what the API reports
        # measuring was ~46 ms with nowhere to attribute it. pydantic model_dump and JSON coding are CPU
        # work, and this container runs at 200m — where 8.1 ms of CPU is burned per call — so "the wire" and
        # "serialising for the wire" have to be told apart before either is blamed.
        _timer = PhaseTimer()
        with _timer.phase("payload"):
            payload = {
                "tool_name": event.tool_name,
                "tool_params": event.tool_params,
                "agent_identity": event.agent_identity.model_dump(),
                "session_id": event.session_id,
                "call_depth": event.call_depth,
                # Preserve the decision source so the central audit record is attributed to the sidecar.
                "framework": event.framework or "sidecar",
            }
        # Retry transient failures before giving up. Without this a single dropped connection — a
        # rolling norviq-api restart, a node's conntrack entry expiring, one 503 from a terminating
        # pod — blocks a live agent's tool call outright. The SDK client has always retried with
        # backoff; the injected sidecar is the zero-code-change path and must be no less resilient.
        # Only transport errors and 5xx are retried: a 4xx is the engine answering with a refusal,
        # so retrying it just delays the same block.
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                with _timer.phase("post"):
                    resp = await self._client.post("/api/v1/evaluate", json=payload)
                    resp.raise_for_status()
                with _timer.phase("parse"):
                    data = resp.json()
                    decision = PolicyDecision(
                        decision=data.get("decision", "block"),
                        rule_id=data.get("rule_id", "remote_eval"),
                        trust_score=float(data.get("trust_score", 0.0)),
                        reason=data.get("reason", ""),
                    )
                for _ph, _ms in _timer.phases_ms().items():
                    record_path_phase("upstream", _ph, _ms)
                record_path_phase("upstream", "unattributed", _timer.unattributed_ms())
                return decision
            except httpx.HTTPStatusError as exc:
                last_exc = exc
                if exc.response.status_code < 500:
                    break  # the engine refused us (auth/bad request) — not retryable
            except (httpx.TimeoutException, httpx.RequestError) as exc:
                last_exc = exc
            except Exception as exc:  # bad body / unexpected — not retryable
                # Announce at the handler site with a stable code: this is the one arm that catches an
                # unanticipated failure, and the shared fail-closed log below cannot say which arm we
                # came from. Operators alert on the code, so a silent swallow here would be invisible.
                log.error(
                    "nrvq.sidecar.remote_evaluator.unexpected_error",
                    error=str(exc),
                    error_type=type(exc).__name__,
                    code="NRVQ-SDC-3033",
                )
                last_exc = exc
                break
            if attempt < self._max_retries:
                await asyncio.sleep((self._backoff_base_ms * (2**attempt)) / 1000)

        # Every attempt failed. A 4xx means the engine ANSWERED and refused us (bad/expired token,
        # malformed request) — that is never an outage and must never fail open, or a revoked
        # credential silently becomes a governance bypass. Only genuine unreachability (5xx, timeout,
        # connect error) honours the operator's configured posture, which defaults to block.
        refused = isinstance(last_exc, httpx.HTTPStatusError) and last_exc.response.status_code < 500
        mode = "block" if refused else settings.sdk_fallback_mode
        if mode == "allow":
            log.warning(
                "nrvq.sidecar.remote_evaluator.fail_open",
                error=str(last_exc),
                code="NRVQ-SDC-3032",
            )
            return PolicyDecision(
                decision="allow",
                rule_id="thin_proxy_fail_open",
                reason=_FAIL_OPEN_REASON,
                trust_score=0.0,
            )
        log.error("nrvq.sidecar.remote_evaluator.fail_closed", error=str(last_exc), code="NRVQ-SDC-3031")
        return PolicyDecision(
            decision="block",
            rule_id="thin_proxy_fail_closed",
            reason=_ENGINE_REFUSED_REASON if refused else _FAIL_CLOSED_REASON,
            trust_score=0.0,
        )
