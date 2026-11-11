# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Thin-proxy evaluator.

In proxy mode the injected sidecar does NOT run its own OPA/Redis/Postgres. It resolves identity
locally, then POSTs the tool call to the central norviq-api ``/api/v1/evaluate`` with a
namespace-scoped service JWT and maps the response to a ``PolicyDecision``.

What happens when no decision comes back depends on whether the engine answered:

- A request this process cannot encode (a non-finite number, a string that is not valid UTF-8,
  nesting or size past what the SDK client will send) never leaves the pod. It blocks
  (``thin_proxy_request_unencodable``, ``NRVQ-SDC-3047``) whatever the fallback posture: the engine was
  not asked, and an unencodable call is not an outage.
- A 4xx is the engine answering with a refusal (expired or wrong credential, malformed request). It
  is not retried and always blocks (``thin_proxy_fail_closed``), whatever the fallback posture.
- A fault this sidecar can tell is its own (a token or URL it cannot send, a TLS trust failure, a
  proxy refusal, an answer that is not a decision, any error that is not a transport error) is not
  retried and blocks (``thin_proxy_client_misconfigured``, ``NRVQ-SDC-3049``); see `client_fault`.
- A 5xx or any other transport error (timeout, refused or reset connection, DNS failure) is retried.
  Once the attempts are spent, the outcome follows ``settings.sdk_fallback_mode``
  (``NRVQ_SDK_FALLBACK_MODE``). With the shipped default, ``allow``, the call is forwarded
  ungoverned under ``thin_proxy_fail_open`` and logged as ``NRVQ-SDC-3036``; with ``block`` it is
  dropped under ``thin_proxy_fail_closed``.

So an engine outage fails OPEN by default. A refusal, an unencodable request and a local fault are
unconditionally fail-closed.
"""

from __future__ import annotations

from time import perf_counter

import asyncio
import os
import ssl
import tempfile

import httpx
import structlog

from norviq.bearer import redact_credentials
from norviq.engine.latency import PhaseTimer
from norviq.telemetry.metrics import record_interception_latency, record_path_phase
from norviq.config import settings
from norviq.sdk.client.engine import (
    DECISIONS,
    ClientFault,
    UnencodableRequest,
    client_fault,
    encode_evaluate_request,
    request_problem,
)
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()

# Reason when the central API is unreachable/unhealthy and the fallback posture is ``block`` —
# distinct from a policy block.
_FAIL_CLOSED_REASON = "Thin-proxy sidecar could not reach the central policy engine (fail-closed)"
# The engine ANSWERED and refused us: a credential/request problem, not an outage. Kept separate so
# operators are not sent to debug healthy engine pods, and so it is auditable as distinct from an outage.
_ENGINE_REFUSED_REASON = (
    "Central policy engine rejected the sidecar's request (credential or request error, not an outage)"
)
# The request could not be built in this pod, so the engine was never asked. Not an outage, so the
# fallback posture does not apply.
_UNENCODABLE_REASON = (
    "The evaluate request could not be encoded in the sidecar (for example, a non-finite number or "
    "nesting too deep); this is not an engine outage, and the fallback posture does not apply"
)
# The event fields the sidecar sends. `framework` is overridden below; the rest of the event (event_id,
# timestamps, MCP context, PEP fields) is the SDK's and was never part of this payload.
_REQUEST_FIELDS = {"tool_name", "tool_params", "agent_identity", "session_id", "call_depth", "framework"}
# Reason when the central API is unreachable/unhealthy and the fallback posture is ``allow``, which
# is the shipped default (config.sdk_fallback_mode), not an opt-in.
_FAIL_OPEN_REASON = (
    "Thin-proxy sidecar could not reach the central policy engine; forwarding UNGOVERNED because "
    "the configured fallback posture is allow"
)


def _client_fault_decision(problem: str) -> PolicyDecision:
    """The block for a fault of this sidecar's own (`NRVQ-SDC-3049`)."""
    return PolicyDecision(
        decision="block",
        rule_id="thin_proxy_client_misconfigured",
        reason=(f"The sidecar could not send a valid request to the central policy engine: {problem}. "
                "This is not an engine outage, and the fallback posture does not apply"),
        trust_score=0.0,
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
        problem = self._config_problem()
        if problem is not None:
            # No client is built; each call blocks on the same problem in `_evaluate_upstream`.
            log.error("nrvq.sidecar.remote_evaluator.client_misconfigured", problem=problem,
                      code="NRVQ-SDC-3049")
            return
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

    def _config_problem(self) -> str | None:
        """Why this sidecar cannot send any request, or None."""
        problem = request_problem(self._api_token, self._api_url)
        if problem is not None:
            return problem
        if self._max_retries < 0:
            return "the client settings are impossible (retries)"
        return None

    def _client_fault(self, problem: str) -> PolicyDecision:
        """Block a call this sidecar could not send or read; the fallback posture does not apply."""
        log.error("nrvq.sidecar.remote_evaluator.client_misconfigured", problem=problem,
                  code="NRVQ-SDC-3049")
        return _client_fault_decision(problem)

    async def _evaluate_upstream(self, event: ToolCallEvent) -> PolicyDecision:
        """POST the event to the central engine. A request that cannot be encoded, a local fault and a
        4xx refusal block; a transport error or 5xx follows ``settings.sdk_fallback_mode``."""
        problem = self._config_problem()
        if problem is not None:
            return self._client_fault(problem)
        if self._client is None:
            try:
                await self.connect()
            except Exception as exc:
                problem = f"the HTTP client could not be built ({type(exc).__name__})"
                log.error("nrvq.sidecar.remote_evaluator.client_misconfigured", problem=problem,
                          code="NRVQ-SDC-3049")
                return _client_fault_decision(problem)
        # Split payload / post / parse: the gap between what this client waits and what the API reports
        # measuring was ~46 ms with nowhere to attribute it. pydantic model_dump and JSON coding are CPU
        # work, and this container runs at 200m — where 8.1 ms of CPU is burned per call — so "the wire" and
        # "serialising for the wire" have to be told apart before either is blamed.
        _timer = PhaseTimer()
        # The body is encoded here, before the retry loop, and by the SDK client's encoder. Encoding is
        # local work that has nothing to do with whether the engine is up, so a failure to encode is
        # decided here, as a block.
        with _timer.phase("payload"):
            try:
                body = encode_evaluate_request(
                    event,
                    include=_REQUEST_FIELDS,
                    # Preserve the decision source so the central audit record is attributed to the sidecar.
                    update={"framework": event.framework or "sidecar"},
                )
            except UnencodableRequest as exc:
                log.error(
                    "nrvq.sidecar.remote_evaluator.unencodable",
                    error=str(exc)[:200],
                    code="NRVQ-SDC-3047",
                )
                return PolicyDecision(
                    decision="block",
                    rule_id="thin_proxy_request_unencodable",
                    reason=_UNENCODABLE_REASON,
                    trust_score=0.0,
                )
        # Retry transient failures before giving up. Without this a single dropped connection — a
        # rolling norviq-api restart, a node's conntrack entry expiring, one 503 from a terminating
        # pod — blocks a live agent's tool call outright. The SDK client has always retried with
        # backoff; the injected sidecar is the zero-code-change path and must be no less resilient.
        # Only transport errors and 5xx are retried: a 4xx is the engine answering with a refusal,
        # so retrying it just delays the same block.
        last_exc: Exception | None = None
        fault: str | None = None
        for attempt in range(self._max_retries + 1):
            try:
                with _timer.phase("post"):
                    resp = await self._client.post(
                        "/api/v1/evaluate", content=body, headers={"Content-Type": "application/json"}
                    )
                    resp.raise_for_status()
                with _timer.phase("parse"):
                    try:
                        data = resp.json()
                    except ValueError:
                        data = None
                    if not isinstance(data, dict) or data.get("decision") not in DECISIONS:
                        raise ClientFault(
                            f"the engine answered HTTP {resp.status_code} without a valid decision")
                    decision = PolicyDecision(
                        decision=data["decision"],
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
                if not 400 <= exc.response.status_code < 600:
                    fault = f"the API URL answered HTTP {exc.response.status_code}, not a decision"
                    break
                if exc.response.status_code < 500:
                    break  # the engine refused us (auth/bad request) — not retryable
            except ClientFault as exc:
                fault = str(exc)
                break
            except httpx.TransportError as exc:
                # Not retried when the fault is this sidecar's own; see `client_fault`.
                fault = client_fault(exc)
                if fault is not None:
                    break
                last_exc = exc
            except ssl.SSLError as exc:
                # Raised after the handshake, so httpcore did not wrap it. Not retried, as before.
                fault = client_fault(exc)
                last_exc = exc
                break
            except Exception as exc:  # unknown means block, as in the SDK client
                problem = client_fault(exc) or "unexpected error"
                log.error("nrvq.sidecar.remote_evaluator.client_misconfigured", problem=problem,
                          code="NRVQ-SDC-3049")
                return _client_fault_decision(problem)
            if attempt < self._max_retries:
                await asyncio.sleep((self._backoff_base_ms * (2**attempt)) / 1000)
        if fault is not None:
            return self._client_fault(fault)

        # Every attempt failed. A 4xx means the engine ANSWERED and refused us (bad/expired token,
        # malformed request) — that is never an outage and must never fail open, or a revoked
        # credential silently becomes a governance bypass. Only genuine unreachability (5xx, timeout,
        # connect error) honours the operator's configured posture, which now defaults to ALLOW so a
        # Norviq outage does not take the customer's agents down with it (see config.sdk_fallback_mode).
        # Both branches carry a distinct rule_id, so "we went unjudged" is countable rather than silent.
        refused = isinstance(last_exc, httpx.HTTPStatusError) and last_exc.response.status_code < 500
        mode = "block" if refused else settings.sdk_fallback_mode
        if mode == "allow":
            log.warning(
                "nrvq.sidecar.remote_evaluator.fail_open",
                error=redact_credentials(str(last_exc), self._api_token or ""),
                code="NRVQ-SDC-3036",
            )
            return PolicyDecision(
                decision="allow",
                rule_id="thin_proxy_fail_open",
                reason=_FAIL_OPEN_REASON,
                trust_score=0.0,
            )
        log.error("nrvq.sidecar.remote_evaluator.fail_closed",
                  error=redact_credentials(str(last_exc), self._api_token or ""), code="NRVQ-SDC-3031")
        return PolicyDecision(
            decision="block",
            rule_id="thin_proxy_fail_closed",
            reason=_ENGINE_REFUSED_REASON if refused else _FAIL_CLOSED_REASON,
            trust_score=0.0,
        )
