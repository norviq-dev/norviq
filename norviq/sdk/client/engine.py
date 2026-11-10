# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async policy engine client for SDK enforcement decisions."""

from __future__ import annotations

import asyncio
import collections
import json
import math
import re
import ssl
import weakref
from typing import Any, get_args
from time import monotonic
from urllib.parse import urlsplit

import httpx
import structlog

from norviq.bearer import bearer_token_problem, redact_credentials
from norviq.config import settings
from norviq.exceptions import NorviqError, NorviqTimeoutError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()


def _non_finite(value: Any) -> bool:
    """Whether a float inf/nan occurs anywhere in `value`.

    Each container is visited once (by identity): a self-referential tool_params made this loop
    forever, holding the event loop while memory grew, and a structure that shares one sub-object many
    times would be walked once per reference. A cycle is left to the encoder, which refuses it.
    Bounded at `_MAX_PARAM_NODES` containers; past that the request is refused as unencodable.
    """
    stack = [value]
    visited: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, float):
            if not math.isfinite(node):
                return True
            continue
        if not isinstance(node, _CONTAINERS):
            continue
        if id(node) in visited:
            continue
        visited.add(id(node))
        if len(visited) > _MAX_PARAM_NODES:
            raise UnencodableRequest(f"more than {_MAX_PARAM_NODES} containers in the call")
        if isinstance(node, dict):
            # Keys too: the encoder writes a float key as a string, so an inf/nan key reaches the
            # engine as text it cannot tell from an ordinary one.
            stack.extend(node.keys())
            stack.extend(node.values())
        else:
            stack.extend(node)
    return False


# Every container the encoder serialises as an object or array. frozenset and deque were walked past,
# so an inf inside one reached the engine as null.
_CONTAINERS = (dict, list, tuple, set, frozenset, collections.deque)


# Containers `_non_finite` will visit in one call. Far above a real tool call; a structure past it is
# not one this process will encode for the engine.
_MAX_PARAM_NODES = 100_000


class UnencodableRequest(Exception):
    """The evaluate request could not be serialised in this process (see `encode_evaluate_request`)."""


def encode_evaluate_request(
    event: ToolCallEvent,
    *,
    include: set[str] | None = None,
    update: dict[str, Any] | None = None,
) -> bytes:
    """The `/api/v1/evaluate` request body for `event`, as it goes on the wire.

    Raises `UnencodableRequest` when this process cannot produce it. Both clients of the endpoint, this
    module's `PolicyEngineClient` and the injected sidecar's `RemoteEvaluator`, encode through here, so a
    call one of them cannot send is refused by the other as well instead of the two drifting apart.
    `include` limits the event fields sent (the sidecar sends a subset); `update` sets values after the
    event is serialised and before the JSON is written, so they pass through the same checks.

    Non-finite floats are refused BEFORE pydantic sees them: `model_dump(mode="json")` writes inf and
    nan as null, so the engine would decide on `amount: null` while the tool runs with the caller's
    real value. The JSON parameters are the ones httpx uses for `json=`.
    """
    if _non_finite(event.tool_params) or _non_finite(event.mcp):
        raise UnencodableRequest("a non-finite number (inf or nan) in the call")
    try:
        document = event.model_dump(mode="json", include=include)
        if update:
            document.update(update)
        return json.dumps(document, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise UnencodableRequest(str(exc)) from exc


class ClientFault(Exception):
    """This client cannot send a valid request, or cannot read a decision from the answer.

    Deterministic: the next attempt fails the same way, so it is not an outage and the fallback mode
    does not apply. The message never contains the token.
    """


#: The decisions an engine answer may carry.
DECISIONS = frozenset(get_args(PolicyDecision.model_fields["decision"].annotation))

# ssl.SSLError reasons for an https URL whose server answered without TLS.
_NOT_TLS = frozenset({"WRONG_VERSION_NUMBER", "HTTP_REQUEST", "HTTPS_PROXY_REQUEST", "UNKNOWN_PROTOCOL",
                      "PACKET_LENGTH_TOO_LONG"})
# TLS alerts that name the certificate this client presented, or the lack of one, as refused. The
# server sends the same alert on every attempt while its configuration stands. A server whose own CRL
# is missing or stale also sends UNKNOWN_CA or CERTIFICATE_EXPIRED; that blocks too, as the engine
# refusing. HANDSHAKE_FAILURE is not here: a server sends it for no shared cipher or no certificate of
# its own as well, so it does not say whose fault it is.
_CERT_REFUSED = frozenset({"TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_CERTIFICATE_EXPIRED",
                           "SSLV3_ALERT_BAD_CERTIFICATE", "SSLV3_ALERT_CERTIFICATE_REVOKED",
                           "SSLV3_ALERT_CERTIFICATE_UNKNOWN", "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
                           "TLSV13_ALERT_CERTIFICATE_REQUIRED", "TLSV1_ALERT_ACCESS_DENIED"})
# The status a forward proxy answered the CONNECT with, as httpx reports it: "407 Proxy Authentication
# Required". A 5xx is the proxy failing to reach the engine; any other status is its refusal.
_PROXY_STATUS = re.compile(r"(\d+)\b")


def engine_url_problem(url: str) -> str | None:
    """Why `url` cannot reach any engine, or None when it may."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "it cannot be parsed"
    if parts.scheme not in ("http", "https"):
        return "its scheme is missing or is not http or https"
    if not parts.hostname:
        return "it has no host"
    if port is not None and not 1 <= port <= 65535:
        return "its port is outside 1-65535"
    return None


def request_problem(token: str, url: str) -> str | None:
    """Why no request with `token` can be sent to `url`, or None. Never contains the token."""
    problem = bearer_token_problem(token or "")
    if problem is not None:
        return f"the API token cannot be sent: {problem}"
    problem = engine_url_problem(url)
    if problem is not None:
        return f"the engine URL is unusable: {problem}"
    return None


def client_fault(exc: BaseException) -> str | None:
    """Why `exc`, raised by a request to the engine, is this client's own fault, or None.

    None means an `httpx.TransportError` that looks like the network or the engine failing (a timeout,
    a refused or reset connection, a DNS failure, a dropped TLS handshake, a proxy 5xx). Those follow
    the fallback mode. So does a bare `ssl.SSLError`: httpcore wraps TLS errors from the handshake
    only, and one raised after it (a corrupted record, an alert) arrives unwrapped. Anything else that
    is not a transport error is a fault: unknown means block.
    """
    if isinstance(exc, ClientFault):
        return str(exc)
    if isinstance(exc, (httpx.LocalProtocolError, httpx.UnsupportedProtocol, httpx.InvalidURL)):
        return f"the request could not be sent ({type(exc).__name__})"
    if isinstance(exc, httpx.ProxyError):
        status = _PROXY_STATUS.match(str(exc))
        if status is None or 500 <= int(status.group(1)) < 600:
            return None
        return f"the forward proxy refused the connection (HTTP {status.group(1)})"
    if not isinstance(exc, (httpx.TransportError, ssl.SSLError)):
        return f"unexpected error ({type(exc).__name__})"
    seen: set[int] = set()
    link: BaseException | None = exc
    while link is not None and id(link) not in seen:
        seen.add(id(link))
        if isinstance(link, ssl.SSLCertVerificationError):
            return "the engine's TLS certificate failed verification"
        if (isinstance(link, ssl.SSLError) and isinstance(exc, httpx.ConnectError)
                and getattr(link, "reason", None) in _NOT_TLS):
            return "the engine URL is https but the server did not answer with TLS"
        if isinstance(link, ssl.SSLError) and getattr(link, "reason", None) in _CERT_REFUSED:
            return f"the engine refused this client's TLS certificate ({link.reason})"
        link = link.__cause__ or link.__context__
    return None


def _decision_body(response: httpx.Response) -> dict:
    """The decision in a 2xx answer, or `ClientFault` when the body is not one."""
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict) or data.get("decision") not in DECISIONS:
        raise ClientFault(f"the engine answered HTTP {response.status_code} without a valid decision")
    return data


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
        # Encoded HERE, before any network call, so that failing to build the request is told apart
        # from the engine failing to answer it. A tool_params tree nested ~255 levels deep makes
        # pydantic's serialiser raise "Circular reference detected (depth exceeded)"; raised inside
        # `client.post` it fell to `_handle_unknown_error` and the OUTAGE fallback, so with
        # sdk_fallback_mode=allow a call nobody could evaluate was allowed. The caller chooses the
        # params, so that was a bypass on demand. A request this process cannot encode is not an
        # outage: `evaluate` blocks it whatever the fallback mode. Non-finite numbers, and why they
        # are checked before pydantic, are covered in `encode_evaluate_request`.
        body = encode_evaluate_request(event)
        for attempt in range(self._max_retries + 1):
            try:
                # The central API mounts the evaluate router at /api/v1 (norviq/api/main.py) — same
                # endpoint + auth contract the thin-proxy sidecar's RemoteEvaluator uses.
                response = await client.post("/api/v1/evaluate", content=body,
                                             headers={"content-type": "application/json"})
                response.raise_for_status()
                self._record_success()
                return _decision_body(response)
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
                if 500 <= exc.response.status_code < 600:
                    self._record_failure()
                raise
            except httpx.TimeoutException as exc:
                self._record_failure()
                if attempt >= self._max_retries:
                    raise NorviqTimeoutError(timeout_ms=self._timeout_ms) from exc
                await asyncio.sleep((self._backoff_base_ms * (2**attempt)) / 1000)
            except httpx.TransportError as exc:
                # Not retried or counted when the fault is this client's own; see `client_fault`.
                fault = client_fault(exc)
                if fault is not None:
                    raise ClientFault(fault) from None
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

    def _config_problem(self) -> str | None:
        """Why this client cannot send any request, or None."""
        problem = request_problem(self._token, self._base_url)
        if problem is not None:
            return problem
        if not self._timeout_ms > 0 or self._max_retries < 0 or settings.sdk_http_max_connections <= 0:
            return "the client settings are impossible (timeout, retries or max connections)"
        return None

    def _client_fault(self, event: ToolCallEvent, problem: str) -> PolicyDecision:
        """Block a call this client could not send or read; the fallback mode does not apply."""
        log.error("nrvq.sdk.evaluate.client_misconfigured", event_id=event.event_id, problem=problem,
                  code="NRVQ-SDK-1018")
        return PolicyDecision(
            decision="block",
            rule_id="engine_client_misconfigured",
            reason=(f"This client could not send a valid request to the policy engine: {problem}. "
                    "This is not an engine outage, and the fallback mode does not apply."),
            event_id=event.event_id,
        )

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
        if status < 400 or status >= 600:
            # A redirect (not followed) or a non-standard status is not the engine answering here.
            return self._client_fault(event, f"the engine URL answered HTTP {status}, not a decision")
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
        """The engine could not be reached on any attempt; return the fallback decision."""
        log.error("nrvq.sdk.evaluate.error", event_id=event.event_id,
                  error=redact_credentials(str(exc), self._token or ""), code="NRVQ-SDK-1000")
        return self._fallback_decision(event)

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Send ToolCallEvent to engine and return PolicyDecision."""
        problem = self._config_problem()
        if problem is not None:
            return self._client_fault(event, problem)
        if self._is_circuit_open():
            log.warning("nrvq.sdk.evaluate.circuit_open", event_id=event.event_id, code="NRVQ-SDK-1013")
            return self._fallback_decision(event)
        try:
            decision = PolicyDecision(**(await self._post(event)))
            self._log_success(event.event_id, decision.decision)
            return decision
        except UnencodableRequest as exc:
            log.error("nrvq.sdk.evaluate.unencodable", event_id=event.event_id, error=str(exc)[:200],
                      code="NRVQ-SDK-1016")
            return PolicyDecision(
                decision="block",
                rule_id="engine_request_unencodable",
                reason=("The evaluate request could not be encoded locally (for example, arguments "
                        "nested too deeply); this is not an engine outage, and fail-open does not apply."),
                event_id=event.event_id,
            )
        except ClientFault as exc:
            return self._client_fault(event, str(exc))
        except NorviqTimeoutError as exc:
            return self._handle_timeout(event, exc)
        except httpx.HTTPStatusError as exc:
            return self._handle_http_error(event, exc)
        except httpx.TransportError as exc:
            return self._handle_unknown_error(event, exc)
        except ssl.SSLError as exc:
            # Raised after the handshake, so httpcore did not wrap it. Not retried or counted, as before.
            fault = client_fault(exc)
            if fault is not None:
                return self._client_fault(event, fault)
            return self._handle_unknown_error(event, exc)
        except Exception as exc:
            # Unknown means block: only a transport error may follow the fallback mode.
            return self._client_fault(event, client_fault(exc) or "unexpected error")

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
