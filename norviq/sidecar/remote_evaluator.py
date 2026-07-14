# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Thin-proxy evaluator (SIDE-2).

In proxy mode the injected sidecar does NOT run its own OPA/Redis/Postgres. It resolves identity
locally, then POSTs the tool call to the central norviq-api ``/api/v1/evaluate`` with a
namespace-scoped service JWT and maps the response to a ``PolicyDecision``. Every failure path
(network error, non-2xx, timeout, bad body) fails **closed** — returns a block decision so the
sidecar drops the tool call rather than forwarding it.
"""

from __future__ import annotations

import os
import ssl
import tempfile

import httpx
import structlog

from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()

# Reason surfaced when the central API is unreachable/unhealthy — distinct from a policy block.
_FAIL_CLOSED_REASON = "Thin-proxy sidecar could not reach the central policy engine (fail-closed)"


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
        """POST the event to the central engine; fail CLOSED (block) on any error."""
        if self._client is None:
            await self.connect()
        payload = {
            "tool_name": event.tool_name,
            "tool_params": event.tool_params,
            "agent_identity": event.agent_identity.model_dump(),
            "session_id": event.session_id,
            "call_depth": event.call_depth,
            # Preserve the decision source so the central audit record is attributed to the sidecar (OBS-2).
            "framework": event.framework or "sidecar",
        }
        try:
            resp = await self._client.post("/api/v1/evaluate", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return PolicyDecision(
                decision=data.get("decision", "block"),
                rule_id=data.get("rule_id", "remote_eval"),
                trust_score=float(data.get("trust_score", 0.0)),
                reason=data.get("reason", ""),
            )
        except Exception as exc:  # network / non-2xx / bad body — never forward on error
            log.error("nrvq.sidecar.remote_evaluator.fail_closed", error=str(exc), code="NRVQ-SDC-3031")
            return PolicyDecision(
                decision="block",
                rule_id="thin_proxy_fail_closed",
                reason=_FAIL_CLOSED_REASON,
                trust_score=0.0,
            )
