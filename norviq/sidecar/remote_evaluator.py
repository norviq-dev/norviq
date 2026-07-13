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

import httpx
import structlog

from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent

log = structlog.get_logger()

# Reason surfaced when the central API is unreachable/unhealthy — distinct from a policy block.
_FAIL_CLOSED_REASON = "Thin-proxy sidecar could not reach the central policy engine (fail-closed)"


class RemoteEvaluator:
    """Evaluate tool calls by delegating to the central norviq-api /evaluate endpoint."""

    def __init__(self, api_url: str | None = None, api_token: str | None = None) -> None:
        """Store the central API base URL + service token; create a keep-alive client."""
        self._api_url = (api_url or settings.api_url).rstrip("/")
        self._api_token = api_token if api_token is not None else settings.api_token
        self._client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        """Open the shared keep-alive HTTP client (a small bounded pool, hot-path safe)."""
        headers = {"Content-Type": "application/json"}
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"
        self._client = httpx.AsyncClient(
            base_url=self._api_url,
            headers=headers,
            timeout=httpx.Timeout(2.0, connect=1.0),
            limits=httpx.Limits(max_keepalive_connections=8, max_connections=16),
        )
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
