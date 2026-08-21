# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The MCP server registry: what an operator has DECIDED about a server.

`pins.py` answers "is this tool definition the one that was approved". This answers the question one
level up — "should this agent be talking to this server at all" — and it is the question the
rogue-server vector turns on. A tool from an unregistered server can be entirely innocuous on its own
terms: a clean description, a benign schema, a read verb. Gate A has nothing to say about it, and a
read is exempt from the write-scoping rule, so before this registry existed such a call passed every
check the product had.

STATUS IS THREE-VALUED ON PURPOSE.

    discovered  seen, never reviewed. The state a server lands in on first sight, and NEVER the state
                a server is promoted into automatically. Observed and approved must be distinguishable,
                for the same reason Gate A reports `scan_severity: "unknown"` rather than `"none"` for
                a definition it never scanned.
    registered  an operator said this server is expected here.
    blocked     an operator said it is not. Refused at DISCOVERY, not at call time — see the firewall's
                Gate A hook. For a poisoned description the description IS the payload, so refusing the
                call afterwards is too late; the text has already reached the model's context.

`writable` is deliberately a separate axis. "May I reach it" and "may I write through it" are different
questions, and a read-only knowledge base is an ordinary shape that one collapsed field cannot express.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from norviq.config import settings

import structlog

log = structlog.get_logger()

STATUS_DISCOVERED = "discovered"
STATUS_REGISTERED = "registered"
STATUS_BLOCKED = "blocked"
STATUSES: tuple[str, ...] = (STATUS_DISCOVERED, STATUS_REGISTERED, STATUS_BLOCKED)

#: The fields of a server's self-description that constitute its identity. `serverInfo` names the
#: implementation; `instructions` is free text the host may put in front of the model, so a change
#: there is a content change in the same sense a tool description is.
_IDENTITY_FIELDS = ("name", "version", "instructions")


def canonical_identity(server_info: dict[str, Any] | None, instructions: str,
                       tool_names: list[str] | None = None) -> str:
    """Canonical JSON of a server's identity surface, for hashing.

    Includes the SORTED TOOL-NAME SET, because the wholesale-swap case is a server-level consent change
    that no per-tool pin can see: every approved tool vanishes and different ones answer under the same
    server id, and each individual tool looks like an ordinary first sight.
    """
    info = server_info or {}
    subset: dict[str, Any] = {k: info.get(k) for k in ("name", "version") if k in info}
    subset["instructions"] = instructions or ""
    subset["tools"] = sorted(tool_names or [])
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def identity_digest(server_info: dict[str, Any] | None, instructions: str,
                    tool_names: list[str] | None = None) -> str:
    """sha256 over the canonical identity surface."""
    return hashlib.sha256(
        canonical_identity(server_info, instructions, tool_names).encode("utf-8")
    ).hexdigest()


@dataclass
class ServerDecision:
    """One operator decision about one server, as the proxy needs to see it."""

    server_id: str
    status: str = STATUS_DISCOVERED
    writable: bool = False
    note: str = ""

    @property
    def reachable(self) -> bool:
        """May the agent see this server's tools at all?

        `discovered` is reachable. A server nobody has reviewed is not thereby hostile, and refusing
        every unreviewed server would mean the product blocks its own first run — the registry would be
        unusable before it was populated. What `discovered` does is make the control
        (`mcp_unregistered_server`) able to SAY so, which is the difference between a posture the
        operator chooses and one the product imposes on day one.
        """
        return self.status != STATUS_BLOCKED


@dataclass
class ServerRegistry:
    """The decisions this proxy knows about, loaded once at startup.

    Read on the DISCOVERY path only, exactly like the pin store — the call path never touches it. A
    server-level decision changes at operator speed, not per call, so a per-request lookup would buy
    nothing and put the control plane in front of every tool invocation.
    """

    decisions: dict[str, ServerDecision] = field(default_factory=dict)
    # True while the control plane could not be reached, so `decisions` is empty or stale.
    #
    # It lives on the REGISTRY, not only on the store, because the firewall holds this object and never
    # sees the store. `ControlPlaneServerStore.degraded` already existed, was maintained correctly, and
    # was read by nothing anywhere in the tree — a status flag with no consumer is the same defect as
    # the control it describes: it reports a state that changes nothing.
    degraded: bool = False

    def get(self, server_id: str) -> ServerDecision:
        """The decision for a server, or an unreviewed one. Never returns None.

        Defaulting to `discovered` rather than raising means a server the registry has not heard of
        behaves like a newly-seen one, which is what it is.
        """
        return self.decisions.get(server_id) or ServerDecision(server_id=server_id)

    def put(self, decision: ServerDecision) -> None:
        self.decisions[decision.server_id] = decision

    @classmethod
    def from_rows(cls, rows: list[dict[str, Any]]) -> ServerRegistry:
        """Build from the control plane's `GET /mcp/servers` payload."""
        reg = cls()
        for row in rows:
            sid = str(row.get("server_id", ""))
            if not sid:
                continue
            status = str(row.get("status") or STATUS_DISCOVERED)
            if status not in STATUSES:
                # An unrecognised status is a newer control plane talking to an older proxy. Treated
                # as unreviewed rather than as blocked: a rolling upgrade must not black out discovery
                # for every server the moment the API is a version ahead of the sidecars.
                log.warning("nrvq.mcp.servers.unknown_status", server=sid, status=status,
                            code="NRVQ-MCP-5072")
                status = STATUS_DISCOVERED
            reg.put(ServerDecision(
                server_id=sid,
                status=status,
                writable=bool(row.get("writable")),
                note=str(row.get("note") or ""),
            ))
        return reg


class ControlPlaneServerStore:
    """The registry as the proxy sees it: loaded from the API, held in memory, refreshed on a timer.

    Read-only by construction. The proxy never writes a decision — deciding is a human act performed
    in the console, and a compromised sidecar that could register itself would make the whole control
    a formality. That is the same reasoning that keeps the approved digest inside the control plane in
    `ControlPlanePinStore`, and it is why this class has a `load()` and no `flush()`.

    Consulted on the DISCOVERY path only, like pins. A server-level decision changes at operator
    speed; putting an HTTP call in front of every `tools/call` would buy nothing and would make the
    control plane a hard dependency of every invocation.

    THE HONEST LIMIT, stated because it is a fail-open. Before the first successful load the registry
    is empty, so every server reads `discovered` and nothing is withheld. A proxy that starts while
    the control plane is unreachable therefore does NOT enforce a `blocked` decision until it can read
    one. The alternative — withhold every tool until the registry is readable — was tried in this
    codebase in a different form and is documented in `HttpProxy._install_pin_store`: three proxies
    refused every call at Gate A for eleven hours across an API rollout, nothing reached the audit
    log, and the failure was indistinguishable from a defence working. Availability wins here for the
    same reason it wins there, with the same two mitigations: it is logged loudly at NRVQ-MCP-5070,
    and Gate B is unaffected — every call is still evaluated, so a policy that refuses an unregistered
    server still refuses it.

    A load that FAILS after a success keeps the last good copy rather than clearing it, so a `blocked`
    server does not become reachable because the API restarted. Only a successful load replaces the
    map, which is also what makes an un-blocking take effect.
    """

    def __init__(self, namespace: str, api_url: str = "", token: str = "") -> None:
        #: Writable because the HTTP transport learns it from an ASYNC identity resolution while the
        #: firewall needs the registry object at construction. Set it before the first `load()`.
        self.namespace = namespace
        self._api_url = (api_url or settings.api_url).rstrip("/")
        self._token = token if token else settings.api_token
        self._registry = ServerRegistry()
        self._loaded = False
        self._degraded = False
        self._refresh_task: asyncio.Task | None = None

    @property
    def registry(self) -> ServerRegistry:
        """The live registry object. Identity is stable across loads on purpose — the firewall holds
        a reference to it, so a refresh has to mutate in place or the proxy keeps its startup copy."""
        return self._registry

    @property
    def degraded(self) -> bool:
        return self._degraded

    @property
    def loaded(self) -> bool:
        """Whether a load has EVER succeeded. False means "no decisions are being enforced"."""
        return self._loaded

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def load(self) -> bool:
        """Pull this namespace's server decisions into memory. Never raises; True on success."""
        import httpx  # local: keeps the module importable where httpx is absent (pure-unit tests)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
                resp = await client.get(
                    f"{self._api_url}/api/v1/mcp/servers",
                    params={"namespace": self.namespace},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                rows = resp.json()
        except Exception as exc:  # noqa: BLE001 — availability choice, see the class docstring
            self._degraded = True
            self._registry.degraded = True   # the firewall reads the registry, not this store
            log.error(
                "nrvq.mcp.servers.control_plane_unreachable",
                namespace=self.namespace, error=str(exc), code="NRVQ-MCP-5070",
                detail=("no server decision is being enforced at discovery" if not self._loaded
                        else "serving the last known decisions; a change made since is not visible"),
                hint="Gate B is unaffected — every tool call is still evaluated against policy",
            )
            return False

        fresh = ServerRegistry.from_rows(rows if isinstance(rows, list) else [])
        # Mutate in place: the firewall holds this exact object.
        self._registry.decisions.clear()
        self._registry.decisions.update(fresh.decisions)
        if self._degraded:
            log.info("nrvq.mcp.servers.control_plane_recovered", namespace=self.namespace,
                     code="NRVQ-MCP-5071")
        self._degraded = False
        self._registry.degraded = False
        self._loaded = True
        blocked = sum(1 for d in self._registry.decisions.values() if d.status == STATUS_BLOCKED)
        log.info("nrvq.mcp.servers.loaded", namespace=self.namespace,
                 count=len(self._registry.decisions), blocked=blocked, code="NRVQ-MCP-5071")
        return True

    def start_refresh(self, interval_s: int) -> None:
        """Re-`load()` every `interval_s` seconds. No-op when <= 0 or already running.

        A poll, for the reason `ControlPlanePinStore.start_refresh` gives: the proxy is the party that
        must not block, and a push channel would mean the control plane holding a connection per
        sidecar. The cost is that a BLOCK takes up to one interval to reach a running proxy — which is
        the property that matters most here, since blocking is the urgent direction of this control.
        """
        if interval_s <= 0 or self._refresh_task is not None:
            return

        async def _loop() -> None:
            while True:
                await asyncio.sleep(interval_s)
                await self.load()

        self._refresh_task = asyncio.create_task(_loop())

    async def aclose(self) -> None:
        """Stop the refresh task. Safe to call more than once."""
        task = self._refresh_task
        self._refresh_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
