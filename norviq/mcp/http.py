# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Streamable-HTTP transport driver.

MCP's streamable-HTTP transport is asymmetric in a way that matters for a firewall:

  * The client POSTs a JSON-RPC message to a single endpoint. The response is EITHER a single
    ``application/json`` body (one message) OR a ``text/event-stream`` carrying several messages —
    the server chooses per request.
  * The client may also open a standalone GET SSE stream on the same endpoint, on which the SERVER
    initiates messages (notifications, and server->client requests like ``sampling/createMessage``).
  * ``Mcp-Session-Id`` bound subsequent requests to a session in 2025-06-18. The 2026-07-28
    revision REMOVES it along with protocol-level sessions (SEP-2567), and list results no longer
    vary per connection. It is therefore accepted-and-ignored here: see `_firewall_for`.

So the proxy must mediate three distinct flows, and the SSE ones are STREAMS: a `tools/list`
response can arrive as one event inside a stream that stays open afterwards. Buffering the stream to
inspect it would break the transport's whole point, so events are parsed and re-emitted one at a
time as they arrive, and back-pressure is preserved by streaming through rather than collecting.

IDENTITY IN HTTP MODE. Placement is still a SIDECAR in the agent's pod, not a shared gateway, for
the reason given in stdio.py: the proxy's own SVID is the caller's identity only when the proxy runs
where the caller runs. A shared gateway would have to attest callers over the network — solvable
(mTLS + SPIFFE, which Norviq's internal-TLS path already does), but it is a different, larger design
and this spike does not pretend to have validated it. Client-supplied identity is never read.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import AsyncIterator

import httpx
import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from norviq.config import settings
from norviq.engine.identity import SPIFFEResolver
from norviq.mcp import protocol as P
from norviq.mcp.firewall import McpFirewall
from norviq.mcp.pins import ControlPlanePinStore, PinRegistry, build_store, effective_store_kind
from norviq.mcp.servers import ControlPlaneServerStore
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()

_SSE = "text/event-stream"
# Headers that belong to THIS hop and must not be copied across it. Content-Length in particular is
# wrong the moment the firewall rewrites a body, and a stale one truncates the response.
_HOP_HEADERS = frozenset({
    "content-length", "transfer-encoding", "connection", "keep-alive",
    "host", "upgrade", "te", "trailer", "proxy-authorization", "proxy-authenticate",
})


class HttpProxy:
    """Streamable-HTTP MCP proxy. One firewall instance per ATTESTED CALLER IDENTITY."""

    def __init__(self, upstream: str, host: str, port: int, server_id: str,
                 tool_name_prefix: str = "") -> None:
        self._upstream = upstream.rstrip("/")
        self._host = host
        self._port = port
        self._server_id = server_id
        self._prefix = tool_name_prefix
        self._client: httpx.AsyncClient | None = None
        self._engine: PolicyEngineClient | None = None
        # Keyed by ATTESTED identity, never by anything the caller sends. See _firewall_for.
        self._firewalls: dict[str, McpFirewall] = {}
        self._identity_key: str | None = None
        # Pins are per-SERVER, not per-session: a rug pull that reset itself every time a client
        # reconnected would not be detectable at all.
        #
        # `memory` is refused on this transport. Under 2026-07-28 any request may land on any
        # instance (SEP-2567), so a per-process pin store means instance A approves a definition that
        # instance B has never seen — every replica reports first_seen forever and drift is
        # undetectable across the fleet. It is a silent degradation of the control, not an outage,
        # which is exactly the kind that survives to production. `file` is allowed because an
        # operator choosing it has chosen shared storage deliberately.
        # THE UPGRADE USED TO BE COSMETIC. This branch logged "using: control-plane", set
        # `_pin_store_kind = "control-plane"`, and then called `build_store("control-plane", ...)` —
        # which knew only `file` and returned a MemoryPinStore. So the transport that most needs a
        # shared store announced that it had one, reported it on every surface, and ran per-process
        # pins anyway. `build_store` now REFUSES that kind rather than falling through, and the real
        # store is constructed below.
        #
        # Construction is deferred to `run()` because `ControlPlanePinStore.load()` is awaited and
        # `__init__` is sync. Deferring is not a weakening: `load()` happens once at startup before
        # any traffic, exactly as the stdio path already does.
        pin_store = settings.mcp_pin_store
        if pin_store == "memory":
            log.warning(
                "nrvq.mcp.http.pin_store_upgraded",
                configured=pin_store, using="control-plane", code="NRVQ-MCP-5065",
                hint="an in-process pin store cannot detect drift when any request may land on any "
                     "instance; set NRVQ_MCP_PIN_STORE explicitly to silence this",
            )
            pin_store = "control-plane"
        # `file` with no location degrades to an in-process store. That degradation is deliberate — an
        # operator whose deployment works today must not be broken by an upgrade — but it must not be
        # SILENT, and the kind we report has to be the one we actually run. Recording the configured
        # value here while `build_store` hands back memory is how a surface ends up asserting
        # durability the process does not have.
        elif pin_store != effective_store_kind(pin_store, settings.mcp_pin_path):
            log.warning(
                "nrvq.mcp.http.pin_store_degraded",
                configured=pin_store, using=effective_store_kind(pin_store, settings.mcp_pin_path),
                code="NRVQ-MCP-5067",
                hint="NRVQ_MCP_PIN_STORE=file needs NRVQ_MCP_PIN_PATH; without it pins are held in "
                     "process, so a restart re-TOFUs every definition and drift is not detected",
            )
            pin_store = effective_store_kind(pin_store, settings.mcp_pin_path)
        self._pin_store_kind = pin_store
        self._pins = PinRegistry(
            # A local store for the local kinds; the control-plane store replaces it in `run()`.
            # Never `build_store(pin_store, ...)` with pin_store == "control-plane" — that is the
            # call that silently produced memory.
            store=build_store("memory" if pin_store == "control-plane" else pin_store, settings.mcp_pin_path),
            mode=settings.mcp_pin_mode,
        )
        self._lock = asyncio.Lock()
        # The control-plane recovery loop (BUG-026). None until a load actually fails.
        self._pin_retry_task: asyncio.Task | None = None
        # The MCP server registry. Constructed HERE, not in `run()`, even though its `load()` is
        # awaited later: `_firewall_for_caller` hands the firewall a reference to `.registry`, and a
        # store that appeared only in `run()` would leave any firewall built before it with its own
        # empty registry forever. Construction is sync and cheap; only the load needs a loop.
        #
        # Loaded on EVERY pin backend, unlike pins: choosing a local pin store is not a decision to
        # stop enforcing blocked servers.
        # Namespace is set in `run()` from the ATTESTED identity, not here. `settings.namespace` does
        # not exist — `getattr(settings, "namespace", "")` returned "" on every deployment there has
        # ever been, silently, because the fallback made the phantom read look deliberate. The stdio
        # transport had it right all along (`identity.namespace` from the SPIFFE resolver); this one
        # was reading a setting nobody defined.
        self._servers = ControlPlaneServerStore(namespace="")

    async def _install_server_registry(self) -> None:
        """Load the server decisions before the listener binds, then keep re-reading.

        No retry loop of its own: unlike the pin store there is nothing to swap in on success — the
        firewall already holds the registry object, and `start_refresh` re-attempts the load on the
        same interval whether or not the first one worked. A failure here is loud (NRVQ-MCP-5070) and
        recovers on the next tick.
        """
        self._servers.namespace = await self._attested_namespace()
        await self._servers.load()
        self._servers.start_refresh(settings.mcp_pin_refresh_s)

    async def _install_pin_store(self) -> None:
        """Swap in the durable, cross-pod store before the listener accepts anything.

        Only for the `control-plane` kind — `memory`/`file` are already correct from `__init__`.
        Failure to reach the control plane degrades to the local store WITH A LOUD LOG, matching the
        documented posture in `ControlPlanePinStore`: Gate B still evaluates every call, so what is
        lost is cross-pod drift detection, not enforcement. Silence would be the unacceptable part.

        On failure it now KEEPS TRYING. This ran once, and a proxy that started while the control
        plane was briefly unavailable stayed degraded for its whole process lifetime — no retry, no
        second chance, and the only evidence one line in a log at startup. Observed for real: three
        proxies ran for eleven hours across several API rollouts, lost the control plane, and refused
        every `tools/call` at Gate A. Nothing reached the engine, nothing reached the audit log, and
        the chat UI showed a red BLOCK badge — so a red-team run would have been scored as a defence
        that never happened. A restart was the only cure and nothing said so.
        """
        if self._pin_store_kind != "control-plane":
            return
        if await self._try_install_pin_store():
            return
        self._schedule_pin_store_retry()

    async def _attested_namespace(self) -> str:
        """The namespace from the ATTESTED identity — the same source stdio uses.

        Both control-plane stores on this transport read a `settings.namespace` that does not exist,
        so both addressed the control plane with an empty namespace. The `getattr` default is what
        hid it: a phantom setting with a fallback reads as a deliberate optional, and produces no
        error at any layer.
        """
        try:
            identity = await SPIFFEResolver().resolve()
        except Exception as exc:  # noqa: BLE001 — an unresolvable identity must not stop the proxy
            log.warning("nrvq.mcp.http.namespace_unresolved", error=str(exc), code="NRVQ-MCP-5073",
                        hint="control-plane pins and server decisions will not be namespace-scoped")
            return ""
        return getattr(identity, "namespace", "") or ""

    async def _try_install_pin_store(self) -> bool:
        """One attempt. True when the durable store is live and installed."""
        namespace = await self._attested_namespace()
        store = ControlPlanePinStore(
            namespace=namespace,
            server_id=self._server_id,
            mode=settings.mcp_pin_mode,
            transport="http",
        )
        try:
            await store.load()
            # Keep re-reading — see stdio.py. A revoke must reach a RUNNING proxy, not only the next
            # one to start.
            store.start_refresh(settings.mcp_pin_refresh_s)
        except Exception as exc:  # noqa: BLE001 — availability choice, see the docstring
            log.error(
                "nrvq.mcp.http.pin_store_degraded",
                error=str(exc), server_id=self._server_id, code="NRVQ-MCP-5046",
                hint="cross-pod drift detection is unavailable until the control plane is reachable; "
                     "enforcement is unaffected; retrying in the background",
            )
            return False
        self._pins = PinRegistry(store=store, mode=settings.mcp_pin_mode)
        return True

    def _schedule_pin_store_retry(self) -> None:
        """Start the recovery loop, once. Idempotent so repeated failures cannot fan out tasks."""
        if self._pin_retry_task is not None and not self._pin_retry_task.done():
            return
        self._pin_retry_task = asyncio.create_task(self._retry_pin_store())

    async def _retry_pin_store(self) -> None:
        """Re-attempt until the control plane answers, then say so out loud.

        The recovery log matters as much as the recovery: an operator who saw the degraded line needs
        to know it ended, and "no further errors" is not evidence of that.
        """
        delay = max(1, int(settings.mcp_pin_refresh_s))
        while True:
            await asyncio.sleep(delay)
            if await self._try_install_pin_store():
                log.info(
                    "nrvq.mcp.http.pin_store_recovered",
                    server_id=self._server_id, code="NRVQ-MCP-5047",
                    hint="cross-pod drift detection is live again",
                )
                return

    # ------------------------------------------------------------------ wiring
    async def _firewall_for_caller(self) -> McpFirewall:
        """The firewall instance for the ATTESTED caller.

        This used to be keyed on the `Mcp-Session-Id` REQUEST HEADER, defaulting to the literal
        string "default". Two things were wrong with that, and the second is the serious one:

        1. 2026-07-28 removes the header (SEP-2567). Every request would then fall to "default", so
           every caller would share ONE firewall instance — and the firewall holds the discovered
           tool catalog. One caller's `tools/list` would decide the Gate-A verdicts applied to
           another caller's `tools/call`.
        2. Even while the header existed it was CLIENT-SUPPLIED. A caller could send any value,
           including another caller's, so it was never an isolation boundary — it was a correlation
           id doing a security job it was never able to do.

        The key is now the attested SVID, which is the same thing `/evaluate` binds the decision to
        (§3: identity is resolved from the credential and never read from an MCP message). In the
        sidecar placement this driver is built for there is exactly one caller, so the map holds one
        entry; keying it explicitly is what makes that a property rather than a coincidence.

        Reusing one instance across requests is also what the stateless revision asks for: list
        results no longer vary per connection, so a catalog that reset per "session" would re-derive
        the same thing and lose drift detection in between.
        """
        key = await self._attested_key()
        fw = self._firewalls.get(key)
        if fw is None:
            fw = McpFirewall(
                interceptor=ToolInterceptor(self._engine, SPIFFEResolver()),
                server_id=self._server_id,
                session_id=f"mcp-http-{key}",
                pins=self._pins,
                servers=self._servers.registry,
                tool_name_prefix=self._prefix,
            )
            # Bounded anyway. The key is attested now, so a peer cannot mint entries — but a resolver
            # returning a varying id (a misconfiguration) should degrade to eviction, not to a memory
            # exhaustion primitive. Pins live in the shared registry, so an evicted entry only loses
            # its in-memory catalog and drift detection stays intact.
            if len(self._firewalls) >= 64:
                self._firewalls.pop(next(iter(self._firewalls)), None)
            self._firewalls[key] = fw
        return fw

    async def _attested_key(self) -> str:
        """Stable key for the caller this proxy runs alongside, from its attested identity."""
        if self._identity_key is None:
            identity = await SPIFFEResolver().resolve()
            self._identity_key = (
                getattr(identity, "spiffe_id", "")
                or f"ns/{getattr(identity, 'namespace', '')}/sa/{getattr(identity, 'service_account', '')}"
            )
        return self._identity_key

    @staticmethod
    def _forward_headers(headers) -> dict[str, str]:
        return {k: v for k, v in headers.items() if k.lower() not in _HOP_HEADERS}

    # ------------------------------------------------------------------ routes
    async def _handle_post(self, request: Request) -> Response:
        """Client -> server. One JSON-RPC message in; JSON or an SSE stream back."""
        raw = await request.body()
        fw = await self._firewall_for_caller()
        msg = P.decode(raw)
        if msg is None:
            return JSONResponse(P.error_response(None, P.E_PARSE, "invalid JSON-RPC payload"), status_code=400)

        mediation = await fw.on_client_message(msg)
        if mediation.reply is not None and mediation.forward is None:
            # Answered locally: the upstream is never contacted. This is the block path, and the
            # 200 is correct — the JSON-RPC envelope carries the refusal, not the HTTP status.
            return Response(mediation.reply, media_type="application/json")
        if mediation.forward is None:
            return JSONResponse(P.error_response(msg.id, P.E_INTERNAL, "message refused by firewall"),
                                status_code=400)

        upstream = await self._client.request(
            "POST", self._upstream, content=mediation.forward,
            headers={**self._forward_headers(request.headers), "content-type": "application/json"},
        ) if not _wants_stream(request) else None

        if upstream is not None and _SSE not in upstream.headers.get("content-type", ""):
            out = await self._mediate_server_bytes(fw, upstream.content)
            return Response(out, status_code=upstream.status_code,
                            headers=_passthrough(upstream.headers), media_type="application/json")

        # Either the client asked for a stream, or the server answered with one. Stream through,
        # mediating each SSE event as it arrives so nothing is buffered.
        return await self._stream_through(fw, "POST", request, mediation.forward)

    async def _handle_get(self, request: Request) -> Response:
        """Standalone SSE stream: server -> client, including server-initiated requests."""
        return await self._stream_through(await self._firewall_for_caller(), "GET", request, None)

    async def _handle_delete(self, request: Request) -> Response:
        """Session teardown.

        The catalog is deliberately NOT dropped here any more. It used to be keyed on a
        client-supplied header, so a DELETE discarded whatever that header pointed at; now the
        instance belongs to the attested caller, and a caller must not be able to reset its OWN
        Gate-A state by asking. Re-discovering a catalog is exactly how a rug pull would be laundered
        into a clean first sight. Pins are server-scoped and survive regardless.
        """
        upstream = await self._client.request(
            "DELETE", self._upstream, headers=self._forward_headers(request.headers))
        return Response(upstream.content, status_code=upstream.status_code,
                        headers=_passthrough(upstream.headers))

    # ------------------------------------------------------------------ streaming
    async def _stream_through(self, fw: McpFirewall, method: str, request: Request,
                              body: bytes | None) -> Response:
        headers = self._forward_headers(request.headers)
        if body is not None:
            headers["content-type"] = "application/json"

        async def events() -> AsyncIterator[bytes]:
            req = self._client.build_request(method, self._upstream, headers=headers, content=body)
            async with self._client.stream(
                method, self._upstream, headers=headers, content=body, timeout=None
            ) as resp:
                buffer = b""
                async for chunk in resp.aiter_bytes():
                    buffer += chunk
                    # SSE frames are separated by a blank line. Split on the boundary and emit whole
                    # frames only — a half-received frame must not be parsed, and must not be held
                    # back longer than it takes to complete.
                    while b"\n\n" in buffer:
                        frame, buffer = buffer.split(b"\n\n", 1)
                        yield await self._mediate_frame(fw, frame) + b"\n\n"
                if buffer.strip():
                    yield await self._mediate_frame(fw, buffer)
            del req

        return StreamingResponse(events(), media_type=_SSE, headers={"cache-control": "no-cache"})

    async def _mediate_frame(self, fw: McpFirewall, frame: bytes) -> bytes:
        """Mediate the JSON payload of one SSE frame, preserving every other SSE field.

        Only `data:` lines carry the JSON-RPC message; `event:`, `id:` and `retry:` are transport
        bookkeeping the client needs intact (`id:` in particular drives resumption).
        """
        out_lines: list[bytes] = []
        for line in frame.split(b"\n"):
            if not line.startswith(b"data:"):
                out_lines.append(line)
                continue
            payload = line[5:].strip()
            mediated = await self._mediate_server_bytes(fw, payload)
            out_lines.append(b"data: " + mediated if mediated else b"data: ")
        return b"\n".join(out_lines)

    async def _mediate_server_bytes(self, fw: McpFirewall, payload: bytes) -> bytes:
        msg = P.decode(payload)
        if msg is None:
            # FAIL CLOSED, like stdio does (`nrvq.mcp.server.undecodable_dropped`). This used to
            # `return payload`, handing the bytes to the client untouched — so anything this proxy
            # could not PARSE skipped both gates entirely. The server chooses the framing, so that is
            # a bypass it can take at will: split one JSON-RPC message across two SSE `data:` frames,
            # or emit deliberately malformed JSON, and neither the injection fence nor the output DLP
            # mask ever runs on content the client is perfectly able to reassemble.
            #
            # `b""` is the same value this method already returns for a refused message, so both
            # callers — the SSE splitter and the non-streaming JSON path — handle it without change.
            log.warning("nrvq.mcp.server.undecodable_dropped", bytes=len(payload),
                        transport="http", code="NRVQ-MCP-5004")
            return b""
        result = await fw.on_server_message(msg)
        if result.reply is not None:
            # A server-initiated request we refused. On this transport the reply travels back as a
            # separate POST rather than inline, so it is dispatched without blocking the stream.
            asyncio.create_task(self._post_back(result.reply))
        if result.forward is None:
            return b""
        return result.forward.rstrip(b"\n")

    async def _post_back(self, payload: bytes) -> None:
        with contextlib.suppress(Exception):
            await self._client.post(self._upstream, content=payload,
                                    headers={"content-type": "application/json"})

    # ------------------------------------------------------------------ lifecycle
    async def run(self) -> int:
        import uvicorn

        self._engine = PolicyEngineClient()
        # BEFORE the listener binds. A request arriving against the per-process fallback would take a
        # first_seen TOFU decision this pod would then never reconcile with the shared store.
        await self._install_pin_store()
        await self._install_server_registry()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=5.0),
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        )
        app = Starlette(routes=[
            Route("/mcp", self._handle_post, methods=["POST"]),
            Route("/mcp", self._handle_get, methods=["GET"]),
            Route("/mcp", self._handle_delete, methods=["DELETE"]),
        ])
        log.info("nrvq.mcp.http.started", listen=f"{self._host}:{self._port}",
                 upstream=self._upstream, code="NRVQ-MCP-5006")
        config = uvicorn.Config(app, host=self._host, port=self._port, log_level="warning")
        try:
            await uvicorn.Server(config).serve()
        finally:
            if self._pin_retry_task is not None:
                self._pin_retry_task.cancel()
            with contextlib.suppress(Exception):
                await self._servers.aclose()
            await self._client.aclose()
            with contextlib.suppress(Exception):
                await self._engine.close()
        return 0


def _wants_stream(request: Request) -> bool:
    """Does the client REQUIRE an SSE stream, or merely accept one?

    The MCP spec has clients send ``Accept: application/json, text/event-stream``:
    they accept EITHER and the server chooses. Reading the mere presence of the
    SSE token as "send me a stream" made this true for every conforming client,
    so the proxy took the streaming path even when the upstream answered with a
    single ``application/json`` body. ``_stream_through`` then labelled that body
    ``text/event-stream`` and emitted it unframed — compact JSON has no ``\\n\\n``,
    so it fell out of the frame splitter whole. The client reads the header,
    switches to SSE parsing, and waits forever for a ``data:`` frame that is
    never coming.

    Found live: the MCP Python SDK hung on every ``initialize`` through the proxy
    while raw POSTs succeeded, which is what an agent behind the firewall would
    experience as a total outage. Only SSE-only clients get the stream now;
    everyone else takes the buffered path, and the upstream's own content-type
    still routes to ``_stream_through`` when IT answers with a stream.
    """
    accept = request.headers.get("accept", "")
    return _SSE in accept and "application/json" not in accept


def _passthrough(headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_HEADERS}
