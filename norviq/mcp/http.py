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
import collections
import contextlib
import hashlib
import http.cookiejar
import json
import uuid
import weakref
from typing import Any, AsyncIterator

import httpx
import structlog
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from norviq.config import settings
from norviq.engine.identity import SPIFFEResolver
from norviq.mcp import protocol as P
from norviq.mcp.firewall import Correlation, McpFirewall, MediationResult
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
# Cap on the answer to the proxy's own `tools/list` (cold catalog). The same bound the stdio driver
# puts on one JSON-RPC line: far above a real catalogue, and it keeps a server from streaming without
# end into memory while a client's call waits.
_OWN_LIST_MAX_BYTES = 8 * 1024 * 1024
# Resumption bookkeeping, per attested caller (`_EventIds`). A resume with an evicted id resumes
# nothing (its responses are dropped), which is the fail-closed direction.
_MAX_EVENT_IDS = 4096                       # entries per caller
_MAX_EVENT_IDS_PER_STREAM = 64              # one stream cannot evict the others' entries
_MAX_EVENT_ID_BUDGET = 1024 * 1024          # bytes of server event ids held per caller
# Longest server SSE event id the proxy will remember. Ids are opaque cursors; a 4 MB one is not.
_MAX_SERVER_EVENT_ID_BYTES = 256
# The client headers the proxy's own `tools/list` carries: what identifies the connection, nothing
# that describes the call that triggered it. See `HttpProxy._upstream_lister`.
_MCP_METHOD_HEADER = "mcp-method"
_LIST_HEADER_ALLOWLIST = frozenset({"authorization", "mcp-session-id", "mcp-protocol-version"})


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
        # Per attested caller (its firewall): minted SSE event id -> (the server's event id, the POST
        # scope it came from, or None for a GET stream). See `_mint_event_id` and `_EventIds`. Keyed by
        # the firewall OBJECT, weakly, so an id minted for one caller is never found for another and
        # an evicted caller's ids go with it.
        self._event_ids: weakref.WeakKeyDictionary[McpFirewall, _EventIds] = weakref.WeakKeyDictionary()
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
            # build_store logs the degradation (NRVQ-MCP-5078) for every caller; this branch only
            # keeps the kind this surface REPORTS equal to the kind it actually runs.
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
        # Set only for the control-plane backend, exactly as in stdio.py. None means "nowhere to
        # report to", which is the truth for the `memory` and `file` kinds.
        self._pin_store: ControlPlanePinStore | None = None

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
        # Held by name, like stdio's `_pin_store`, so the reporting path does not have to reach into
        # PinRegistry's private `_store` to find out whether there is a control plane to talk to.
        self._pin_store = store
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
                # This driver never passed it, so every audit row and every pin this transport wrote
                # claimed `transport: "stdio"` — the firewall's default. A console filtering MCP
                # traffic by transport was reading a constant, and the one deployment shape where the
                # distinction matters (any-request-any-instance under 2026-07-28) was the one
                # mislabelled.
                transport="http",
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

        # This POST's own correlation scope: its response body answers its request and nothing else,
        # and a GET that resumes this POST's stream answers it at most once more. See `Correlation`.
        corr = fw.new_correlation()
        corr.upstream_headers = _connection_headers(request)
        mediation = await fw.on_client_message(msg, list_upstream=self._upstream_lister(request),
                                               corr=corr)
        if mediation.catalog_scanned:
            # The proxy listed a cold catalog itself; report it exactly as a forwarded tools/list.
            self._report_catalog(fw, mediation)
        if mediation.reply is not None and mediation.forward is None:
            # Answered locally: the upstream is never contacted. This is the block path, and the
            # 200 is correct — the JSON-RPC envelope carries the refusal, not the HTTP status.
            return Response(mediation.reply, media_type="application/json")
        if mediation.forward is None:
            return JSONResponse(P.error_response(msg.id, P.E_INTERNAL, "message refused by firewall"),
                                status_code=400)

        # EXACTLY ONE upstream request, always.
        #
        # This used to issue a buffered POST, and then — if the server happened to answer
        # `text/event-stream` rather than `application/json` — fall through to `_stream_through` with
        # the SAME `mediation.forward`, POSTing the approved tool call a second time. The first
        # response was discarded unread, so the client saw only the second execution while the tool
        # had run twice for one Gate-B decision and one audit row.
        #
        # The server chooses that content-type per request and is the untrusted party here, so any
        # MCP server could double every state-changing call it was permitted — send the email twice,
        # take the payment twice — with nothing surfacing to the client or the operator. "One
        # evaluate, one execution" is the invariant this whole file is built on.
        #
        # Opening the response as a stream lets the content-type be read BEFORE the body is consumed,
        # so one request serves both shapes.
        initialize = msg.method == P.M_INITIALIZE
        if _wants_stream(request):
            return await self._stream_through(fw, "POST", request, mediation.forward, corr,
                                              initialize=initialize)
        return await self._post_once(fw, request, mediation.forward, corr, initialize=initialize)

    def _upstream_lister(self, request: Request):
        """The firewall's way to send its own `tools/list` upstream for a cold catalog.

        The headers are the ones a `tools/list` from THIS client would carry, not the headers of the
        `tools/call` that triggered it. Copying the call's headers wholesale sent `Mcp-Method:
        tools/call`, `Mcp-Name: <tool>` and the `Mcp-Param-*` headers (built from model-controlled
        arguments) on a request whose body says `tools/list`: a 2026-07-28 server rejects that
        mismatch (`-32020`), which broke the self-list for exactly the stateless clients it exists
        for, and it put call-derived values on the wire before Gate B had decided the call.

        So only what identifies the CONNECTION is carried — `_LIST_HEADER_ALLOWLIST`: the
        credential the server authenticates (`Authorization`), the 2025-06-18 session
        (`Mcp-Session-Id`) and the negotiated revision (`Mcp-Protocol-Version`). `Mcp-Method` is set
        to `tools/list` when the client's own request carried an `Mcp-Method` (a client that speaks
        the header revision), and is absent otherwise, as it would be on that client's own list.

        Bounded in total bytes here and in time by the firewall. The answer is either one JSON body or
        an SSE stream, the server's choice per request as everywhere on this transport; on a stream the
        response is the frame whose id matches, and the stream is closed as soon as it is found.
        """
        client_headers = {k.lower(): v for k, v in request.headers.items()}
        headers = {k: v for k, v in client_headers.items() if k in _LIST_HEADER_ALLOWLIST}
        if _MCP_METHOD_HEADER in client_headers:
            headers[_MCP_METHOD_HEADER] = P.M_TOOLS_LIST
        headers["content-type"] = "application/json"
        headers["accept"] = f"application/json, {_SSE}"
        # No compression. The size cap counts the bytes httpx hands back, which are DECODED: a gzip
        # answer of a few hundred KiB expands to tens of MiB inside one chunk before any check can
        # run. Asking for identity and refusing anything else keeps the cap a cap on the wire.
        headers["accept-encoding"] = "identity"

        async def _list(own: P.JsonRpcMessage) -> P.JsonRpcMessage | None:
            async with self._client.stream("POST", self._upstream, headers=headers,
                                           content=own.raw) as resp:
                if resp.status_code >= 400:
                    raise RuntimeError(f"upstream answered HTTP {resp.status_code}")
                encoding = resp.headers.get("content-encoding", "identity").strip().lower()
                if encoding not in ("", "identity"):
                    raise RuntimeError(f"upstream answered with content-encoding {encoding[:32]!r}; "
                                       "the proxy's own list accepts identity only")
                streamed = _is_sse(resp.headers)
                buffer = b""
                received = 0
                lines = _SseLines()
                async for chunk in resp.aiter_bytes():
                    # TOTAL bytes, not the unparsed remainder: on a stream the remainder shrinks as
                    # frames are split off, so a server sending endless small non-matching frames
                    # would never reach a cap measured on it.
                    received += len(chunk)
                    if received > _OWN_LIST_MAX_BYTES:
                        raise RuntimeError(f"tools/list answer exceeded {_OWN_LIST_MAX_BYTES} bytes")
                    if not streamed:
                        buffer += chunk
                        continue
                    buffer += lines.feed(chunk)
                    while b"\n\n" in buffer:
                        frame, buffer = buffer.split(b"\n\n", 1)
                        found = _own_response_in_frame(frame, own.id)
                        if found is not None:
                            return found
                if streamed:
                    return _own_response_in_frame(buffer, own.id)
                found = P.decode(buffer)
                return found if found is not None and found.id == own.id else None

        # Single flight and back-off are per credential (see `McpFirewall._cold_lists`): a digest, so
        # the credential itself is never held as a key.
        _list.credential_key = hashlib.sha256(                       # type: ignore[attr-defined]
            f"{client_headers.get('authorization', '')}\0{client_headers.get('mcp-session-id', '')}"
            .encode("utf-8", "replace")).hexdigest()[:32]
        return _list

    async def _handle_get(self, request: Request) -> Response:
        """Standalone SSE stream: server -> client, including server-initiated requests.

        A plain GET stream answers NO request: the transport says a server MUST NOT send a response
        on it unless resuming a stream associated with a previous client request, and every response
        there is dropped (`Correlation.get_stream`). A GET carrying a Last-Event-ID the proxy minted on
        one of its POST streams resumes THAT stream: it is mediated in that POST's scope, and the
        server is sent its own event id back. An id the proxy did not mint resumes nothing.
        """
        fw = await self._firewall_for_caller()
        corr = fw.new_correlation(get_stream=True)
        server_last_id: str | None = None
        last = request.headers.get("last-event-id")
        if last is not None:
            ids = self._event_ids.get(fw)
            known = ids.get(last) if ids is not None else None
            if known is not None:
                server_last_id, origin = known
                if origin is not None:
                    corr = origin.resumption()
        if not corr.resumed:
            corr.upstream_headers = _connection_headers(request)
        return await self._stream_through(fw, "GET", request, None, corr,
                                          last_event_id=server_last_id)

    async def _handle_delete(self, request: Request) -> Response:
        """Session teardown.

        The catalog is deliberately NOT dropped here any more. It used to be keyed on a
        client-supplied header, so a DELETE discarded whatever that header pointed at; now the
        instance belongs to the attested caller, and a caller must not be able to reset its OWN
        Gate-A state by asking. Re-discovering a catalog is exactly how a rug pull would be laundered
        into a clean first sight. Pins are server-scoped and survive regardless.
        """
        # The status and headers are passed on; the BODY is not. It was read whole into memory, with no
        # bound, and handed to the client unmediated — server text on a path no gate looks at. A
        # DELETE's answer has nothing a client needs beyond its status.
        headers = {**self._forward_headers(request.headers), "accept-encoding": "identity"}
        async with self._client.stream("DELETE", self._upstream, headers=headers) as upstream:
            out = {k: v for k, v in _passthrough(upstream.headers).items() if k.lower() != "content-type"}
            return Response(b"", status_code=upstream.status_code, headers=out)

    # ------------------------------------------------------------------ streaming
    async def _stream_through(self, fw: McpFirewall, method: str, request: Request,
                              body: bytes | None, corr: Correlation, initialize: bool = False,
                              last_event_id: str | None = None) -> Response:
        headers = self._forward_headers(request.headers)
        if body is not None:
            headers["content-type"] = "application/json"
        if last_event_id is not None:
            # The client resumes with the id the proxy minted; the server knows its own.
            headers = {k: v for k, v in headers.items() if k.lower() != "last-event-id"}
            headers["last-event-id"] = last_event_id
        # Opened before the response is returned, so the session header can be decided from the
        # upstream's response headers (see `_session_header`).
        cm = self._client.stream(method, self._upstream, headers=headers, content=body, timeout=None)
        resp = await cm.__aenter__()
        out_headers = {"cache-control": "no-cache",
                       **self._session_header(request, resp.headers, initialize)}

        async def events() -> AsyncIterator[bytes]:
            try:
                async for out in self._pump_frames(fw, resp, corr):
                    yield out
            finally:
                await cm.__aexit__(None, None, None)

        return StreamingResponse(events(), media_type=_SSE, headers=out_headers)

    def _session_header(self, request: Request, upstream_headers: Any, initialize: bool) -> dict[str, str]:
        """The Mcp-Session-Id to hand the client, if any.

        The server assigns the session on the response to `initialize`, and that is the only response
        whose session id is passed on. On any other response a session id that differs from the one
        the client sent is withheld (NRVQ-MCP-5087): the TypeScript SDK 1.32 adopts a session id from
        ANY response, so a server could otherwise move a client onto another client's session.
        """
        upstream = upstream_headers.get("mcp-session-id")
        if upstream is None:
            return {}
        if initialize or upstream == request.headers.get("mcp-session-id"):
            return {"mcp-session-id": upstream}
        log.warning("nrvq.mcp.http.session_id_withheld", server=self._server_id, code="NRVQ-MCP-5087",
                    detail="a non-initialize response carried a session id different from the "
                           "request's; it was not passed to the client")
        return {}

    def _mint_event_id(self, fw: McpFirewall, server_id: str, corr: Correlation | None) -> str:
        """An SSE event id of the proxy's own, mapped to the server's id and to the stream's scope.

        The client resumes with what it was given. Event ids the SERVER chose cannot say which of the
        proxy's streams they belonged to — a server can repeat one across streams — so the client is
        given ids the proxy minted, and a resuming GET is mapped back to exactly one POST's scope.
        """
        ids = self._event_ids.get(fw)
        if ids is None:
            ids = self._event_ids[fw] = _EventIds()
        origin = None if corr is None or corr.get_stream else corr
        return ids.add(server_id, origin, id(corr) if corr is not None else 0)

    async def _pump_frames(self, fw: McpFirewall, resp: Any,
                           corr: Correlation | None = None) -> AsyncIterator[bytes]:
        """Mediate an SSE body frame by frame. One implementation, two callers.

        `_stream_through` and `_post_once` both consume SSE, and duplicating this loop is how the two
        would eventually disagree about framing — the same way `initialize` and `server/discover`
        drifted until one of them had no scan at all.
        """
        if not _is_sse(resp.headers):
            # The server answered a body that is NOT a stream on the path that serves the client a
            # stream (an SSE-only client, or the GET stream). It has no frames and no `data:` lines, so
            # the frame loop below would have read the whole body as bookkeeping and passed it through
            # unmediated. It is one JSON-RPC message: mediate it whole, exactly as the JSON route does,
            # and hand the client the result as the one SSE event it asked for. A body that does not
            # decode is dropped by `_mediate_server_bytes` and nothing is emitted.
            body = await self._read_capped(resp, "stream path, non-stream body")
            if body is None:
                return
            mediated = await self._mediate_server_bytes(fw, body, corr) if body.strip() else b""
            if mediated:
                yield b"event: message\ndata: " + _one_line(mediated) + b"\n\n"
            return
        buffer = b""
        scan_from = 0
        lines = _SseLines()
        limit = int(settings.mcp_http_max_message_bytes)
        async for chunk in resp.aiter_bytes():
            buffer += lines.feed(chunk)
            # SSE frames are separated by a blank line. Split on the boundary and emit whole frames
            # only — a half-received frame must not be parsed, and must not be held back longer than
            # it takes to complete. The search resumes where the last one stopped: rescanning the
            # whole pending frame on every chunk made a long frame quadratic.
            while True:
                end = buffer.find(b"\n\n", scan_from)
                if end < 0:
                    scan_from = max(0, len(buffer) - 1)
                    break
                frame, buffer, scan_from = buffer[:end], buffer[end + 2:], 0
                yield await self._mediate_frame(fw, frame, corr) + b"\n\n"
            if len(buffer) > limit:
                # One frame larger than any message the proxy will hold. Ending the stream is the
                # only fail-closed choice: the frame cannot be mediated without being held whole.
                self._over_limit("stream path, one SSE frame", limit)
                return
        if buffer.strip():
            yield await self._mediate_frame(fw, buffer, corr)

    async def _read_capped(self, resp: Any, where: str) -> bytes | None:
        """The whole body, or None (logged) once it passes `mcp_http_max_message_bytes`."""
        limit = int(settings.mcp_http_max_message_bytes)
        parts: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > limit:
                self._over_limit(where, limit)
                return None
            parts.append(chunk)
        return b"".join(parts)

    def _over_limit(self, where: str, limit: int) -> None:
        log.warning("nrvq.mcp.http.upstream_message_too_large", where=where, limit=limit,
                    server=self._server_id, code="NRVQ-MCP-5085",
                    hint="raise NRVQ_MCP_HTTP_MAX_MESSAGE_BYTES only if the server's messages are "
                         "legitimately this large")

    async def _post_once(self, fw: McpFirewall, request: Request, body: bytes,
                         corr: Correlation | None = None, initialize: bool = False) -> Response:
        """POST upstream exactly once and serve whichever shape comes back.

        The context manager is entered by hand because the decision — buffer or stream — depends on a
        header that is only available after the response starts, and the streaming branch must keep
        the connection open past the return. Both branches close it: the buffered one in `finally`,
        the streaming one when the generator is exhausted or discarded.
        """
        headers = {**self._forward_headers(request.headers), "content-type": "application/json"}
        cm = self._client.stream("POST", self._upstream, headers=headers, content=body, timeout=None)
        resp = await cm.__aenter__()
        session_header = self._session_header(request, resp.headers, initialize)

        if not _is_sse(resp.headers):
            try:
                raw = await self._read_capped(resp, "json path")
                if raw is None:
                    sent = P.decode(body)
                    return Response(P.encode(P.error_response(
                        sent.id if sent is not None else None, P.E_INTERNAL,
                        "Norviq MCP proxy: the upstream response exceeded the size limit and was not "
                        "forwarded")), status_code=502, media_type="application/json")
                out = await self._mediate_server_bytes(fw, raw, corr)
                return Response(out, status_code=resp.status_code,
                                headers={**_passthrough(resp.headers), **session_header},
                                media_type="application/json")
            finally:
                await cm.__aexit__(None, None, None)

        async def events() -> AsyncIterator[bytes]:
            try:
                async for out in self._pump_frames(fw, resp, corr):
                    yield out
            finally:
                await cm.__aexit__(None, None, None)

        return StreamingResponse(events(), media_type=_SSE,
                                 headers={"cache-control": "no-cache", **session_header})

    async def _mediate_frame(self, fw: McpFirewall, frame: bytes,
                             corr: Correlation | None = None) -> bytes:
        """Mediate the JSON payload of one SSE frame, preserving the SSE fields a client acts on.

        Only `data` carries the JSON-RPC message; `event:`, `id:`, `retry:` and comments are transport
        bookkeeping the client needs intact (`id:` in particular drives resumption). The data lines are
        joined and mediated as ONE message, as the client will read them. Any other line is dropped:
        a spec client ignores an unknown field, and the proxy forwards nothing it did not classify.
        """
        keep, data, dropped = _split_frame(frame)
        if dropped:
            log.warning("nrvq.mcp.http.sse_lines_dropped", lines=dropped, server=self._server_id,
                        code="NRVQ-MCP-5082",
                        detail="lines in a server SSE frame that are neither data nor a known field "
                               "were not forwarded")
        # Event ids: the client is handed one the proxy minted (see `_mint_event_id`). An empty `id:`
        # (which resets the client's last id) is passed as it is.
        # Only the LAST `id:` of a frame sets the client's last event id (each one overwrites the
        # buffer before dispatch), so only that one is kept and minted; minting every one let a server
        # cost the proxy a mint and a map entry per line of an 8 MiB frame.
        id_lines = [i for i, line in enumerate(keep) if line.partition(b":")[0] == b"id"]
        for i in id_lines[:-1]:
            keep[i] = b""
        for i, line in enumerate(keep):
            name, _, value = line.partition(b":")
            if name == b"id" and line:
                raw_id = value[1:] if value.startswith(b" ") else value
                if len(raw_id) > _MAX_SERVER_EVENT_ID_BYTES:
                    # Held in memory until evicted, so bounded: an id this long is not one the proxy
                    # will remember. The frame goes on without an id (the client cannot resume to it).
                    log.warning("nrvq.mcp.http.sse_event_id_too_long", bytes=len(raw_id),
                                limit=_MAX_SERVER_EVENT_ID_BYTES, server=self._server_id,
                                code="NRVQ-MCP-5088")
                    keep[i] = b""
                elif raw_id:
                    keep[i] = b"id: " + self._mint_event_id(
                        fw, raw_id.decode("utf-8", "replace"), corr).encode()
                # An EMPTY `id:` is passed as it is: it resets the client's last event id.
        keep = [line for line in keep if line]
        if data is not None:
            mediated = await self._mediate_server_bytes(fw, data, corr)
            keep.append(b"data: " + _one_line(mediated) if mediated else b"data: ")
        return b"\n".join(keep)

    async def _mediate_server_bytes(self, fw: McpFirewall, payload: bytes,
                                    corr: Correlation | None = None) -> bytes:
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
        result = await fw.on_server_message(msg, corr)
        if result.reply is not None:
            # A server-initiated request we refused. On this transport the reply travels back as a
            # separate POST rather than inline, so it is dispatched without blocking the stream.
            asyncio.create_task(self._post_back(result.reply, corr.upstream_headers if corr else {}))
        self._report_catalog(fw, result)
        if result.forward is None:
            return b""
        return result.forward.rstrip(b"\n")

    def _report_catalog(self, fw: McpFirewall, _result: MediationResult) -> None:
        """Tell the control plane what this server served. Mirrors stdio.py's call site.

        THIS TRANSPORT NEVER DID. `ControlPlanePinStore.put()` only enqueues; `flush()` is what sends,
        and nothing here called it — so on streamable HTTP, the transport the 2026-07-28 spec mandates
        and the one every real deployment uses, no MCP observation ever reached the control plane. The
        console's MCP Servers page was empty on every such install, the pin table stayed at zero, and
        cross-pod drift detection had nothing to compare against. Local Gate A worked throughout, which
        is why it went unnoticed: the enforcement was real and the entire record of it was missing.

        Found by driving a spec-compliant MCP client through the proxy and then reading the console —
        the same method that found the SSE transport bug, and for the same reason: a unit test asserts
        what the firewall decided, and nobody had asserted that anyone was ever told.

        Background task, after the response is composed: the local decision was already made from the
        state loaded at startup, so this write is durability and visibility, never the decision itself,
        and the client must not wait on it.
        """
        if self._pin_store is None:
            return                                     # a local pin store has nowhere to report to
        catalog = fw.catalog_report_due()
        if catalog is not None:
            asyncio.create_task(self._pin_store.flush(catalog))

    async def _post_back(self, payload: bytes, connection: dict[str, str]) -> None:
        """POST the proxy's refusal of a server request back upstream.

        The reply is NOT read. `post()` read the server's whole answer into memory, unbounded and
        uncompressed-on-arrival, for a body nobody uses: one refused elicitation answered with 400 MiB
        took the process from 110 to 473 MiB, and refusals run concurrently. The status is all that is
        looked at; the stream is closed unread.

        It carries the client's connection headers (`_connection_headers`: the credential, the
        2025-06-18 session and the protocol revision), so the refusal reaches the session that asked.
        """
        headers = {**connection, "content-type": "application/json",
                   "accept": f"application/json, {_SSE}", "accept-encoding": "identity"}
        with contextlib.suppress(Exception):
            async with self._client.stream("POST", self._upstream, headers=headers, content=payload):
                pass

    # ------------------------------------------------------------------ lifecycle
    async def run(self) -> int:
        import uvicorn

        self._engine = PolicyEngineClient()
        # BEFORE the listener binds. A request arriving against the per-process fallback would take a
        # first_seen TOFU decision this pod would then never reconcile with the shared store.
        await self._install_pin_store()
        await self._install_server_registry()
        self._client = _upstream_client()
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


class _SseLines:
    """SSE's three line terminators — CRLF, bare CR, bare LF — turned into LF, across chunk boundaries.

    The proxy and the client must agree on where a line ends, because the proxy decides from the start
    of a line whether it carries data (mediated) or bookkeeping (passed). Splitting on LF alone, as
    this driver did, read `event: message<CR>data: {...}` as ONE bookkeeping line, while every spec
    client reads it as two and dispatches the data. A CR ends the line at once, as it does for a
    streaming client; an LF that opens the NEXT chunk straight after it is the second half of that
    CRLF and is skipped, so a CRLF split across chunks is one line end, not two.
    """

    __slots__ = ("_cr",)

    def __init__(self) -> None:
        self._cr = False

    def feed(self, chunk: bytes) -> bytes:
        if self._cr and chunk.startswith(b"\n"):
            chunk = chunk[1:]
        self._cr = chunk.endswith(b"\r")
        return chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


# The SSE fields other than `data` that a client acts on, plus comments (`:`). Anything else is
# ignored by a spec client and dropped here, so nothing the proxy did not classify is forwarded.
_SSE_BOOKKEEPING = frozenset({b"event", b"id", b"retry"})


def _split_frame(frame: bytes) -> tuple[list[bytes], bytes | None, int]:
    """One LF-normalised SSE frame -> (bookkeeping lines to keep, joined data or None, lines dropped).

    `data` values are joined with LF, exactly as a client joins them before parsing, so a message
    written over several `data:` lines is mediated as the one message the client will read.
    """
    keep: list[bytes] = []
    data: list[bytes] = []
    dropped = 0
    for line in frame.split(b"\n"):
        if b"\r" in line:
            dropped += 1        # cannot survive `_SseLines`; never forwarded if a caller skipped it
            continue
        if line.startswith(b":"):
            keep.append(line)
            continue
        name, _, value = line.partition(b":")
        if name == b"data":
            data.append(value[1:] if value.startswith(b" ") else value)
        elif name in _SSE_BOOKKEEPING:
            keep.append(line)
        elif line:
            dropped += 1
    return keep, (b"\n".join(data) if data else None), dropped


class _EventIds:
    """One caller's minted event ids, bounded three ways.

    Per stream (`_MAX_EVENT_IDS_PER_STREAM`, the oldest of that stream goes): resumption needs a
    stream's recent ids, and one stream emitting thousands must not evict every other stream's. Per
    caller in entries and in bytes (the oldest overall goes): the server chooses how many streams and
    how long its ids are, and these are held in memory.
    """

    __slots__ = ("entries", "streams", "bytes")

    def __init__(self) -> None:
        self.entries: dict[str, tuple[str, Correlation | None, int]] = {}
        self.streams: dict[int, collections.deque] = {}
        self.bytes = 0

    def get(self, minted: str) -> tuple[str, Correlation | None] | None:
        entry = self.entries.get(minted)
        return None if entry is None else (entry[0], entry[1])

    def _drop(self, minted: str) -> None:
        entry = self.entries.pop(minted, None)
        if entry is None:
            return
        self.bytes -= len(entry[0])
        queue = self.streams.get(entry[2])
        if queue is not None:
            with contextlib.suppress(ValueError):
                queue.remove(minted)
            if not queue:
                self.streams.pop(entry[2], None)

    def add(self, server_id: str, origin: Correlation | None, stream: int) -> str:
        minted = f"nrvq-{uuid.uuid4().hex}"
        queue = self.streams.setdefault(stream, collections.deque())
        while len(queue) >= _MAX_EVENT_IDS_PER_STREAM:
            self._drop(queue[0])
        while self.entries and (len(self.entries) >= _MAX_EVENT_IDS
                                or self.bytes + len(server_id) > _MAX_EVENT_ID_BUDGET):
            self._drop(next(iter(self.entries)))
        queue = self.streams.setdefault(stream, collections.deque())
        queue.append(minted)
        self.entries[minted] = (server_id, origin, stream)
        self.bytes += len(server_id)
        return minted


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    """Accept no cookie, return no cookie."""

    def set_ok(self, cookie, request):  # noqa: D401 - CookiePolicy interface
        return False

    def return_ok(self, cookie, request):
        return False


def _upstream_client(transport: Any = None) -> httpx.AsyncClient:
    """The one client the proxy talks to the upstream with — WITHOUT a cookie jar that remembers.

    httpx keeps the cookies a server sets and sends them on every later request from the same client,
    and this one client serves every caller of the proxy: a session cookie the server set for one
    caller went out on another caller's requests, including the proxy's own self-lists and post-backs,
    which are documented to carry no cookie. A client's own `Cookie` header still travels on that
    client's forwarded requests, as any request header does.
    """
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(60.0, connect=5.0),
        limits=httpx.Limits(max_connections=32, max_keepalive_connections=16),
        transport=transport,
    )
    # On the client's own jar: httpx copies a jar passed as `cookies=` into a fresh default one, which
    # would drop the policy.
    client.cookies.jar.set_policy(_NoCookies())
    return client


def _connection_headers(request: Request) -> dict[str, str]:
    """The client headers that identify its CONNECTION (credential, session, revision) and nothing
    that describes a particular call — what the proxy's own requests upstream carry."""
    return {k.lower(): v for k, v in request.headers.items() if k.lower() in _LIST_HEADER_ALLOWLIST}


def _is_sse(headers: Any) -> bool:
    """Whether a response is an SSE stream. Media types are case-insensitive (RFC 9110 §8.3.1)."""
    return _SSE in str(headers.get("content-type", "")).lower()


def _one_line(message: bytes) -> bytes:
    """A mediated message as ONE `data:` value.

    A message forwarded unchanged is re-emitted from the server's bytes, and a server that spread its
    JSON over several `data:` lines (or pretty-printed a body) left line breaks in those bytes. After a
    single `data: ` prefix the client read only the first line as data and lost the message. Line
    breaks in JSON are only ever whitespace between tokens (inside a string they must be escaped), so
    a compact re-encoding is the same message.
    """
    if b"\n" not in message and b"\r" not in message:
        return message
    return P.encode(json.loads(message)).rstrip(b"\n")


def _own_response_in_frame(frame: bytes, own_id: Any) -> P.JsonRpcMessage | None:
    """The response to the proxy's own request, if this SSE frame carries it; else None."""
    _keep, data, _dropped = _split_frame(frame)
    if data is None:
        return None
    msg = P.decode(data)
    if msg is not None and msg.is_response and msg.id == own_id:
        return msg
    return None


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
    # Content-Encoding too: httpx has already decoded the body that is sent on, so a copied
    # `gzip` would tell the client to decompress plain bytes. Mcp-Session-Id is never copied: it is
    # passed only by `HttpProxy._session_header`.
    return {k: v for k, v in headers.items()
            if k.lower() not in _HOP_HEADERS and k.lower() not in ("content-encoding", "mcp-session-id")}
