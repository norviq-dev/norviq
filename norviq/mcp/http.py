# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Streamable-HTTP transport driver.

MCP's streamable-HTTP transport is asymmetric in a way that matters for a firewall:

  * The client POSTs a JSON-RPC message to a single endpoint. The response is EITHER a single
    ``application/json`` body (one message) OR a ``text/event-stream`` carrying several messages —
    the server chooses per request.
  * The client may also open a standalone GET SSE stream on the same endpoint, on which the SERVER
    initiates messages (notifications, and server->client requests like ``sampling/createMessage``).
  * ``Mcp-Session-Id`` on the initialize response binds subsequent requests to a session.

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
from norviq.mcp.pins import PinRegistry, build_store
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
    """Streamable-HTTP MCP proxy. One firewall instance per `Mcp-Session-Id`."""

    def __init__(self, upstream: str, host: str, port: int, server_id: str,
                 tool_name_prefix: str = "") -> None:
        self._upstream = upstream.rstrip("/")
        self._host = host
        self._port = port
        self._server_id = server_id
        self._prefix = tool_name_prefix
        self._client: httpx.AsyncClient | None = None
        self._engine: PolicyEngineClient | None = None
        self._sessions: dict[str, McpFirewall] = {}
        # Pins are per-SERVER, not per-session: a rug pull that reset itself every time a client
        # reconnected would not be detectable at all.
        self._pins = PinRegistry(
            store=build_store(settings.mcp_pin_store, settings.mcp_pin_path),
            mode=settings.mcp_pin_mode,
        )
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ wiring
    def _firewall_for(self, session: str) -> McpFirewall:
        fw = self._sessions.get(session)
        if fw is None:
            fw = McpFirewall(
                interceptor=ToolInterceptor(self._engine, SPIFFEResolver()),
                server_id=self._server_id,
                session_id=f"mcp-http-{session}",
                pins=self._pins,
                tool_name_prefix=self._prefix,
            )
            # Bounded: a peer can mint session ids freely, and an unbounded map is a memory
            # exhaustion primitive. Oldest-first eviction only costs the evicted session its
            # in-memory catalog — pins survive in the shared registry, so drift detection is intact.
            if len(self._sessions) >= 512:
                self._sessions.pop(next(iter(self._sessions)), None)
            self._sessions[session] = fw
        return fw

    @staticmethod
    def _session_of(request: Request) -> str:
        return request.headers.get("mcp-session-id", "default")

    @staticmethod
    def _forward_headers(headers) -> dict[str, str]:
        return {k: v for k, v in headers.items() if k.lower() not in _HOP_HEADERS}

    # ------------------------------------------------------------------ routes
    async def _handle_post(self, request: Request) -> Response:
        """Client -> server. One JSON-RPC message in; JSON or an SSE stream back."""
        raw = await request.body()
        fw = self._firewall_for(self._session_of(request))
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
        return await self._stream_through(self._firewall_for(self._session_of(request)),
                                          "GET", request, None)

    async def _handle_delete(self, request: Request) -> Response:
        """Session teardown. Drop the per-session catalog; pins are server-scoped and survive."""
        self._sessions.pop(self._session_of(request), None)
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
            return payload
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
            await self._client.aclose()
            with contextlib.suppress(Exception):
                await self._engine.close()
        return 0


def _wants_stream(request: Request) -> bool:
    return _SSE in request.headers.get("accept", "")


def _passthrough(headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _HOP_HEADERS}
