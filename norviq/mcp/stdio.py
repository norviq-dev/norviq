# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""stdio transport driver: the firewall becomes the MCP server the client spawns.

PLACEMENT, AND WHY THERE IS NO CHOICE HERE. A stdio MCP server is a CHILD PROCESS of the client.
There is no socket, no port, and no network hop, so there is nothing for a gateway to sit in front
of. The only faithful interception point is to BE the child:

    before:   host ──spawn──> mcp-server            (pipes)
    after:    host ──spawn──> norviq-mcp-proxy ──spawn──> mcp-server

The host's config changes from `{"command": "mcp-server"}` to
`{"command": "norviq-mcp-proxy", "args": ["--", "mcp-server"]}` and nothing else moves. The proxy
speaks the client's stdio on one side and the server's stdio on the other.

WHY THIS ALSO SOLVES IDENTITY. The hard question for MCP is "who is calling", because MCP carries
no identity at all — the protocol has no principal. Being the spawned child answers it structurally
rather than by trusting a field:

  * The proxy is in the SAME pod, SAME uid namespace, SAME network namespace as the agent that
    spawned it. Its SPIFFE SVID *is* that workload's identity — there is nothing to impersonate,
    because the pod that runs the agent is the pod that runs the proxy.
  * There is exactly ONE client per proxy process (its parent). "Which caller is this" is not a
    question that can arise, so it cannot be answered wrongly.
  * Identity is resolved from the SVID via the existing `SPIFFEResolver` and NEVER read from any
    MCP message. Even that is belt-and-braces: `/api/v1/evaluate` re-binds every enforcement-
    selecting field to the caller's own credential (`scoped_identity` / `attested_namespace`), so a
    proxy that lied would have its claim overwritten by the engine.

A shared network gateway cannot make any of those statements about a stdio server, which is the
argument for sidecar placement and against a central MCP gateway. It also costs less: a sidecar hop
is a pipe write, not a network round trip.

DUPLEX AND ORDERING. Four independent flows run concurrently (client→server, server→client, plus
each side's stderr) and each direction is pumped by its own task, so a slow evaluate on one message
cannot head-of-line-block the other direction. Within a direction, messages are processed strictly
in order: an MCP client is entitled to assume its requests reach the server in the order it sent
them, and `tools/call` evaluation is awaited inline to preserve that. Concurrency WITHIN a
direction would be a correctness bug, not a performance win.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from typing import Sequence

import structlog

from norviq.config import settings
from norviq.engine.identity import SPIFFEResolver
from norviq.mcp import protocol as P
from norviq.mcp.firewall import McpFirewall
from norviq.mcp.pins import ControlPlanePinStore, PinRegistry, build_store
from norviq.mcp.servers import ControlPlaneServerStore
from norviq.sdk.client.engine import PolicyEngineClient
from norviq.sdk.core.interceptor import ToolInterceptor

log = structlog.get_logger()

# A single JSON-RPC line larger than this is refused rather than buffered. asyncio's readline() on an
# unbounded stream will happily accumulate until the process dies, and both peers here are untrusted
# from the proxy's point of view (the server certainly is). 8 MiB is far above any real MCP message
# and still bounded.
_MAX_LINE = 8 * 1024 * 1024
# How long the server->client pump gets to drain after the CLIENT hangs up. Bounded so a server that
# never closes its stdout cannot keep the proxy alive indefinitely.
_DRAIN_TIMEOUT_S = 5.0


def configure_stdio_logging() -> None:
    """Force every log line onto STDERR before anything can log.

    Not a preference — a correctness requirement, and the first bug this proxy actually had. On the
    stdio transport, **stdout IS the JSON-RPC channel**. structlog's default factory writes to
    stdout, so the very first `nrvq.mcp.proxy.started` line lands in the middle of the protocol
    stream and the client's parser sees garbage where a message should be. The MCP spec is explicit
    that a stdio server must not write anything but valid messages to stdout, and the reason is
    exactly this.

    Called from `StdioProxy.run()` rather than at import, so importing the module (tests, the HTTP
    driver) does not reconfigure a host application's logging as a side effect.

    It also applies `NRVQ_LOG_LEVEL`, which nothing in this process was honouring — structlog with
    no `wrapper_class` emits every level, so the setting existed and did nothing here. That is a
    MEASURED hot-path cost, not a tidiness point: the shared enforcement spine logs two INFO lines
    per decision (`nrvq.sdk.evaluate.ok`, `nrvq.intercept.result`), each one a synchronous formatted
    write to stderr, and on kind that accounted for ~6 ms of the ~20 ms a `tools/call` waited —
    roughly a third of the proxy's entire added latency, spent on log lines nobody reads at steady
    state. Filtering at the bound logger drops the message before it is rendered, so setting
    NRVQ_LOG_LEVEL=WARNING removes the formatting AND the write. The default stays INFO so
    behaviour matches the rest of the product; the numbers for both are in the design note.
    """
    level = str(getattr(settings, "log_level", "INFO") or "INFO").upper()
    try:
        wrapper = structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO))
    except Exception:  # never let a bad level string stop the proxy from starting
        wrapper = structlog.make_filtering_bound_logger(20)
    structlog.configure(
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=wrapper,
        cache_logger_on_first_use=True,
    )


class StdioProxy:
    """Runs one MCP session: this process's stdin/stdout on the client side, a spawned child on the
    server side."""

    def __init__(
        self,
        server_cmd: Sequence[str],
        server_id: str = "",
        session_id: str = "",
        tool_name_prefix: str = "",
    ) -> None:
        if not server_cmd:
            raise ValueError("an upstream MCP server command is required")
        self._cmd = list(server_cmd)
        self._server_id = server_id or os.path.basename(self._cmd[0])
        self._session_id = session_id
        self._prefix = tool_name_prefix
        self._proc: asyncio.subprocess.Process | None = None
        self._firewall: McpFirewall | None = None
        self._engine: PolicyEngineClient | None = None
        self._client_out: "_Writer | None" = None
        self._out_lock = asyncio.Lock()
        self._pin_store = None      # set only for the control-plane backend
        self._server_store = None   # the MCP server registry; always set once the firewall is built

    # ------------------------------------------------------------------ setup
    async def _build_firewall(self) -> McpFirewall:
        # Reuse the SDK's engine client verbatim: pooled keep-alive httpx, retry with backoff, the
        # circuit breaker, and the fail-closed posture including "a 4xx is a refusal, not an outage,
        # and never fails open". Reimplementing any of that for MCP would be a second, less-tested
        # copy of a security boundary.
        self._engine = PolicyEngineClient()
        identity = await SPIFFEResolver().resolve()
        interceptor = ToolInterceptor(self._engine, SPIFFEResolver())

        # Pin backend. `control-plane` is the recommended posture: pins are approvals, and approvals
        # belong with policy — tenant-scoped, RBAC'd, audited, console-visible, and immune to a pod
        # restart. `memory`/`file` remain for air-gapped or single-process use. The load happens ONCE
        # here, before any traffic, so the discovery path never blocks on the control plane.
        if settings.mcp_pin_store == "control-plane":
            store = ControlPlanePinStore(
                namespace=identity.namespace,
                server_id=self._server_id,
                mode=settings.mcp_pin_mode,
                transport="stdio",
            )
            await store.load()
            # Keep re-reading. Without this the process holds its startup copy for its whole life, so
            # POST /mcp/pins/revoke updates the DB and the console while this proxy keeps listing and
            # executing the revoked tool until the pod restarts.
            store.start_refresh(settings.mcp_pin_refresh_s)
            self._pin_store = store
        else:
            store = build_store(settings.mcp_pin_store, settings.mcp_pin_path)
        pins = PinRegistry(store=store, mode=settings.mcp_pin_mode)

        # The server-level registry, loaded on the same terms as pins: once here before any traffic,
        # then re-read on the same interval so a BLOCK made in the console reaches a RUNNING proxy.
        # It is loaded whatever the pin backend is — pins and decisions answer different questions,
        # and an operator who chose a local pin store has not thereby declined to have their
        # blocked-server decisions enforced.
        servers = ControlPlaneServerStore(namespace=identity.namespace)
        await servers.load()
        servers.start_refresh(settings.mcp_pin_refresh_s)
        self._server_store = servers

        return McpFirewall(
            interceptor=interceptor,
            server_id=self._server_id,
            session_id=self._session_id,
            pins=pins,
            servers=servers.registry,
            tool_name_prefix=self._prefix,
            transport="stdio",
        )

    async def _stdio_streams(self) -> tuple[asyncio.StreamReader, "_Writer"]:
        """Wrap this process's stdin/stdout as asyncio streams.

        ``connect_read_pipe`` is the right mechanism and covers the real deployment — an MCP host
        spawns the proxy with pipes on both ends. It also raises outright when stdin is a regular
        file or a tty ("Pipe transport is for pipes/sockets only"), which is every manual
        `proxy < script.jsonl` invocation and every terminal session. Refusing to run there would
        make the proxy untestable by hand and undiagnosable in a shell, so a non-pipe stdin falls
        back to a reader thread. The fallback is not on any hot path an agent uses.
        """
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=_MAX_LINE)
        try:
            await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        except ValueError:
            asyncio.create_task(self._feed_from_thread(reader))
        try:
            transport, protocol = await loop.connect_write_pipe(
                asyncio.streams.FlowControlMixin, sys.stdout
            )
            return reader, _Writer(asyncio.StreamWriter(transport, protocol, None, loop))
        except ValueError:
            return reader, _Writer(None)

    @staticmethod
    async def _feed_from_thread(reader: asyncio.StreamReader) -> None:
        """Pump a non-pipe stdin into the StreamReader without blocking the event loop."""
        loop = asyncio.get_running_loop()
        while True:
            line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            if not line:
                reader.feed_eof()
                return
            reader.feed_data(line)

    # ------------------------------------------------------------------- run
    async def run(self) -> int:
        """Spawn the upstream server and pump both directions until either side closes."""
        configure_stdio_logging()
        self._firewall = await self._build_firewall()
        client_in, client_out = await self._stdio_streams()
        self._client_out = client_out

        self._proc = await asyncio.create_subprocess_exec(
            *self._cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_MAX_LINE,
        )
        log.info(
            "nrvq.mcp.proxy.started", server=self._server_id, pid=self._proc.pid,
            cmd=self._cmd[0], pin_mode=settings.mcp_pin_mode, code="NRVQ-MCP-5000",
        )

        tasks = [
            asyncio.create_task(self._pump_client_to_server(client_in), name="c2s"),
            asyncio.create_task(self._pump_server_to_client(), name="s2c"),
            asyncio.create_task(self._drain_server_stderr(), name="stderr"),
        ]
        c2s, s2c, _err = tasks
        try:
            # First completion wins: whichever side hangs up ends the session. Waiting for ALL of
            # them would hang forever when the client detaches but the server keeps running.
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            # ...but if it was the CLIENT that hung up, cancelling immediately would discard replies
            # the server has already produced for requests we forwarded. Half-answered requests are
            # a real bug, not a shutdown detail: a client that closes stdin after its last request
            # (the normal way a scripted or one-shot session ends) would silently lose that
            # request's response. So: close the server's stdin — which is how a stdio server is told
            # the session is over — and give the server-to-client pump a bounded window to drain.
            if c2s in done and s2c not in done:
                if self._proc.stdin is not None and not self._proc.stdin.is_closing():
                    with contextlib.suppress(Exception):
                        self._proc.stdin.close()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(s2c), timeout=_DRAIN_TIMEOUT_S)
                pending = [t for t in tasks if not t.done()]

            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in tasks:
                if t.done() and not t.cancelled() and t.exception() is not None:
                    log.error("nrvq.mcp.proxy.pump_failed", task=t.get_name(),
                              error=str(t.exception()), code="NRVQ-MCP-5001")
        finally:
            await self._shutdown()
        return 0

    async def _shutdown(self) -> None:
        stats = dict(self._firewall.stats) if self._firewall else {}
        if self._proc is not None and self._proc.returncode is None:
            # SIGTERM then a bounded wait then SIGKILL. A server that ignores TERM must not be able
            # to keep the proxy (and therefore the enforcement point) alive after the session ended.
            with contextlib.suppress(ProcessLookupError):
                self._proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    self._proc.kill()
                await self._proc.wait()
        if self._pin_store is not None:
            # A drift observed near the end of a session must not be lost with the process.
            with contextlib.suppress(Exception):
                await self._pin_store.flush(
                    self._firewall.observed_catalog() if self._firewall else None
                )
        if self._server_store is not None:
            # Cancel the refresh loop. Left running it holds the event loop open past shutdown and
            # logs a control-plane error on the way down, which reads like a failure when it is only
            # a poll that outlived the thing it was polling for.
            with contextlib.suppress(Exception):
                await self._server_store.aclose()
        if self._engine is not None:
            with contextlib.suppress(Exception):
                await self._engine.close()
        log.info("nrvq.mcp.proxy.stopped", server=self._server_id, stats=stats, code="NRVQ-MCP-5002")

    # ------------------------------------------------------------------ pumps
    async def _write_client(self, data: bytes) -> None:
        """Serialise writes to the client. Two tasks can produce client-bound bytes — a forwarded
        server message and a locally-generated block reply — and interleaving them mid-line would
        corrupt the framing."""
        async with self._out_lock:
            await self._client_out.write(data)

    async def _write_server(self, data: bytes) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.stdin.is_closing():
            return
        proc.stdin.write(data)
        await proc.stdin.drain()

    async def _pump_client_to_server(self, client_in: asyncio.StreamReader) -> None:
        firewall = self._firewall
        while True:
            line = await _read_line(client_in)
            if line is None:
                break
            msg = P.decode(line)
            if msg is None:
                # Unparseable input. Dropping is the fail-closed choice: forwarding bytes we could
                # not classify would mean forwarding a possible tools/call ungoverned.
                log.warning("nrvq.mcp.client.undecodable_dropped", bytes=len(line), code="NRVQ-MCP-5003")
                continue
            result = await firewall.on_client_message(msg)
            if result.reply is not None:
                await self._write_client(result.reply)
            if result.forward is not None:
                await self._write_server(result.forward)

    async def _pump_server_to_client(self) -> None:
        firewall = self._firewall
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        while True:
            line = await _read_line(proc.stdout)
            if line is None:
                break
            msg = P.decode(line)
            if msg is None:
                log.warning("nrvq.mcp.server.undecodable_dropped", bytes=len(line), code="NRVQ-MCP-5004")
                continue
            result = await firewall.on_server_message(msg)
            if result.reply is not None:
                await self._write_server(result.reply)
            if result.forward is not None:
                await self._write_client(result.forward)
            # Report the catalog to the control plane AFTER the response has been forwarded, and as a
            # background task, so the client never waits on it. The local decision was already made
            # from the state loaded at startup; this write is durability and visibility, not the
            # decision itself, so it must not sit on the discovery path either.
            if result.note == "gate_a_rewrote_tools_list" or firewall.stats.get("_listed") is None:
                if self._pin_store is not None and firewall.observed_catalog():
                    firewall.stats["_listed"] = 1
                    asyncio.create_task(self._pin_store.flush(firewall.observed_catalog()))

    async def _drain_server_stderr(self) -> None:
        """Relay the upstream server's stderr to ours.

        Not cosmetic: MCP servers log diagnostics on stderr and a host surfaces them to the
        operator. Swallowing them would make the proxy look like it broke the server. Never
        forwarded to stdout — that is the JSON-RPC channel and a stray log line there corrupts the
        session.
        """
        proc = self._proc
        assert proc is not None and proc.stderr is not None
        while True:
            chunk = await proc.stderr.readline()
            if not chunk:
                break
            sys.stderr.buffer.write(b"[upstream] " + chunk)
            sys.stderr.buffer.flush()


class _Writer:
    """Client-side output, over an asyncio pipe writer when there is one and plain stdout otherwise.

    Same reason as the reader fallback: a redirected/tty stdout cannot be wrapped in a pipe
    transport, and the proxy has to stay runnable by hand.
    """

    __slots__ = ("_w",)

    def __init__(self, writer: asyncio.StreamWriter | None) -> None:
        self._w = writer

    async def write(self, data: bytes) -> None:
        if self._w is not None:
            self._w.write(data)
            await self._w.drain()
            return
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


async def _read_line(reader: asyncio.StreamReader) -> bytes | None:
    """Read one framed line, returning None at EOF.

    A line longer than the stream limit raises `LimitOverrunError`/`ValueError` rather than being
    silently truncated, and truncation is exactly what must not happen: half a JSON-RPC message that
    still parses is a message the proxy would enforce on incorrectly. The oversized line is drained
    and dropped instead.
    """
    try:
        line = await reader.readline()
    except (asyncio.LimitOverrunError, ValueError):
        log.error("nrvq.mcp.oversized_message_dropped", limit=_MAX_LINE, code="NRVQ-MCP-5005")
        return b""
    return None if not line else line
