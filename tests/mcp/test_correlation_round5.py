# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Correlation must not be steerable through what the SERVER chooses: the session id, or the id text.

* `Mcp-Session-Id` is assigned by the server. Two client sessions it gives the same id must not
  pool their requests into one GET-stream scope where one session's request replaces the other's.
* A response id is server text, read on the event loop for every response. Reading it must cost
  time linear in a short, bounded prefix of it.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from structlog.testing import capture_logs

from test_cold_catalog import CLEAN_TOOL, POISONED_TOOL, _call, _fw, _make, _rpc_msg

_FORGED = {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "tools": [POISONED_TOOL, CLEAN_TOOL]}}


async def _warm(fw) -> None:
    """A scanned catalog, so a call to search_docs is allowed by the baseline stub."""
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}}))
    await fw.on_server_message(_rpc_msg({"jsonrpc": "2.0", "id": 100, "result": {"tools": [CLEAN_TOOL]}}))


# ── L1: one session id, two sessions ────────────────────────────────────────────────────────────
async def test_an_id_pending_from_two_posts_in_one_session_scope_is_not_answerable_on_the_get_stream():
    """Session 1 lists (id 1); session 2, which the server gave the SAME session id, calls with id 1.
    The shared scope used to keep only the second (tools/call), so a GET-stream answer shaped as both
    a tool result and a listing was mediated as a tool result — no Gate A — and the client SDK of
    session 1 resolved its pending tools/list with it."""
    fw, _ = _fw()
    await _warm(fw)
    session = fw.session_correlation("X")
    post1, post2 = fw.new_correlation([session]), fw.new_correlation([session])
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                               corr=post1)
    await fw.on_client_message(_rpc_msg(_call("search_docs", 1)), corr=post2)

    with capture_logs() as logs:
        on_get = await fw.on_server_message(_rpc_msg(_FORGED), session)
    assert on_get.forward is None, "an ambiguous id was answered on the shared GET stream"
    assert any("ambiguous" in str(e.get("reason", "")) for e in logs)

    # Each request is still answered on its own POST, as what it is.
    listed = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL, CLEAN_TOOL]}}), post1)
    called = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}), post2)
    assert listed.forward is not None and b"id_rsa" not in listed.forward
    assert called.forward is not None


async def test_an_id_stays_ambiguous_for_a_third_post():
    fw, _ = _fw()
    await _warm(fw)
    session = fw.session_correlation("X")
    for _ in range(3):
        await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                                   corr=fw.new_correlation([session]))
    on_get = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [CLEAN_TOOL]}}), session)
    assert on_get.forward is None


async def test_one_session_id_issued_to_two_initialize_exchanges_poisons_its_get_stream():
    fw, _ = _fw()
    await _warm(fw)
    fw.note_session_issued("X", fw.new_correlation())
    fw.note_session_issued("X", fw.new_correlation())
    post = fw.new_correlation([fw.session_correlation("X")])
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}),
                               corr=post)
    on_get = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 7, "result": {"tools": [CLEAN_TOOL]}}), fw.session_correlation("X"))
    assert on_get.forward is None


async def test_an_answer_on_the_post_consumes_the_session_entry_too():
    """A second answer to the same request on the GET stream is not an answer to anything."""
    fw, _ = _fw()
    session = fw.session_correlation("X")
    post = fw.new_correlation([session])
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
                               corr=post)
    first = await fw.on_server_message(_rpc_msg({"jsonrpc": "2.0", "id": 3, "result": {"tools": [CLEAN_TOOL]}}), post)
    again = await fw.on_server_message(_rpc_msg({"jsonrpc": "2.0", "id": 3, "result": {"tools": [CLEAN_TOOL]}}), session)
    assert first.forward is not None and again.forward is None


async def test_session_scopes_are_bounded():
    from norviq.mcp.firewall import _MAX_SESSION_SCOPES

    fw, _ = _fw()
    for i in range(_MAX_SESSION_SCOPES + 40):
        fw.session_correlation(f"s{i}")
    assert len(fw._session_corrs) <= _MAX_SESSION_SCOPES                 # noqa: SLF001


async def test_http_a_server_merging_two_sessions_cannot_answer_a_listing_on_the_get_stream():
    """The review probe, end to end over HTTP: the merged session's GET stream carries a forged
    answer for id 1 while session 1's tools/list and session 2's tools/call (both id 1) are in flight."""
    client, upstream, _, proxy, _ = _make()
    call_seen, release = asyncio.Event(), asyncio.Event()

    async def post(request):
        b = json.loads(await request.body() or b"{}")
        m, i = b.get("method"), b.get("id")
        if m == "tools/list" and i == 1:
            await release.wait()
            return JSONResponse({"jsonrpc": "2.0", "id": i, "result": {"tools": [CLEAN_TOOL]}})
        if m == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": i, "result": {"tools": [CLEAN_TOOL]}})
        if m == "tools/call":
            call_seen.set()
            await release.wait()
            return JSONResponse({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "ok"}]}})
        return Response(status_code=202)

    async def get(request):
        async def gen():
            await call_seen.wait()
            await asyncio.sleep(0.05)
            yield b"event: message\ndata: " + json.dumps(_FORGED).encode() + b"\n\n"

            async def _release():
                # The POSTs stay unanswered until the forged frame has been through the proxy.
                await asyncio.sleep(1.0)
                release.set()
            asyncio.ensure_future(_release())
        return StreamingResponse(gen(), media_type="text/event-stream")

    proxy._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=Starlette(routes=[   # noqa: SLF001
        Route("/mcp", post, methods=["POST"]), Route("/mcp", get, methods=["GET"])])), base_url="http://u")
    app = Starlette(routes=[Route("/mcp", proxy._handle_post, methods=["POST"]),         # noqa: SLF001
                            Route("/mcp", proxy._handle_get, methods=["GET"])])           # noqa: SLF001
    pc = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")
    hdrs = {"accept": "application/json, text/event-stream", "mcp-session-id": "X"}
    await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}},
                  headers=dict(hdrs, **{"mcp-session-id": "W"}))

    chunks: list[bytes] = []

    async def get_stream():
        async with pc.stream("GET", "/mcp", headers={"accept": "text/event-stream", "mcp-session-id": "X"}) as r:
            async for c in r.aiter_bytes():
                chunks.append(c)

    g = asyncio.ensure_future(get_stream())
    s1 = asyncio.ensure_future(pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                                                     "params": {}}, headers=hdrs, timeout=10))
    await asyncio.sleep(0.1)
    s2 = await pc.post("/mcp", json=_call("search_docs", 1), headers=hdrs, timeout=10)
    await s1
    await asyncio.wait_for(g, 5)
    assert b"id_rsa" not in b"".join(chunks)
    assert s2.status_code == 200


# ── L2: reading a response id is linear and bounded ─────────────────────────────────────────────
def test_a_long_digit_run_id_is_read_in_linear_time():
    from norviq.mcp.firewall import _numeric_readings

    started = time.perf_counter()
    assert _numeric_readings("1" * 1_048_576 + "x") == set()
    assert (time.perf_counter() - started) < 0.05


def test_a_50k_digit_run_id_is_read_in_linear_time():
    """The size the review measured: the old pattern took seconds here."""
    from norviq.mcp.firewall import _js_number

    started = time.perf_counter()
    assert _js_number("1" * 50_000 + "x") is None
    assert (time.perf_counter() - started) < 0.05


def test_a_long_id_has_no_numeric_reading():
    from norviq.mcp.firewall import _numeric_readings

    assert _numeric_readings("1" * 65) == set()
    assert int("1" * 20) in _numeric_readings("1" * 20)


async def test_a_response_with_a_huge_id_is_dropped_quickly():
    fw, _ = _fw()
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}}))
    started = time.perf_counter()
    result = await fw.on_server_message(_rpc_msg({"jsonrpc": "2.0", "id": "5" * 1_048_576 + "x",
                                                  "result": {"tools": []}}))
    assert result.forward is None and (time.perf_counter() - started) < 0.5


# ── stdio read-ahead is bounded in bytes as well as messages ────────────────────────────────────
async def test_stdio_read_ahead_stops_at_its_byte_budget(monkeypatch):
    from norviq.mcp import stdio as stdio_mod
    from norviq.mcp.firewall import MediationResult
    from norviq.mcp.stdio import StdioProxy

    monkeypatch.setattr(stdio_mod, "_READ_AHEAD_BYTES", 3000)
    proxy = StdioProxy(["true"], server_id="s")
    hold = asyncio.Event()
    noted: list = []

    class _Fw:
        def note_client_request(self, msg):
            noted.append(msg.id)

        async def on_client_message(self, msg, list_upstream=None, registered=False):
            await hold.wait()                    # mediation held, as behind a cold self-list
            return MediationResult()

    proxy._firewall = _Fw()                                           # noqa: SLF001
    reader = asyncio.StreamReader()
    for i in range(10):
        reader.feed_data(json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping",
                                     "params": {"pad": "x" * 950}}).encode() + b"\n")
    reader.feed_eof()
    pump = asyncio.ensure_future(proxy._pump_client_to_server(reader))  # noqa: SLF001
    await asyncio.sleep(0.2)
    read_ahead = len(noted)
    hold.set()
    await asyncio.wait_for(pump, 5)
    assert read_ahead <= 5, f"read {read_ahead} messages ahead past a 3000-byte budget"
    assert len(noted) == 10
