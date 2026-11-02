# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Correlation must not be steerable through what the SERVER chooses: the stream, the session id,
or the id text.

* A GET stream answers no request; a GET that resumes one of the proxy's POST streams answers that
  POST's request, once, under its id. The SDKs resolve responses there regardless of their id.
* `Mcp-Session-Id` reaches the client only on the response to initialize (or unchanged).
* A response id is server text, read on the event loop for every response. Reading it must cost
  time linear in a short, bounded prefix of it.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest
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


# ── GET streams answer nothing; a resumed POST stream answers its own request once ──────────────
async def test_a_resumed_stream_answers_its_post_request_once_under_that_requests_id():
    """The Python SDK 1.30 rewrites the id of a response on a resumed stream to its pending request's
    id. So whatever id the server writes there, the response is mediated as THAT request, and only
    while it is still unanswered."""
    fw, _ = _fw()
    post = fw.new_correlation()
    await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                               corr=post)
    resumed = post.resumption()
    first = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 999, "result": {"tools": [POISONED_TOOL, CLEAN_TOOL]}}), resumed)
    again = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}}), resumed)
    out = json.loads(first.forward)
    assert out["id"] == 1 and [t["name"] for t in out["result"]["tools"]] == ["search_docs"]
    assert again.forward is None
    late_on_post = await fw.on_server_message(_rpc_msg(
        {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}}), post)
    assert late_on_post.forward is None


async def test_a_resumed_stream_of_a_call_cannot_deliver_a_listing():
    fw, _ = _fw()
    await _warm(fw)
    post = fw.new_correlation()
    await fw.on_client_message(_rpc_msg(_call("search_docs", 1)), corr=post)
    out = await fw.on_server_message(_rpc_msg(_FORGED), post.resumption())
    # Mediated as what the SDK will resolve it as: the tools/call result. It is not a listing to
    # anyone, so Gate A has nothing to say; the content guard ran.
    assert out.forward is not None and json.loads(out.forward)["id"] == 1


def _resuming_upstream(event_frames: list[bytes], get_answer: dict, seen: list):
    async def post(request):
        body = json.loads(await request.body() or b"{}")
        if body.get("method") == "tools/list" and str(body.get("id")) == "1":
            async def gen():
                for f in event_frames:
                    yield f
            return StreamingResponse(gen(), media_type="text/event-stream")
        return JSONResponse({"jsonrpc": "2.0", "id": body.get("id"), "result": {"tools": [CLEAN_TOOL]}})

    async def get(request):
        seen.append(request.headers.get("last-event-id"))

        async def gen():
            yield b"id: s2\ndata: " + json.dumps(get_answer).encode() + b"\n\n"
            yield b"data: " + json.dumps(dict(get_answer, id=1)).encode() + b"\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")
    return Starlette(routes=[Route("/mcp", post, methods=["POST"]), Route("/mcp", get, methods=["GET"])])


async def _proxy_client(upstream_app):
    _, _, _, proxy, _ = _make()
    proxy._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app),  # noqa: SLF001
                                      base_url="http://u")
    app = Starlette(routes=[Route("/mcp", proxy._handle_post, methods=["POST"]),         # noqa: SLF001
                            Route("/mcp", proxy._handle_get, methods=["GET"])])           # noqa: SLF001
    return proxy, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy")


async def test_http_a_resumed_post_stream_is_mediated_as_that_post_and_only_once():
    """End to end: the POST stream gives an event id and ends without the answer; the client resumes
    with the id it was given; the server answers on the resumed GET under another id."""
    seen: list = []
    answer = {"jsonrpc": "2.0", "id": 77, "result": {"tools": [POISONED_TOOL, CLEAN_TOOL]}}
    proxy, pc = await _proxy_client(_resuming_upstream([b"id: s1\ndata: " + json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}).encode() + b"\n\n"],
        answer, seen))
    posted = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                           headers={"accept": "text/event-stream"})
    minted = next(line[4:] for line in posted.text.splitlines() if line.startswith("id: "))
    assert minted != "s1"
    resumed = await pc.get("/mcp", headers={"accept": "text/event-stream", "last-event-id": minted})

    assert seen == ["s1"], "the server must be sent its own event id"
    datas = [json.loads(line[6:]) for line in resumed.text.splitlines() if line.startswith("data: {")]
    assert len(datas) == 1, resumed.text                 # the second answer on the stream is dropped
    assert datas[0]["id"] == 1
    assert [t["name"] for t in datas[0]["result"]["tools"]] == ["search_docs"]


async def test_http_a_get_with_an_unknown_last_event_id_answers_nothing():
    seen: list = []
    answer = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}}
    _, pc = await _proxy_client(_resuming_upstream([], answer, seen))
    resumed = await pc.get("/mcp", headers={"accept": "text/event-stream", "last-event-id": "made-up"})
    assert "id_rsa" not in resumed.text and '"result"' not in resumed.text
    assert seen == ["made-up"]


async def test_http_a_plain_get_stream_answers_nothing():
    seen: list = []
    answer = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}}
    _, pc = await _proxy_client(_resuming_upstream([], answer, seen))
    r = await pc.get("/mcp", headers={"accept": "text/event-stream"})
    assert '"result"' not in r.text and seen == [None]


# ── Mcp-Session-Id is passed only on the response to initialize ─────────────────────────────────
def _session_upstream(session_out: str):
    async def handler(request):
        body = json.loads(await request.body() or b"{}")
        payload = {"jsonrpc": "2.0", "id": body.get("id"), "result": (
            {"tools": [CLEAN_TOOL]} if body.get("method") == "tools/list" else {})}
        if request.headers.get("x-shape") == "sse":
            async def gen():
                yield b"data: " + json.dumps(payload).encode() + b"\n\n"
            return StreamingResponse(gen(), media_type="text/event-stream", headers={"mcp-session-id": session_out})
        return JSONResponse(payload, headers={"mcp-session-id": session_out})
    return Starlette(routes=[Route("/mcp", handler, methods=["POST"])])


@pytest.mark.parametrize("shape", ["json", "sse"])
async def test_http_the_session_id_of_initialize_reaches_the_client(shape):
    _, pc = await _proxy_client(_session_upstream("S1"))
    accept = "application/json" if shape == "json" else "text/event-stream"
    r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
                      headers={"accept": accept, "x-shape": shape})
    assert r.headers.get("mcp-session-id") == "S1"


@pytest.mark.parametrize("shape", ["json", "sse"])
async def test_http_a_different_session_id_on_another_response_is_withheld(shape):
    """The TypeScript SDK 1.32 adopts a session id from ANY response; a server could move a client
    onto another client's session with it."""
    _, pc = await _proxy_client(_session_upstream("SOMEONE-ELSE"))
    accept = "application/json" if shape == "json" else "text/event-stream"
    with capture_logs() as logs:
        r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                          headers={"accept": accept, "x-shape": shape, "mcp-session-id": "MINE"})
    assert r.headers.get("mcp-session-id") is None
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5087"]


async def test_http_the_same_session_id_on_another_response_is_kept():
    _, pc = await _proxy_client(_session_upstream("MINE"))
    r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                      headers={"accept": "application/json", "mcp-session-id": "MINE"})
    assert r.headers.get("mcp-session-id") == "MINE"


# ── review survivors ────────────────────────────────────────────────────────────────────────────
async def test_a_self_list_whose_scan_fails_leaves_the_catalog_cold(monkeypatch):
    """Scan before mark: the catalog is listed only by a listing that went through Gate A."""
    from test_cold_catalog import _Lister

    fw, _ = _fw()

    async def boom(_msg):
        raise RuntimeError("scanner failure")

    monkeypatch.setattr(fw, "_gate_a_tools_list", boom)
    await fw.on_client_message(_rpc_msg(_call("search_docs")), list_upstream=_Lister())
    assert fw._catalog_listed is False                                  # noqa: SLF001


def test_a_response_carrying_a_method_is_not_well_formed():
    from norviq.mcp.firewall import _response_defect

    msg = _rpc_msg({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})
    msg.data["method"] = "tools/list"
    assert _response_defect(msg, "tools/list") == "a response carries a method"
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


async def test_http_a_plain_get_stream_answers_nothing_even_with_requests_pending_elsewhere():
    """The GET stream's scope is its own, empty one — not the firewall's default scope, which a
    request could be pending in."""
    seen: list = []
    answer = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [POISONED_TOOL]}}
    proxy, pc = await _proxy_client(_resuming_upstream([], answer, seen))
    fw = await proxy._firewall_for_caller()                             # noqa: SLF001
    fw._corr.pending.put(1, "tools/call")                               # noqa: SLF001
    r = await pc.get("/mcp", headers={"accept": "text/event-stream"})
    assert '"result"' not in r.text


# ── resumption bookkeeping is bounded and per caller ────────────────────────────────────────────
def _frames_upstream(frames: list[bytes]):
    async def post(request):
        async def gen():
            for f in frames:
                yield f
        return StreamingResponse(gen(), media_type="text/event-stream")
    return Starlette(routes=[Route("/mcp", post, methods=["POST"])])


def _ping_frame(event_id: bytes, n: int = 0) -> bytes:
    return (b"id: " + event_id + b"\ndata: " + json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": n}}).encode() + b"\n\n")


async def test_a_long_server_event_id_is_not_remembered_and_the_frame_goes_on_without_it():
    proxy, pc = await _proxy_client(_frames_upstream([_ping_frame(b"x" * 4096)]))
    with capture_logs() as logs:
        r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                          headers={"accept": "text/event-stream"})
    assert "notifications/progress" in r.text and "\nid:" not in "\n" + r.text
    assert not any(ids.entries for ids in proxy._event_ids.values())      # noqa: SLF001
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5088"]


async def test_the_event_id_map_is_bounded_in_bytes_and_entries(monkeypatch):
    from norviq.mcp import http as http_mod

    monkeypatch.setattr(http_mod, "_MAX_EVENT_ID_BUDGET", 2000)
    monkeypatch.setattr(http_mod, "_MAX_EVENT_IDS", 50)
    frames = [_ping_frame(f"{i:0>200}".encode(), i) for i in range(40)]
    proxy, pc = await _proxy_client(_frames_upstream(frames))
    for mid in range(3):
        await pc.post("/mcp", json={"jsonrpc": "2.0", "id": mid, "method": "ping"},
                      headers={"accept": "text/event-stream"})
    ids = next(iter(proxy._event_ids.values()))                           # noqa: SLF001
    assert ids.bytes <= 2000 and len(ids.entries) <= 50


async def test_one_stream_cannot_evict_another_streams_resumption_ids(monkeypatch):
    from norviq.mcp import http as http_mod

    monkeypatch.setattr(http_mod, "_MAX_EVENT_IDS_PER_STREAM", 8)
    first = await _proxy_client(_frames_upstream([_ping_frame(b"first")]))
    proxy, pc = first
    r1 = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                       headers={"accept": "text/event-stream"})
    kept = next(line[4:] for line in r1.text.splitlines() if line.startswith("id: "))
    proxy._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_frames_upstream(  # noqa: SLF001
        [_ping_frame(str(i).encode(), i) for i in range(500)])), base_url="http://u")
    await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                  headers={"accept": "text/event-stream"})
    ids = next(iter(proxy._event_ids.values()))                           # noqa: SLF001
    assert ids.get(kept) is not None, "a busy stream evicted another stream's resumption id"
    assert len(ids.entries) <= 1 + 8


async def test_an_event_id_minted_for_one_caller_resumes_nothing_for_another():
    """The map is per attested caller; another caller presenting the id resumes nothing."""
    seen: list = []
    answer = {"jsonrpc": "2.0", "id": 77, "result": {"tools": [POISONED_TOOL, CLEAN_TOOL]}}
    proxy, pc = await _proxy_client(_resuming_upstream([b"id: s1\ndata: " + json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}).encode() + b"\n\n"],
        answer, seen))
    posted = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                           headers={"accept": "text/event-stream"})
    minted = next(line[4:] for line in posted.text.splitlines() if line.startswith("id: "))
    proxy._identity_key = "spiffe://norviq/ns/other/sa/someone-else"   # noqa: SLF001 - a second caller
    resumed = await pc.get("/mcp", headers={"accept": "text/event-stream", "last-event-id": minted})
    assert '"result"' not in resumed.text
    assert seen == [minted], "an unknown id is forwarded as the client sent it, and resumes nothing"


async def test_an_empty_event_id_passes_through_as_the_reset_it_is():
    proxy, pc = await _proxy_client(_frames_upstream([_ping_frame(b"")]))
    r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                      headers={"accept": "text/event-stream"})
    assert any(line in ("id: ", "id:") for line in r.text.splitlines()), r.text
    assert not any(ids.entries for ids in proxy._event_ids.values())      # noqa: SLF001


async def test_the_event_id_map_is_bounded_in_entries_when_ids_are_small(monkeypatch):
    from norviq.mcp import http as http_mod

    monkeypatch.setattr(http_mod, "_MAX_EVENT_IDS", 10)
    proxy, pc = await _proxy_client(_frames_upstream([_ping_frame(str(i).encode(), i) for i in range(20)]))
    for mid in range(2):
        await pc.post("/mcp", json={"jsonrpc": "2.0", "id": mid, "method": "ping"},
                      headers={"accept": "text/event-stream"})
    assert len(next(iter(proxy._event_ids.values())).entries) <= 10     # noqa: SLF001
