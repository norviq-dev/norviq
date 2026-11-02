# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Round-3 review follow-ups on the HTTP driver and the cold-catalog self-list.

* a message forwarded unchanged reaches an SSE client as ONE parseable `data:` value;
* upstream messages are read into memory only up to `mcp_http_max_message_bytes`;
* the self-list's single flight and back-off belong to the credential that sent it;
* behaviour the mutation run showed untested: timeout 0, the HTTP report after a self-list, the
  random self-list id, and an answer with no tools list.
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from structlog.testing import capture_logs

from norviq.config import settings
from test_cold_catalog import CLEAN_TOOL, POISONED_TOOL, _call, _fw, _Lister, _make, _post, _rpc_msg
from test_http_sse_framing import _sse_events, _sse_only_post, _with_upstream
from test_http_transport import _rpc

_PING_RESULT = {"jsonrpc": "2.0", "id": 5, "result": {}}


# ── (a) one data: value per message ─────────────────────────────────────────────────────────────
def test_a_clean_message_spread_over_data_lines_reaches_the_client_parseable():
    async def handler(request: Request) -> Response:
        body = json.loads(await request.body())
        pretty = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {}}, indent=1).encode()

        async def gen():
            yield b"".join(b"data: " + line + b"\n" for line in pretty.split(b"\n")) + b"\n"
        return StreamingResponse(gen(), media_type="text/event-stream")
    client, _ = _with_upstream(handler)
    events = _sse_events(_sse_only_post(client, _rpc("ping", mid=5)))
    assert [json.loads(e["data"]) for e in events] == [_PING_RESULT]


def test_a_pretty_printed_json_body_on_the_stream_path_reaches_the_client_parseable():
    async def handler(request: Request) -> Response:
        body = json.loads(await request.body())
        return Response(json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": {}}, indent=2),
                        media_type="application/json")
    client, _ = _with_upstream(handler)
    events = _sse_events(_sse_only_post(client, _rpc("ping", mid=5)))
    assert [json.loads(e["data"]) for e in events] == [_PING_RESULT]


# ── (b) size bounds and media-type matching ─────────────────────────────────────────────────────
def _big(request_id) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [
        dict(CLEAN_TOOL, name=f"t{i}", description="x" * 400) for i in range(40)]}}


def test_an_oversized_json_answer_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "mcp_http_max_message_bytes", 4096)

    async def handler(request: Request) -> Response:
        return JSONResponse(_big(json.loads(await request.body())["id"]))
    client, _ = _with_upstream(handler)
    with capture_logs() as logs:
        r = client.post("/mcp", json=_rpc("tools/list", mid=5), headers={"accept": "application/json"})
    assert r.status_code == 502 and r.json()["error"]["code"] == -32603
    assert "t0" not in r.text
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5085"]


def test_an_oversized_non_stream_body_on_the_stream_path_emits_nothing(monkeypatch):
    monkeypatch.setattr(settings, "mcp_http_max_message_bytes", 4096)

    async def handler(request: Request) -> Response:
        return JSONResponse(_big(json.loads(await request.body())["id"]))
    client, _ = _with_upstream(handler)
    with capture_logs() as logs:
        text = _sse_only_post(client, _rpc("tools/list", mid=5))
    assert "t0" not in text
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5085"]


async def test_an_sse_frame_that_never_ends_is_cut_off_at_the_limit(monkeypatch):
    """No blank line ever arrives; the pending frame must not grow without bound."""
    monkeypatch.setattr(settings, "mcp_http_max_message_bytes", 4096)
    _, _, _, proxy, _ = _make()
    fw = await proxy._firewall_for_caller()                            # noqa: SLF001
    fed = 0

    class _Resp:
        headers = {"content-type": "text/event-stream"}

        async def aiter_bytes(self):
            nonlocal fed
            yield b"data: {"
            for _ in range(2000):        # finite, so a missing bound fails the test instead of hanging it
                fed += 1
                yield b'"x":1,' * 50

    with capture_logs() as logs:
        out = [chunk async for chunk in proxy._pump_frames(fw, _Resp())]  # noqa: SLF001
    assert out == [] and fed < 50
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5085"]


async def test_the_sse_media_type_is_matched_case_insensitively():
    """`Text/Event-Stream` is an SSE stream. Read as a JSON body it was buffered to its end."""
    _, _, _, proxy, _ = _make()
    fw = await proxy._firewall_for_caller()                            # noqa: SLF001
    fw.note_client_request(_rpc_msg({"jsonrpc": "2.0", "id": 5, "method": "ping"}))

    class _Resp:
        headers = {"content-type": "Text/Event-Stream; charset=utf-8"}

        async def aiter_bytes(self):
            yield b"data: " + json.dumps(_PING_RESULT).encode() + b"\n\n"
            await asyncio.sleep(30)

    frames = proxy._pump_frames(fw, _Resp())                           # noqa: SLF001
    first = await asyncio.wait_for(frames.__anext__(), 2)
    await frames.aclose()
    assert json.loads(first.split(b"data: ", 1)[1]) == _PING_RESULT


def test_a_decoded_body_is_not_labelled_with_the_upstreams_content_encoding():
    from norviq.mcp.http import _passthrough

    assert "content-encoding" not in {k.lower() for k in _passthrough(
        {"Content-Encoding": "gzip", "X-Other": "1"})}


# ── (c) single flight and back-off per credential ───────────────────────────────────────────────
async def test_one_callers_failed_list_does_not_back_off_another_caller(monkeypatch):
    monkeypatch.setattr(settings, "mcp_cold_list_timeout_s", 1.0)
    client, upstream, evaluator, proxy, _ = _make()
    seen_auth: list[str] = []
    inner = upstream.handle

    async def by_token(request: Request) -> Response:
        body = json.loads(await request.body())
        if body.get("method") == "tools/list":
            seen_auth.append(request.headers.get("authorization", ""))
            if request.headers.get("authorization") == "Bearer revoked":
                upstream.received.append(body)
                return Response(b"unauthorised", status_code=401)
        return await inner(request)

    proxy._client = httpx.AsyncClient(                                 # noqa: SLF001
        transport=httpx.ASGITransport(app=Starlette(routes=[Route("/mcp", by_token, methods=["POST"])])),
        base_url="http://upstream")
    bad = await client.post("/mcp", json=_call("search_docs", 1), headers={"authorization": "Bearer revoked"})
    good = await client.post("/mcp", json=_call("search_docs", 2), headers={"authorization": "Bearer valid"})

    assert bad.json()["result"]["_meta"]["norviq"]["rule_id"] == "mcp_definition_never_scanned"
    assert good.json()["result"]["isError"] is False, good.json()
    assert seen_auth == ["Bearer revoked", "Bearer valid"]


async def test_concurrent_calls_with_different_credentials_do_not_share_one_list():
    fw, _ = _fw()
    gate = asyncio.Event()
    a, b = _Lister(gate=gate), _Lister(gate=gate)
    a.credential_key, b.credential_key = "A", "B"
    calls = [asyncio.ensure_future(fw.on_client_message(_rpc_msg(_call("search_docs", i)), list_upstream=lst))
             for i, lst in ((1, a), (2, b), (3, a))]
    await asyncio.sleep(0.01)
    gate.set()
    await asyncio.gather(*calls)
    assert len(a.requests) == 1 and len(b.requests) == 1


# ── (d) mutation survivors ──────────────────────────────────────────────────────────────────────
async def test_timeout_zero_sends_no_list_and_logs_no_failure(monkeypatch):
    monkeypatch.setattr(settings, "mcp_cold_list_timeout_s", 0)
    fw, _ = _fw()
    lister = _Lister()
    with capture_logs() as logs:
        await fw.on_client_message(_rpc_msg(_call("search_docs")), list_upstream=lister)
    assert lister.requests == []
    assert not [e for e in logs if e.get("code") in ("NRVQ-MCP-5079", "NRVQ-MCP-5080")]


async def test_a_self_list_is_reported_even_when_the_call_is_refused():
    """The report must come from the self-list, not from a later forwarded response: a call Gate A
    refuses has no upstream response to piggy-back on."""
    client, upstream, _, _, store = _make()
    upstream.tools = [POISONED_TOOL, CLEAN_TOOL]
    body = await _post(client, _call("add"))
    assert body["result"]["_meta"]["norviq"]["gate"] == "A"
    for _ in range(50):
        if store.flushed:
            break
        await asyncio.sleep(0.01)
    assert store.flushed and {t["tool_name"] for t in store.flushed[0]} == {"add", "search_docs"}


async def test_the_self_list_id_is_unpredictable():
    ids = []
    for _ in range(2):
        fw, _ = _fw()
        lister = _Lister()
        await fw.on_client_message(_rpc_msg(_call("search_docs")), list_upstream=lister)
        ids.append(lister.requests[0].id)
    assert ids[0] != ids[1]
    assert all(re.fullmatch(r"norviq-cold-list-[0-9a-f]{32}", i) for i in ids), ids


async def test_an_answer_without_a_tools_list_fails_and_backs_off():
    fw, _ = _fw()

    class _NoTools(_Lister):
        async def __call__(self, request):
            self.requests.append(request)
            return _rpc_msg({"jsonrpc": "2.0", "id": request.id, "result": {}})

    lister = _NoTools()
    with capture_logs() as logs:
        for mid in (1, 2):
            await fw.on_client_message(_rpc_msg(_call("search_docs", mid)), list_upstream=lister)
    assert len(lister.requests) == 1, "an answer with no tools list must back off like any failure"
    assert [e for e in logs if e.get("code") == "NRVQ-MCP-5080"]
    assert not [e for e in logs if e.get("code") == "NRVQ-MCP-5079"]
