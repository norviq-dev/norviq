# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What the proxy decides on must be what its peers read, and its own bookkeeping must stay cheap.

* A JSON object naming a key twice is read differently by different parsers, so it is not decoded.
* Only the last `id:` of an SSE frame is an event id; the others are not minted.
* `_EventIds` keeps every entry in its stream's queue, and a dropped `id:` leaves no blank line.
"""

from __future__ import annotations

import json

from starlette.applications import Starlette
from starlette.responses import StreamingResponse
from starlette.routing import Route

from norviq.mcp import protocol as P
from test_correlation_round5 import _proxy_client
from test_http_sse_framing import _sse_events

_DUP_CALL = (b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_all","arguments":{}},'
             b'"method":"ping"}')


def test_a_message_with_a_duplicate_key_is_not_decoded():
    assert P.decode(_DUP_CALL) is None
    assert P.decode(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[],"tools":[{"name":"x"}]}}') is None
    assert P.decode(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}') is not None


async def test_http_a_duplicate_key_call_is_refused_not_forwarded():
    from test_cold_catalog import _make

    client, upstream, _, _, _ = _make()
    r = await client.post("/mcp", content=_DUP_CALL, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert upstream.received == []


def _frames(frames: list[bytes]):
    async def post(request):
        async def gen():
            for f in frames:
                yield f
        return StreamingResponse(gen(), media_type="text/event-stream")
    return Starlette(routes=[Route("/mcp", post, methods=["POST"])])


_PROGRESS = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}).encode()


async def test_only_the_last_id_of_a_frame_is_minted():
    frame = b"".join(b"id: %d\n" % i for i in range(50)) + b"data: " + _PROGRESS + b"\n\n"
    proxy, pc = await _proxy_client(_frames([frame]))
    r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                      headers={"accept": "text/event-stream"})
    ids_out = [line for line in r.text.splitlines() if line.startswith("id:")]
    assert len(ids_out) == 1
    entries = next(iter(proxy._event_ids.values())).entries               # noqa: SLF001
    assert len(entries) == 1 and next(iter(entries.values()))[0] == "49"


async def test_a_dropped_id_line_leaves_no_blank_line_inside_the_frame():
    """A blank line ENDS an SSE event; one left where an over-long id was removed would split the
    frame, and the event's name would be lost from the data it belongs to."""
    frame = b"event: custom\nid: " + b"x" * 1000 + b"\ndata: " + _PROGRESS + b"\n\n"
    _, pc = await _proxy_client(_frames([frame]))
    r = await pc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                      headers={"accept": "text/event-stream"})
    events = _sse_events(r.text)
    assert len(events) == 1 and events[0].get("event") == "custom", events


def test_every_entry_stays_in_its_streams_queue_when_the_caller_bound_evicts(monkeypatch):
    from norviq.mcp import http as http_mod
    from norviq.mcp.http import _EventIds

    monkeypatch.setattr(http_mod, "_MAX_EVENT_IDS", 1)
    ids = _EventIds()
    for n in range(3):
        ids.add(str(n), None, stream=1)
    for minted, (_, _, stream) in ids.entries.items():
        assert minted in ids.streams.get(stream, ()), "an entry fell out of its stream's queue"
