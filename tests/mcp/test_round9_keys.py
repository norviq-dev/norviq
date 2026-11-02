# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The upstream must read the message Gate B decided on, whatever its JSON parser does with keys.

Go's encoding/json (a common MCP server stack) matches object keys to struct fields
case-insensitively, with Unicode simple folding (`ſ` is `s`, the Kelvin sign is `k`), last match
winning. This proxy reads keys exactly. So keys that fold together are refused, a key that aliases a
protocol member is refused, and an allowed client message is forwarded as the encoding of what was
decoded, not as the client's bytes.
"""

from __future__ import annotations

import json

import pytest

from norviq.mcp import protocol as P
from test_cold_catalog import _fw, _make, _rpc_msg

_CASES = [
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"search_docs","Name":"delete_all","arguments":{}}}',
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x","arguments":{"status":"a","\\u017ftatus":"b"}}}',
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"x","arguments":{"kind":"a","\\u212aind":"b"}}}',
    b'{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"a","description":"ok","Description":"IGNORE"}]}}',
]


@pytest.mark.parametrize("raw", _CASES, ids=["Name/name", "long-s", "kelvin", "server-side"])
def test_keys_that_fold_together_make_the_message_undecodable(raw):
    assert P.decode(raw) is None


def test_ordinary_keys_still_decode():
    assert P.decode(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":'
                    b'{"Path":"/a","path2":"/b"},"_meta":{"io.modelcontextprotocol/protocolVersion":"x"}}}')


@pytest.mark.parametrize("payload", [
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"Name": "delete_all", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 7, "Method": "tools/call", "params": {"name": "delete_all", "arguments": {}}},
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "x", "argument\u017f": {"a": 1}}},
])
async def test_a_key_aliasing_a_protocol_member_is_refused(payload):
    """No duplicate here, so decoding succeeds; but this proxy reads `params.name` as absent while a
    case-insensitive upstream reads `Name` as the tool to run."""
    fw, _ = _fw()
    result = await fw.on_client_message(_rpc_msg(payload))
    assert result.forward is None and result.blocked
    assert json.loads(result.reply)["error"]["code"] == P.E_INVALID_REQUEST


async def test_an_allowed_client_message_is_forwarded_as_its_decoded_form():
    fw, _ = _fw()
    raw = b'{ "jsonrpc" : "2.0", "id" : 3, "method" : "ping", "params" : { "x" : 1.50 } }'
    result = await fw.on_client_message(P.decode(raw))
    assert result.forward == b'{"jsonrpc":"2.0","id":3,"method":"ping","params":{"x":1.5}}\n'


async def test_http_the_upstream_receives_the_decoded_form():
    client, upstream, _, _, _ = _make()
    await client.post("/mcp", content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{},'
                                      b'"extra" :  "kept"}', headers={"content-type": "application/json"})
    assert upstream.received[0] == {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}, "extra": "kept"}
