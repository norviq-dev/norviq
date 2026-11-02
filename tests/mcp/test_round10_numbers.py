# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Re-encoded client messages carry the numbers the client wrote; non-JSON numbers are refused;
`requestState` is a protocol member for the alias check; a post-back is bounded in total time."""

from __future__ import annotations

import asyncio
import contextlib
import json

import pytest

from norviq.mcp import protocol as P
from test_cold_catalog import _fw, _make, _rpc_msg


@pytest.mark.parametrize("literal", ["12345678901234567890.25", "0.1000000000000000055511151231257827",
                                     "1e2", "-0.0", "1.50", "3.0", "2.5"])
async def test_a_forwarded_client_number_keeps_its_literal(literal):
    fw, _ = _fw()
    raw = ('{"jsonrpc":"2.0","id":3,"method":"ping","params":{"amount":' + literal + '}}').encode()
    result = await fw.on_client_message(P.decode(raw))
    assert result.forward == raw + b"\n"


@pytest.mark.parametrize("raw", [b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":1e400}',
                                 b'{"a":-1e999}'])
def test_non_finite_numbers_are_not_decoded(raw):
    assert P.decode(raw) is None


async def test_request_state_is_a_protocol_member_for_the_alias_check():
    fw, _ = _fw()
    out = await fw.on_client_message(_rpc_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "search_docs", "arguments": {}, "RequestState": "x"}}))
    assert out.forward is None and out.note == "ambiguous_key"


async def test_a_post_back_is_bounded_in_total_time(monkeypatch):
    from norviq.mcp import http as http_mod

    monkeypatch.setattr(http_mod, "_POST_BACK_TIMEOUT_S", 0.1)
    _, _, _, proxy, _ = _make()

    class _Stalling:
        @contextlib.asynccontextmanager
        async def stream(self, *_a, **_kw):
            await asyncio.sleep(30)              # each phase within its own timeout, forever overall
            yield None

    proxy._client = _Stalling()                                          # noqa: SLF001
    await asyncio.wait_for(proxy._post_back(b"{}", {}), 2)               # noqa: SLF001


def test_json_encode_exact_matches_encode_without_literals():
    payload = {"a": 1, "b": [1.5, "x", None, True], "c": {"d": "é"}}
    assert P.encode_exact(payload) == P.encode(payload)
    assert json.loads(P.encode_exact(payload)) == payload
