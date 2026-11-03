# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Nesting depth is bounded where messages are decoded, in both directions."""

from __future__ import annotations

import pytest

from norviq.mcp import protocol as P
from test_cold_catalog import _fw, _make


def _nested(n: int) -> bytes:
    return b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x","arguments":{"b":' + \
        b"[" * n + b"]" * n + b"}}}"


@pytest.mark.parametrize("depth", [1, 100, P.MAX_DEPTH - 5])
def test_ordinary_depth_decodes(depth):
    assert P.decode(_nested(depth)) is not None


@pytest.mark.parametrize("depth", [P.MAX_DEPTH, 300, 1000, 100_000])
def test_excessive_depth_is_undecodable_without_crashing(depth):
    assert P.decode(_nested(depth)) is None


def test_a_wide_shallow_message_is_not_mistaken_for_a_deep_one():
    raw = b'{"jsonrpc":"2.0","id":1,"result":{"items":[' + b",".join([b'{"a":[1]}'] * 5000) + b"]}}"
    assert P.decode(raw) is not None


async def test_a_call_nested_100_deep_is_evaluated():
    fw, evaluator = _fw()
    await fw.on_client_message(P.decode(_nested(100)))
    assert evaluator.seen, "the call must reach policy evaluation"


async def test_http_a_call_nested_300_deep_is_refused_before_evaluation():
    client, upstream, evaluator, _, _ = _make()
    r = await client.post("/mcp", content=_nested(300), headers={"content-type": "application/json"})
    assert r.status_code == 400 and evaluator.seen == [] and upstream.received == []
