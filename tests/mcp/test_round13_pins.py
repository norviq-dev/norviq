# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Pins for guards that overlap, so each is held by a test of its own."""

from __future__ import annotations

import json

from norviq.config import settings
from norviq.mcp import protocol as P
from norviq.mcp import scanner as S
from test_cold_catalog import CLEAN_TOOL, _fw, _Lister, _call, _rpc_msg


def _deep_tool() -> dict:
    node: dict = {"type": "string"}
    for i in range(S._MAX_WALK_DEPTH):
        node = {"type": "object", "properties": {f"p{i}": node}}
    return {"name": "add", "description": "Adds.", "inputSchema": node}


async def test_a_truncated_definition_is_withheld_even_when_only_critical_findings_strip(monkeypatch):
    """`budget_exhausted` strips on its own; it does not depend on the truncation grade reaching the
    configured strip severity."""
    monkeypatch.setattr(settings, "mcp_scan_strip_severity", "critical")
    fw, _ = _fw()
    fw._corr.pending.put(5, "tools/list")                                  # noqa: SLF001
    out = await fw.on_server_message(_rpc_msg({"jsonrpc": "2.0", "id": 5, "result": {"tools": [_deep_tool(), CLEAN_TOOL]}}))
    assert [t["name"] for t in json.loads(out.forward)["result"]["tools"]] == ["search_docs"]


def test_the_walk_truncation_of_a_tool_definition_is_graded_high():
    report = S.scan_tool_definition(_deep_tool())
    assert {f.severity for f in report.findings if f.rule == "mcp_a_scan_truncated"} == {"high"}


def test_the_depth_bound_is_exact():
    nested = []
    for _ in range(P.MAX_DEPTH - 1):
        nested = [nested]
    assert P._deeper_than(nested, P.MAX_DEPTH) is False                  # exactly MAX_DEPTH levels
    assert P._deeper_than([nested], P.MAX_DEPTH) is True                 # one more


def test_a_message_of_exactly_the_bound_decodes_and_one_deeper_does_not():
    def message(depth: int) -> bytes:
        # The message object, `params` and `arguments` are three levels.
        inner = depth - 3
        return (b'{"jsonrpc":"2.0","id":1,"method":"m","params":{"arguments":{"a":'
                + b"[" * inner + b"]" * inner + b"}}}")
    assert P.decode(message(P.MAX_DEPTH)) is not None
    assert P.decode(message(P.MAX_DEPTH + 1)) is None


async def test_the_per_credential_cold_list_maps_are_bounded():
    from norviq.mcp import firewall as fw_mod

    fw, _ = _fw()

    class _Failing(_Lister):
        async def __call__(self, request):
            self.requests.append(request)
            return _rpc_msg({"jsonrpc": "2.0", "id": request.id, "error": {"code": 1, "message": "no"}})

    for i in range(fw_mod._COLD_LIST_MAX_CREDENTIALS + 10):
        lister = _Failing()
        lister.credential_key = f"cred-{i}"
        await fw.on_client_message(_rpc_msg(_call("search_docs", i + 1)), list_upstream=lister)
    assert len(fw._cold_list_failed) <= fw_mod._COLD_LIST_MAX_CREDENTIALS      # noqa: SLF001
    assert len(fw._cold_lists) <= fw_mod._COLD_LIST_MAX_CREDENTIALS            # noqa: SLF001
