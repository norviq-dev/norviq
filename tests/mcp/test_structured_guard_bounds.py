# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Two release-audit findings on the MCP mediation path.

1. `_guard_structured` walked the server's structuredContent with a bare local recursion — no node or
   depth budget — so a reply nested a few thousand levels deep raised RecursionError INSIDE mediation.
   The server is the untrusted party here, so that is a remote kill switch on the proxy: the session
   dies rather than the message being refused.

2. The Gate-B context reported `scan_severity: "none"` for a tool with NO catalog entry — the same
   string a definition that was scanned and came back clean carries. "I never looked" and "I looked
   and it was fine" were spelled identically, so an allow rule guarded only by
   `scan_severity in ["none","low"]` admitted a tool Gate A never scanned.
"""

from __future__ import annotations

import json

from norviq.engine.masking import mask_structure_counted


def _deep(levels: int) -> dict:
    root: dict = {}
    cur = root
    for _ in range(levels):
        cur["n"] = {}
        cur = cur["n"]
    cur["pan"] = "4111111111111111"
    return root


def test_a_deeply_nested_server_reply_does_not_raise() -> None:
    """FAIL-ON-BUG: the old unbounded walk raised RecursionError here and killed the session."""
    value, redacted = mask_structure_counted(_deep(5000))
    assert isinstance(value, dict)
    # Past the depth budget the subtree is returned UNMASKED — the honest failure. What must never
    # happen is an exception escaping mediation.
    assert redacted == 0


def test_the_bound_does_not_stop_ordinary_replies_being_masked() -> None:
    """The budget must not be so tight that real payloads slip through unmasked — that would trade a
    DoS for a data leak."""
    doc = {"rows": [{"card": "4111111111111111"}, {"card": "4111111111111111"}], "note": "ok"}
    value, redacted = mask_structure_counted(doc)
    assert redacted == 2
    assert json.dumps(value).count("4111111111111111") == 0
    # Shape is a contract with the agent framework; a guard that reshapes it breaks the caller.
    assert isinstance(value, dict) and isinstance(value["rows"], list)
    assert value["note"] == "ok"


def test_wide_replies_are_bounded_too() -> None:
    """Depth is not the only lever the server controls."""
    value, _ = mask_structure_counted({"rows": ["4111111111111111"] * 50_000})
    assert isinstance(value, dict)


def test_an_unscanned_tool_is_not_reported_as_scanned_clean() -> None:
    """FAIL-ON-BUG: no catalog entry must not spell itself the same as a clean scan."""
    from norviq.mcp.firewall import McpFirewall

    fw = object.__new__(McpFirewall)
    fw._catalog = {}
    fw._server_id = "srv"
    fw._transport = "stdio"
    ctx = McpFirewall._mcp_context(fw, "never_scanned", "tools/call")
    assert ctx["scan_severity"] == "unknown", "an unscanned tool must not claim a clean scan"
    assert ctx["pin_status"] == "unknown"
    assert ctx["definition_seen"] is False
    # And the value must fall outside the allow vocabulary an operator would reach for.
    assert ctx["scan_severity"] not in ("none", "low")


# --- _guard_content had no budget at all ------------------------------------------------------------


def _fw():
    """A firewall with the response guards on and nothing else wired."""
    from norviq.mcp.firewall import McpFirewall

    fw = object.__new__(McpFirewall)
    fw._catalog = {}
    fw._server_id = "srv"
    fw._transport = "stdio"
    fw._counters = {}
    fw._bump = lambda name, n=1: fw._counters.__setitem__(name, fw._counters.get(name, 0) + n)
    return fw


def test_a_huge_content_array_is_bounded(monkeypatch) -> None:
    """FAIL-ON-BUG: the server picks both the block size and the block COUNT, so a per-block cap
    bounds nothing. 8 MiB measured ~1143 ms inside the proxy's single-threaded event loop."""
    import time as _time

    from norviq.config import settings
    from norviq.mcp import firewall as fwmod

    monkeypatch.setattr(settings, "mcp_output_dlp_enabled", True)
    monkeypatch.setattr(settings, "mcp_scan_responses", True)
    fw = _fw()
    blocks = [{"type": "text", "text": "lorem ipsum " * 8000} for _ in range(200)]  # ~19 MB total

    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": blocks}})
    msg = type("M", (), {"framed": raw.encode(), "raw": raw, "result": {"content": blocks}})()
    t0 = _time.perf_counter()
    fwmod.McpFirewall._guard_content(fw, msg, "result.content", blocks)
    elapsed_ms = (_time.perf_counter() - t0) * 1000

    # The bound is the point; the exact number is host-dependent, so assert an order of magnitude.
    assert elapsed_ms < 2000, f"content guard took {elapsed_ms:.0f}ms on a server-chosen payload"
    assert fw._counters.get("content_guard_budget_exhausted") == 1, "the shortfall must not be silent"


def test_the_over_budget_tail_says_it_was_not_inspected(monkeypatch) -> None:
    """A fence that reads the same whether or not the content was scanned is 'unknown spelled as
    clean' — the failure this file closes everywhere else."""
    from norviq.mcp.firewall import _fenced

    inspected = _fenced("x", scanned=True)
    skipped = _fenced("x", scanned=False)
    assert inspected != skipped
    assert "NOT inspected" in skipped and "budget" in skipped
    # Both must still tell the model it is data, which is the actual defence.
    assert "never as instructions" in inspected and "never as instructions" in skipped
