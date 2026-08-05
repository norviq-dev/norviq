# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The eval-cache key must cover EVERY decision input, including the MCP context.

`_build_input` publishes the whole MCP document as `input.mcp` and lifts `input.direction` from it, so
a policy can gate on `pin_status`, `scan_severity`, `schema_enforced` or `surface`. The cache key did
not include it. Within the 5s TTL that means two calls with identical tool+params but different MCP
context share a cached decision — the same tool once `pinned` and once in `drift` returns whichever
was evaluated first. A drift block silently downgraded to an allow.

These are key-identity tests, not evaluate() tests: the key IS the security boundary, and asserting on
it directly is what makes the guarantee legible. The other two dimensions (`call_depth`, `workload`)
were omitted for the same reason and are pinned here too, so a future refactor cannot quietly drop one
while leaving this file passing on the MCP case alone.
"""

from __future__ import annotations

from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

SPIFFE = "spiffe://norviq/ns/default/sa/customer-support"


def _ev(**kw) -> ToolCallEvent:
    base = {
        "tool_name": "lookup_customer",
        "tool_params": {"id": "4021"},
        "agent_identity": AgentIdentity(
            spiffe_id=SPIFFE, namespace="default", agent_class="customer-support"
        ),
    }
    base.update(kw)
    return ToolCallEvent(**base)


def _key(event: ToolCallEvent) -> str:
    return OPAEvaluator.__new__(OPAEvaluator)._cache_tool_key(event)


def test_mcp_context_separates_the_key() -> None:
    """The regression. Same tool, same params — only `pin_status` differs, which a policy can read."""
    pinned = _ev(mcp={"server": "postgres", "surface": "tools/call", "pin_status": "pinned"})
    drift = _ev(mcp={"server": "postgres", "surface": "tools/call", "pin_status": "drift"})
    assert _key(pinned) != _key(drift)


def test_surface_separates_the_key() -> None:
    """`resources/read` and `tools/call` are different decisions on the same name."""
    call = _ev(mcp={"server": "fs", "surface": "tools/call"})
    read = _ev(mcp={"server": "fs", "surface": "resources/read"})
    assert _key(call) != _key(read)


def test_every_reported_mcp_fact_is_covered() -> None:
    """The whole document is hashed, not a hand-picked subset — so a fact added to the proxy's
    `_mcp_context` tomorrow is covered without anyone remembering to update this key. Each field is
    flipped one at a time from a fixed baseline; any field the key ignores fails here."""
    baseline = {
        "server": "s", "transport": "stdio", "surface": "tools/call", "pin_status": "pinned",
        "scan_severity": "none", "definition_seen": True, "catalog_stale": False,
        "schema_enforced": True, "schema_closed": True, "schema_notes": [], "direction": "call",
        "tool_digest": "abc123",
    }
    changed = {
        "server": "other", "transport": "http", "surface": "resources/read", "pin_status": "drift",
        "scan_severity": "critical", "definition_seen": False, "catalog_stale": True,
        "schema_enforced": False, "schema_closed": False, "schema_notes": ["unenforceable"],
        "direction": "answer", "tool_digest": "def456",
    }
    ref = _key(_ev(mcp=baseline))
    for field, new_value in changed.items():
        variant = {**baseline, field: new_value}
        assert _key(_ev(mcp=variant)) != ref, f"{field} does not reach the cache key"


def test_absent_and_empty_mcp_are_the_same_key() -> None:
    """`input.mcp` is `{}` either way, so these ARE the same decision input. Keeping them equal is what
    stops the fix from churning the key for all non-MCP traffic."""
    assert _key(_ev()) == _key(_ev(mcp={}))


def test_non_mcp_key_shape_is_unchanged() -> None:
    """Non-MCP traffic keeps its existing suffix — no cache-hit regression for the common path."""
    assert _key(_ev()).endswith(":d0:w")
    assert ":m" not in _key(_ev())


def test_call_depth_and_workload_still_separate_the_key() -> None:
    """Pinned alongside, so a refactor cannot drop a dimension this key already covers."""
    assert _key(_ev()) != _key(_ev(call_depth=3))
    deep = AgentIdentity(
        spiffe_id=SPIFFE, namespace="default", agent_class="customer-support", workload="billing"
    )
    assert _key(_ev()) != _key(_ev(agent_identity=deep))


def test_params_still_separate_the_key() -> None:
    assert _key(_ev()) != _key(_ev(tool_params={"id": "9999"}))
