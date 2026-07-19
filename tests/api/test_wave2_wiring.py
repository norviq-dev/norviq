# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Wave-2 UI-wiring unit tests.

A1 — synthetic/probe classification + graph filtering (default-hide seeded test identities).
B4 — parse namespace + agent_class from a SPIFFE id for the Agents table.
C1 — an apply re-stamps the last-applied time (even for unchanged content).
"""

from __future__ import annotations

from datetime import datetime, timezone

from norviq.api.routers.agents import _class_from_spiffe, _namespace_from_spiffe
from norviq.api.routers.graphs import _filter_synthetic_assets
from norviq.api.schemas.graphs import AssetEdge, AssetNode
from norviq.api.synthetic import is_synthetic_identity


# ---------------------------------------------------------------------------------------------
# A1 — synthetic classification
# ---------------------------------------------------------------------------------------------

def test_probe_naming_is_synthetic():
    assert is_synthetic_identity("allowlist-probe-d5e5")
    assert is_synthetic_identity("e2e-intent-1783251077894")
    assert is_synthetic_identity("policy-tester")
    assert is_synthetic_identity(None, "spiffe://norviq/ns/default/sa/allowlist-probe-abc")


def test_real_agents_are_not_synthetic():
    for real in ("customer-support", "deploy-bot", "report-runner", "brand-new-agent"):
        assert not is_synthetic_identity(real), real
    assert not is_synthetic_identity(None, "spiffe://norviq/ns/default/sa/customer-support")


def test_explicit_synthetic_marker_wins():
    # The harness can tag a probe SVID even if it does not match the naming convention.
    assert is_synthetic_identity("some-load-test", properties={"synthetic": True})
    assert is_synthetic_identity("some-load-test", properties={"norviq.io/synthetic": "true"})
    assert not is_synthetic_identity("some-load-test", properties={"synthetic": False})


# ---------------------------------------------------------------------------------------------
# A1 — graph node/edge filtering
# ---------------------------------------------------------------------------------------------

def _agent(nid: str, cls: str) -> AssetNode:
    return AssetNode(id=nid, type="agent", name=cls, properties={"agent_class": cls})


def _tool(nid: str) -> AssetNode:
    return AssetNode(id=nid, type="tool", name=nid, properties={})


def _edge(s: str, t: str) -> AssetEdge:
    return AssetEdge(source=s, target=t, type="calls", weight=1.0, properties={})


def test_filter_removes_synthetic_agents_edges_and_orphaned_tools():
    nodes = [
        _agent("a:real", "customer-support"),
        _agent("a:probe", "allowlist-probe-x"),
        _tool("t:shared"),       # used by the real agent → kept
        _tool("t:probe_only"),   # used ONLY by the probe → orphaned → dropped
    ]
    edges = [
        _edge("a:real", "t:shared"),
        _edge("a:probe", "t:shared"),
        _edge("a:probe", "t:probe_only"),
    ]
    kept_nodes, kept_edges, hidden = _filter_synthetic_assets(nodes, edges)
    kept_ids = {n.id for n in kept_nodes}
    assert hidden == 1
    assert "a:real" in kept_ids and "t:shared" in kept_ids
    assert "a:probe" not in kept_ids          # synthetic agent removed
    assert "t:probe_only" not in kept_ids     # orphaned tool removed (no lone dot)
    assert all(e.source != "a:probe" and e.target != "a:probe" for e in kept_edges)


def test_filter_keeps_a_quiet_real_agent_with_no_edges():
    nodes = [_agent("a:awaiting", "report-runner"), _agent("a:probe", "probe-xyz")]
    kept_nodes, _, hidden = _filter_synthetic_assets(nodes, [])
    assert hidden == 1
    assert {n.id for n in kept_nodes} == {"a:awaiting"}  # a real awaiting agent still gets its circle


def test_filter_noop_when_no_synthetics():
    nodes = [_agent("a:real", "customer-support"), _tool("t:x")]
    edges = [_edge("a:real", "t:x")]
    kept_nodes, kept_edges, hidden = _filter_synthetic_assets(nodes, edges)
    assert hidden == 0
    assert len(kept_nodes) == 2 and len(kept_edges) == 1


# ---------------------------------------------------------------------------------------------
# B4 — SPIFFE parsing for the Agents table
# ---------------------------------------------------------------------------------------------

def test_spiffe_namespace_and_class_parse():
    sid = "spiffe://norviq/ns/default/sa/deploy-bot"
    assert _namespace_from_spiffe(sid) == "default"
    assert _class_from_spiffe(sid) == "deploy-bot"


def test_spiffe_parse_is_defensive():
    assert _class_from_spiffe("spiffe://norviq/ns/default") is None
    assert _namespace_from_spiffe("not-a-spiffe") is None


# ---------------------------------------------------------------------------------------------
# C1 — apply re-stamps the last-applied time
# ---------------------------------------------------------------------------------------------

class _CacheStub:
    pass


class _EvalStub:
    def bind_loader(self, loader):
        return None


def test_mark_applied_records_and_returns_time():
    from norviq.engine.policy_loader import PolicyLoader

    loader = PolicyLoader(_CacheStub(), _EvalStub())  # type: ignore[arg-type]
    assert loader.get_applied_at("default", "customer-support") is None
    before = datetime.now(timezone.utc)
    loader.mark_applied("default", "customer-support")
    stamped = loader.get_applied_at("default", "customer-support")
    assert stamped is not None and stamped >= before
    # scoped per (ns, class)
    assert loader.get_applied_at("other", "customer-support") is None
