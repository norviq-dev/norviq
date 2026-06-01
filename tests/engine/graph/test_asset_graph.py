# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for asset graph builder behavior."""

from norviq.engine.graph.asset_graph import AssetGraphBuilder


def test_add_nodes_and_edges() -> None:
    """Create agent, tool, data nodes and expected edges."""
    graph = AssetGraphBuilder()
    graph.add_agent("spiffe://a", "planner", "default", trust_score=0.2)
    graph.add_tool("execute_sql")
    graph.add_data("postgresql/users", sensitivity="critical")
    graph.record_tool_call("spiffe://a", "execute_sql", "allow", "default", "planner")
    graph.record_data_access("execute_sql", "postgresql/users")
    counts = graph.get_node_count()
    assert counts["agents"] == 1
    assert counts["tools"] == 1
    assert counts["data"] >= 1
    assert counts["edges"] >= 2


def test_duplicate_tool_call_increments_counts() -> None:
    """Increment edge and tool counters on duplicate call."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://a", "search_kb", "allow")
    graph.record_tool_call("spiffe://a", "search_kb", "audit")
    edge = graph.graph["spiffe://a"]["tool:search_kb"]
    tool = graph.graph.nodes["tool:search_kb"]
    assert edge["properties"]["call_count"] == 2
    assert edge["properties"]["last_decision"] == "audit"
    assert tool["properties"]["call_count"] == 2


def test_round_trip_serialization() -> None:
    """Preserve graph shape after to_dict/from_dict roundtrip."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://a", "get_customer", "allow")
    graph.record_delegation("spiffe://a", "spiffe://b", depth=2)
    graph.record_data_access("get_customer", "postgresql/customers")
    payload = graph.to_dict()
    clone = AssetGraphBuilder()
    clone.from_dict(payload)
    assert clone.get_node_count() == graph.get_node_count()


def test_node_limit_evicts_oldest_nodes() -> None:
    """Keep graph size bounded by configured max nodes."""
    graph = AssetGraphBuilder(max_nodes=100)
    for idx in range(120):
        graph.record_tool_call(f"spiffe://{idx}", f"tool_{idx}", "allow")
    assert graph.graph.number_of_nodes() <= 100
