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


def test_multiple_classes_under_one_identity_are_accumulated() -> None:
    """Two agent_classes on ONE SPIFFE id accumulate in agent_classes (read model expands them)."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://svc", "search_kb", "allow", "default", "support-bot")
    graph.record_tool_call("spiffe://svc", "execute_sql", "allow", "default", "payments-bot")
    props = graph.graph.nodes["spiffe://svc"]["properties"]
    # identity stays keyed by SPIFFE (single node); both classes are recorded
    assert graph.get_node_count()["agents"] == 1
    assert props["agent_classes"] == ["support-bot", "payments-bot"]


def test_repeated_same_class_is_not_duplicated() -> None:
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://svc", "search_kb", "allow", "default", "support-bot")
    graph.record_tool_call("spiffe://svc", "send_email", "allow", "default", "support-bot")
    assert graph.graph.nodes["spiffe://svc"]["properties"]["agent_classes"] == ["support-bot"]


def test_node_limit_evicts_oldest_nodes() -> None:
    """Keep graph size bounded by configured max nodes."""
    graph = AssetGraphBuilder(max_nodes=100)
    for idx in range(120):
        graph.record_tool_call(f"spiffe://{idx}", f"tool_{idx}", "allow")
    assert graph.graph.number_of_nodes() <= 100


def test_remove_node_deletes_node_and_incident_edges() -> None:
    """Admin housekeeping: removing a node takes its edges with it and reports absence honestly."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://a", "probe_tool", "allow", "default", "planner")
    graph.record_tool_call("spiffe://a", "search_kb", "allow", "default", "planner")
    edges_before = graph.graph.number_of_edges()
    assert graph.remove_node("tool:probe_tool") is True
    counts = graph.get_node_count()
    assert counts["tools"] == 1                      # only search_kb remains
    assert "tool:probe_tool" not in graph.graph
    assert graph.graph.number_of_edges() == edges_before - 1  # exactly the probe edge went with the node
    assert graph.remove_node("tool:probe_tool") is False  # idempotent: absent → False, no raise
