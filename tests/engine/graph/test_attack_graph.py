# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for attack graph reachability and risk."""

from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.attack_graph import AttackGraphEngine


def _seed_graph() -> AssetGraphBuilder:
    """Create reusable graph with agent-tool-data chains."""
    graph = AssetGraphBuilder()
    graph.add_agent("spiffe://low", "worker", "default", trust_score=0.2)
    graph.add_agent("spiffe://high", "planner", "default", trust_score=0.9)
    graph.record_delegation("spiffe://high", "spiffe://low")
    graph.record_tool_call("spiffe://low", "execute_sql", "allow")
    graph.record_data_access("execute_sql", "postgresql/users")
    return graph


def test_blast_radius_and_attack_paths() -> None:
    """Return reachable nodes and at least one path."""
    engine = AttackGraphEngine(_seed_graph().graph)
    blast = engine.compute_blast_radius("spiffe://high")
    assert "tool:execute_sql" in blast.reachable_tools
    assert any(path.target.startswith("data:") for path in blast.attack_paths)


def test_critical_paths_and_chokepoints() -> None:
    """Find low-trust critical paths and tool chokepoints."""
    engine = AttackGraphEngine(_seed_graph().graph)
    critical = engine.find_critical_paths()
    chokepoints = engine.find_chokepoints()
    assert critical
    assert chokepoints and chokepoints[0]["tool"] == "tool:execute_sql"


def test_risk_matrix_returns_grid() -> None:
    """Create matrix entries for each agent and data node."""
    engine = AttackGraphEngine(_seed_graph().graph)
    matrix = engine.compute_risk_matrix()
    assert "spiffe://high" in matrix
    assert any(node.startswith("data:") for node in matrix["spiffe://high"])
