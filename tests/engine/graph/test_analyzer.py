# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for graph analyzer report output."""

from norviq.engine.graph.analyzer import GraphAnalyzer
from norviq.engine.graph.asset_graph import AssetGraphBuilder


def test_full_analysis_has_required_sections() -> None:
    """Emit summary, chokepoints, critical paths, and riskiest agents."""
    graph = AssetGraphBuilder()
    graph.record_tool_call("spiffe://agent", "execute_sql", "allow", "default", "planner")
    graph.record_data_access("execute_sql", "postgresql/users")
    report = GraphAnalyzer(graph).full_analysis()
    assert {"summary", "chokepoints", "critical_paths", "riskiest_agents"} <= set(report)
    assert report["summary"]["total_nodes"] >= 2
