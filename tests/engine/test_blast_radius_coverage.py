# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-042: blast radius was empty by construction, not because nothing was reachable.

`TOOL_DATA_MAP` has eight literal entries and was the ONLY source of tool→data edges. Blast radius is
computed by walking those edges, so `GET /graph/blast-radius/{spiffe}` returned 200 with
`total_reachable: 0` and `attack_paths: []` for an agent with 300+ evaluations and 130 `shell_exec`
calls.

`exec_shell`, `drop_table`, `spawn_pod`, `modify_config` and `upload_file` are all in
`TOOL_RISK_MAP` — the product already calls them critical — and none of them was in the data map.
An all-empty blast radius does not read as "we cannot see this"; it reads as "nothing is reachable",
which is the most dangerous thing a security console can say wrongly.
"""

from __future__ import annotations

import pytest

from norviq.engine.graph.asset_graph import TOOL_DATA_MAP, TOOL_RISK_MAP, AssetGraphBuilder


def _data_edges(builder: AssetGraphBuilder, tool: str) -> list[str]:
    return sorted(
        v for u, v in builder.graph.edges()
        if u == f"tool:{tool}" and v.startswith("data:")
    )


@pytest.mark.parametrize("tool", ["exec_shell", "drop_table", "spawn_pod", "modify_config", "upload_file"])
def test_dangerous_tools_now_reach_something(tool):
    """Each of these is CRITICAL or HIGH in TOOL_RISK_MAP and had no data edge at all."""
    assert tool not in TOOL_DATA_MAP, "fixture assumption: these are the tools the static map misses"
    b = AssetGraphBuilder()
    b.add_tool(tool)
    b._record_mapped_data(tool)
    assert _data_edges(b, tool), f"{tool} still reaches nothing, so blast radius stays empty"


def test_critical_sensitivity_can_now_populate():
    """`blast.critical_data` was always empty because add_data defaulted to `medium` and nothing
    ever passed anything else."""
    b = AssetGraphBuilder()
    b.add_tool("exec_shell")
    b._record_mapped_data("exec_shell")
    node = b.graph.nodes[_data_edges(b, "exec_shell")[0]]
    assert node["properties"]["sensitivity"] == "critical"


def test_the_static_map_still_wins_where_it_has_an_answer():
    """The map is a seed, not a fallback: where a precise URI is known it must not be replaced by a
    coarse verb-derived one."""
    b = AssetGraphBuilder()
    b.add_tool("execute_sql")
    b._record_mapped_data("execute_sql")
    assert _data_edges(b, "execute_sql") == [
        "data:postgresql/orders", "data:postgresql/payments", "data:postgresql/users",
    ]


def test_a_derived_node_is_marked_as_derived():
    """Reporting a guess as a precise asset would be its own kind of lie — the console has to be able
    to tell 'the orders table' from 'this destroys something we could not name'."""
    b = AssetGraphBuilder()
    b.add_tool("exec_shell")
    b._record_mapped_data("exec_shell")
    node = b.graph.nodes[_data_edges(b, "exec_shell")[0]]
    assert node["properties"]["data_type"] == "derived"


def test_an_unclassifiable_tool_adds_no_noise():
    """A tool whose verb resolves to nothing must produce NO edge. An edge to a generic 'unknown'
    asset would inflate every blast radius with a node that means nothing."""
    b = AssetGraphBuilder()
    b.add_tool("acme_widget")
    b._record_mapped_data("acme_widget")
    assert _data_edges(b, "acme_widget") == []


def test_every_risk_mapped_tool_now_reaches_something():
    """The guard that would have caught this: a tool the product grades for risk but cannot place on
    the graph is invisible to blast radius, whatever its grade says."""
    unreachable = []
    for tool in TOOL_RISK_MAP:
        b = AssetGraphBuilder()
        b.add_tool(tool)
        b._record_mapped_data(tool)
        if not _data_edges(b, tool):
            unreachable.append(tool)
    assert unreachable == [], f"graded for risk but unreachable in the graph: {unreachable}"
