# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The MCP server as a first-class node in the asset graph.

The tables answer "which servers exist and what did I decide about them". The graph answers the
question neither table can: the SHAPE — which agents reach which servers, through which tools, and
what a compromised one would put in reach. Without the node, an MCP estate is invisible on the one
screen an operator uses to ask "what can this agent touch".

The failure modes being defended here are all silent ones. A node type nothing counts, a node with no
edge that a filter drops, a kind with no colour or radius that draws as nothing — each renders as "no
MCP servers" rather than as an error.
"""

from __future__ import annotations

from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.models import EdgeType, NodeType

AGENT = "spiffe://norviq/ns/agents/sa/default"


def _graph() -> AssetGraphBuilder:
    g = AssetGraphBuilder()
    g.record_tool_call(AGENT, "read_file", "allow", "agents", "support-agent")
    g.record_mcp_serving("rugpull", "read_file", "agents", "http")
    return g


def test_the_server_becomes_a_node_of_its_own_kind() -> None:
    servers = _graph().get_mcp_servers()
    assert [s["label"] for s in servers] == ["rugpull"]
    assert servers[0]["type"] == NodeType.MCP_SERVER


def test_the_id_is_prefixed_so_a_server_and_a_tool_of_the_same_name_are_two_nodes() -> None:
    """Node ids share ONE namespace in the graph. A server called `read_file` and a tool called
    `read_file` would otherwise be a single node with two meanings and a merged edge set."""
    g = AssetGraphBuilder()
    g.add_tool("read_file", "agents")
    g.add_mcp_server("read_file", "agents")
    assert set(g.graph.nodes) == {"tool:read_file", "mcp:read_file"}


def test_the_edge_runs_server_to_tool() -> None:
    """Direction is not cosmetic: the server PROVIDES the definition. Reversing it would make the
    tool look like something that reaches out to the server, which is the opposite of the trust
    relationship an operator is being asked to judge."""
    g = _graph()
    assert g.graph.has_edge("mcp:rugpull", "tool:read_file")
    assert not g.graph.has_edge("tool:read_file", "mcp:rugpull")
    assert g.graph["mcp:rugpull"]["tool:read_file"]["type"] == EdgeType.SERVES


def test_the_agent_to_tool_edge_is_untouched() -> None:
    """The `serves` edge is additive. An existing agent->tool path, and everything derived from it,
    must read exactly as it did before MCP topology existed."""
    g = _graph()
    assert g.graph.has_edge(AGENT, "tool:read_file")
    assert g.graph[AGENT]["tool:read_file"]["properties"]["call_count"] == 1


def test_two_servers_serving_one_tool_NAME_are_two_edges() -> None:
    """`read_file` on `filesystem` and on `runbooks` are different definitions, scanned and approved
    independently — the collision the MCP Servers page already calls out. The engine governs both
    with one policy because it sees only the bare name, and the graph is where that fan-in is
    visible."""
    g = AssetGraphBuilder()
    g.record_mcp_serving("filesystem", "read_file", "agents")
    g.record_mcp_serving("runbooks", "read_file", "agents")
    assert set(g.graph.predecessors("tool:read_file")) == {"mcp:filesystem", "mcp:runbooks"}


def test_recording_the_same_serving_twice_does_not_double_the_tool_count() -> None:
    """Discovery re-runs on every list_changed notification, so this is the common case, not an edge
    one. A count that grew per re-list would be a call counter wearing a topology label."""
    g = AssetGraphBuilder()
    for _ in range(5):
        g.record_mcp_serving("kb", "search", "agents")
    assert g.graph.nodes["mcp:kb"]["properties"]["tool_count"] == 1


def test_a_server_with_no_tool_name_records_nothing() -> None:
    """`input.mcp` is PEP-reported and may be partial. A node built from an empty string would be a
    server called "" sitting in the estate map forever."""
    g = AssetGraphBuilder()
    g.record_mcp_serving("kb", "", "agents")
    g.record_mcp_serving("", "search", "agents")
    assert list(g.graph.nodes) == []


def test_the_node_count_INCLUDES_mcp_servers() -> None:
    """The gotcha this was written for. `get_node_count` was a 3-way if/elif chain, so a new kind
    counted in no bucket: it would be in the graph, on the screen, traversed by every analysis, and
    absent from the totals — a count that quietly disagreed with the picture."""
    counts = _graph().get_node_count()
    assert counts["mcp_servers"] == 1
    assert counts["agents"] == 1 and counts["tools"] == 1


def test_the_node_carries_no_pin_or_registration_state() -> None:
    """Those live in `mcp_servers` and `mcp_tool_pins`, where an operator changes them. A copy here
    would be a second answer to "is this server registered" that goes stale the moment somebody
    clicks Block — and the graph is refreshed by traffic, not by decisions."""
    props = _graph().get_mcp_servers()[0]["properties"]
    assert set(props) == {"server_id", "transport", "tool_count"}


def test_the_snapshot_round_trips_the_new_kind_as_a_plain_string() -> None:
    """The graph is persisted and re-read; the API projection reads `node["type"]` as a string. An
    enum that serialised as `NodeType.MCP_SERVER` would survive the round trip and match no UI
    branch."""
    import json

    import networkx as nx

    data = json.loads(json.dumps(nx.node_link_data(_graph().graph, edges="links"), default=str))
    kinds = {n["type"] for n in data["nodes"]}
    assert "mcp_server" in kinds
