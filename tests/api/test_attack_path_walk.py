# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Regression: the ranked kill-chain must never DROP a reachable destructive chokepoint.

Surfaced by the live chatbot demo — a `customer-support` agent that invoked `execute_sql` (which fans
out to many data targets) and `delete_record` (a destructive tool-terminal). The old flat per-agent cap
(`_MAX_PATHS_PER_AGENT = 6`) was consumed by `execute_sql`'s many chains, so `delete_record` was silently
absent from `/threats/attack-paths` even though it had audit rows and an asset-graph edge. A security
operator must never lose sight of a reachable destructive tool because a benign/high-fan-out sibling was
walked first. `_walk_paths` now budgets each chokepoint independently and visits them worst-risk-first.
"""

from __future__ import annotations

from norviq.api.routers import threats as t


def _agent(nid: str, cls: str = "customer-support") -> dict:
    return {"id": nid, "type": "agent", "name": cls, "properties": {"agent_class": cls}}


def _tool(name: str) -> dict:
    return {"id": f"tool:{name}", "type": "tool", "name": name, "properties": {}}


def _data(name: str) -> dict:
    return {"id": f"data:{name}", "type": "data", "name": name, "properties": {"risk_level": "high"}}


def _edge(src: str, tgt: str, typ: str = "calls") -> dict:
    return {"source": src, "target": tgt, "type": typ, "properties": {}}


def _graph_with_starvation() -> tuple[dict, dict]:
    """Agent reaches execute_sql (fans to 10 data tables) AND delete_record (tool-terminal)."""
    agent = "agent:svc"
    nodes = {agent: _agent(agent)}
    out_edges: dict[str, list[dict]] = {agent: []}
    # high-fan-out critical tool: execute_sql -> 10 distinct data targets (10 candidate chains)
    nodes["tool:execute_sql"] = _tool("execute_sql")
    out_edges[agent].append(_edge(agent, "tool:execute_sql"))
    out_edges["tool:execute_sql"] = []
    for i in range(10):
        d = f"data:table{i}"
        nodes[d] = _data(f"table{i}")
        out_edges["tool:execute_sql"].append(_edge("tool:execute_sql", d, "accesses"))
    # destructive tool-terminal walked AFTER the fan-out tool in edge order
    nodes["tool:delete_record"] = _tool("delete_record")
    out_edges[agent].append(_edge(agent, "tool:delete_record"))
    # a couple of benign reads too
    for name in ("search_kb", "get_customer"):
        nodes[f"tool:{name}"] = _tool(name)
        out_edges[agent].append(_edge(agent, f"tool:{name}"))
    return nodes, out_edges


def _chokepoints(chains: list[list[str]], nodes: dict) -> set[str]:
    # the chokepoint is the first tool hop (index 1) of each chain
    return {nodes[c[1]]["name"] for c in chains if len(c) >= 2 and c[1] in nodes}


def test_destructive_chokepoint_survives_high_fanout_sibling() -> None:
    nodes, out_edges = _graph_with_starvation()
    chains = t._walk_paths("agent:svc", out_edges, nodes)
    choke = _chokepoints(chains, nodes)
    # the regression: delete_record must be present despite execute_sql's 10-way fan-out
    assert "delete_record" in choke, f"destructive chokepoint dropped; got {choke}"
    assert "execute_sql" in choke


def test_single_chokepoint_fanout_is_bounded() -> None:
    nodes, out_edges = _graph_with_starvation()
    chains = t._walk_paths("agent:svc", out_edges, nodes)
    sql_chains = [c for c in chains if len(c) >= 2 and nodes[c[1]]["name"] == "execute_sql"]
    # one high-fan-out tool cannot monopolise: bounded by _MAX_CHAINS_PER_CHOKEPOINT
    assert 1 <= len(sql_chains) <= t._MAX_CHAINS_PER_CHOKEPOINT


def test_every_destructive_chokepoint_survives_even_beyond_cap() -> None:
    """A class node unions every same-class identity's tools, so it can expose more than
    _MAX_CHOKEPOINTS_PER_AGENT critical tools. EVERY destructive chokepoint must still appear — the cap
    only trims the low-risk tail. Regression for delete_record vanishing behind ~20 sibling criticals on
    the merged customer-support class node."""
    agent = "agent:svc"
    nodes = {agent: _agent(agent)}
    out_edges: dict[str, list[dict]] = {agent: []}
    crit_tools = [f"delete_thing_{i}" for i in range(t._MAX_CHOKEPOINTS_PER_AGENT + 8)]
    for name in crit_tools:
        nodes[f"tool:{name}"] = _tool(name)
        out_edges[agent].append(_edge(agent, f"tool:{name}"))
    choke = _chokepoints(t._walk_paths(agent, out_edges, nodes), nodes)
    missing = [n for n in crit_tools if n not in choke]
    assert not missing, f"destructive chokepoints capped away: {missing}"


def test_chokepoints_visited_worst_risk_first() -> None:
    """When an agent has more reachable tools than the per-agent cap, the most dangerous are kept."""
    agent = "agent:svc"
    nodes = {agent: _agent(agent)}
    out_edges: dict[str, list[dict]] = {agent: []}
    # many benign reads (walked first in insertion order) + one critical delete at the very end
    for i in range(t._MAX_CHOKEPOINTS_PER_AGENT + 5):
        name = f"read_tool_{i}"
        nodes[f"tool:{name}"] = _tool(name)
        out_edges[agent].append(_edge(agent, f"tool:{name}"))
    nodes["tool:wipe_database"] = _tool("wipe_database")
    out_edges[agent].append(_edge(agent, "tool:wipe_database"))
    chains = t._walk_paths(agent, out_edges, nodes)
    choke = _chokepoints(chains, nodes)
    # 'read_tool_*' classify low, 'wipe_database' classifies critical -> must survive the cap
    assert "wipe_database" in choke, f"critical chokepoint truncated away; got {sorted(choke)}"
