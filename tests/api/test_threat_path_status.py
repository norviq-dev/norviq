# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What a kill-chain's status says about the traffic behind it.

These drive the real `_assemble` -> `_snapshot_to_assets` -> `_build_path` -> `_derive_paths` chain
from a stored snapshot and a decision-count map, stubbing only the two database reads. Stubbing
`_derive_paths` or hand-building `hist` dicts is how the defects below stayed green: the tool -> data
hop's zero counts are produced by `_snapshot_to_assets`, so a test has to go through it.
"""

from __future__ import annotations

import pytest

from norviq.api.routers import threats as T

AGENT = "spiffe://norviq/ns/analytics/sa/data-analyst"


def _snapshot(tools: dict[str, list[str]]) -> dict:
    """One agent calling each tool; each tool reaching its listed data URIs (the stored graph shape)."""
    nodes = [{
        "id": AGENT, "type": "agent", "name": "data-analyst",
        "properties": {"agent_class": "data-analyst", "trust_score": 0.6},
    }]
    edges = []
    seen_data: set[str] = set()
    for tool, data in tools.items():
        nodes.append({"id": f"tool:{tool}", "type": "tool", "name": tool, "properties": {}})
        edges.append({"source": AGENT, "target": f"tool:{tool}", "type": "calls", "properties": {}})
        for uri in data:
            if uri not in seen_data:
                nodes.append({"id": f"data:{uri}", "type": "data", "name": uri,
                              "properties": {"sensitivity": "high"}})
                seen_data.add(uri)
            edges.append({"source": f"tool:{tool}", "target": f"data:{uri}", "type": "accesses",
                          "properties": {"access_type": "read"}})
    return {"nodes": nodes, "edges": edges}


def _counts(**per_tool: dict) -> dict:
    out = {}
    for tool, c in per_tool.items():
        out[(AGENT, tool)] = {"allow": 0, "block": 0, "escalate": 0, "would_block": 0, **c}
    return out


async def _derive(monkeypatch, snapshot: dict, counts: dict, namespaces=("analytics",)):
    async def _latest(_s, _ns):
        return [("analytics", snapshot)]

    async def _decisions(_s, _ns, _since):
        return counts

    async def _empty(*_a, **_k):
        return {}

    monkeypatch.setattr(T, "_latest_snapshots", _latest)
    monkeypatch.setattr(T, "_decision_counts", _decisions)
    for name in ("_verb_overrides", "_verb_evidence", "_governing_policies", "_mcp_registry"):
        monkeypatch.setattr(T, name, _empty)
    paths, _seen, _hidden = await T._derive_paths(None, list(namespaces) if namespaces else None,
                                                  None, 24, cap=None)
    return paths


@pytest.mark.asyncio
class TestAllowedTrafficIsExploitable:
    async def test_an_allowed_two_hop_path_is_exploitable(self, monkeypatch):
        """Six allowed send_email calls and no policy: the chain was walked end to end. The tool -> data
        hop has no audit rows of its own, so it read 0 calls and the path was stuck at "unsimulated"."""
        paths = await _derive(monkeypatch, _snapshot({"send_email": ["smtp/outbound"]}),
                              _counts(send_email={"allow": 6}))
        [p] = paths
        assert p.status == "exploitable", p.verdict
        assert p.steps[1].allow == 6
        assert p.steps[1].via == "send_email"
        assert p.steps[0].via is None

    async def test_the_verdict_says_the_evidence_is_per_tool_not_per_table(self, monkeypatch):
        """execute_sql reaches three tables and ran six times. Audit rows name the tool, never the table,
        so all three paths borrow the same six calls and all three read exploitable. The verdict said
        "reachable end-to-end" as if each table had its own evidence."""
        snap = _snapshot({"execute_sql": ["postgresql/users", "postgresql/orders", "postgresql/payments"]})
        paths = await _derive(monkeypatch, snap, _counts(execute_sql={"allow": 6}))
        assert [p.status for p in paths] == ["exploitable"] * 3
        for p in paths:
            assert "counted per tool, not per table" in p.verdict, p.verdict
            assert "audit rows do not name the data node" in p.verdict
            assert p.tgt in p.verdict, "the caveat names the table it does not prove"

    async def test_a_tool_terminal_path_carries_no_per_table_caveat(self, monkeypatch):
        """A chain ending at a tool has no borrowed hop: its counts are its own."""
        snap = _snapshot({"run_shell": []})
        paths = await _derive(monkeypatch, snap, _counts(run_shell={"allow": 2}))
        [p] = paths
        assert p.status == "exploitable", p.verdict
        assert "per table" not in p.verdict

    async def test_the_data_hop_carries_THIS_origins_calls_only(self, monkeypatch):
        """The accesses edge is shared by every agent that calls the tool. Another identity's allowed
        calls must not make this agent's chain exploitable."""
        snap = _snapshot({"send_email": ["smtp/outbound"]})
        other = "spiffe://norviq/ns/analytics/sa/other"
        snap["nodes"].append({"id": other, "type": "agent", "name": "other",
                              "properties": {"agent_class": "other"}})
        snap["edges"].append({"source": other, "target": "tool:send_email", "type": "calls", "properties": {}})
        counts = {(other, "send_email"): {"allow": 9, "block": 0, "escalate": 0, "would_block": 0}}
        paths = await _derive(monkeypatch, snap, counts)
        mine = [p for p in paths if p.cls == "data-analyst"]
        theirs = [p for p in paths if p.cls == "other"]
        assert [p.status for p in mine] == ["unsimulated"]
        assert [p.status for p in theirs] == ["exploitable"]

    async def test_mixed_traffic_is_exploitable(self, monkeypatch):
        """Some calls were blocked and some went through: the chain was still walked end to end."""
        paths = await _derive(monkeypatch, _snapshot({"execute_sql": ["postgresql/users"]}),
                              _counts(execute_sql={"allow": 4, "block": 2}))
        [p] = paths
        assert p.status == "exploitable", p.verdict
        assert (p.steps[1].allow, p.steps[1].deny) == (4, 2)

    async def test_a_blocked_call_blocks_the_data_hop_too(self, monkeypatch):
        paths = await _derive(monkeypatch, _snapshot({"run_shell": ["compute/destructive"]}),
                              _counts(run_shell={"block": 3}))
        [p] = paths
        assert p.status == "blocked"
        assert p.steps[1].deny == 3


@pytest.mark.asyncio
class TestMonitorWouldBlocksAreNotBlocks:
    async def test_a_monitor_would_block_is_its_own_status(self, monkeypatch):
        """analytics is in Monitor and nothing was ever blocked: execute_sql ran five times as `audit`.
        That path was reported "blocked", counted under the Blocked tile and hidden from Exploitable."""
        paths = await _derive(monkeypatch, _snapshot({"execute_sql": ["postgresql/users"]}),
                              _counts(execute_sql={"would_block": 5}))
        [p] = paths
        assert p.status == "would_block"
        assert p.status != "blocked"
        assert "ran" in p.verdict
        assert p.steps[0].dec == "would_block" and p.steps[1].dec == "would_block"

    async def test_nothing_in_a_monitor_namespace_reads_blocked(self, monkeypatch):
        snap = _snapshot({
            "execute_sql": ["postgresql/users", "postgresql/orders", "postgresql/payments"],
            "send_email": ["smtp/outbound"],
        })
        paths = await _derive(monkeypatch, snap,
                              _counts(execute_sql={"would_block": 5}, send_email={"allow": 6}))
        assert [p.status for p in paths if p.status == "blocked"] == []
        assert sorted(p.status for p in paths) == ["exploitable"] + ["would_block"] * 3

    async def test_would_block_ranks_after_exploitable_and_before_unsimulated(self, monkeypatch):
        snap = _snapshot({"execute_sql": ["postgresql/users"], "send_email": ["smtp/outbound"],
                          "read_file": ["fs/docs"], "run_shell": ["compute/destructive"]})
        paths = await _derive(monkeypatch, snap, _counts(
            execute_sql={"would_block": 2}, send_email={"allow": 1}, run_shell={"block": 1}))
        assert [p.status for p in paths] == ["exploitable", "would_block", "unsimulated", "blocked"]


@pytest.mark.asyncio
class TestSiblingChokepointsAreSeparatePaths:
    async def test_two_tools_reaching_one_table_are_two_paths(self, monkeypatch):
        """execute_sql and delete_record both reach postgresql/users. The id was (ns, src, tgt, hops),
        so they collapsed and the dedupe kept whichever was least blocked: the destructive one vanished."""
        snap = _snapshot({"execute_sql": ["postgresql/users"], "delete_record": ["postgresql/users"]})
        paths = await _derive(monkeypatch, snap,
                              _counts(execute_sql={"allow": 4}, delete_record={"would_block": 3}))
        assert sorted(p.tool for p in paths) == ["delete_record", "execute_sql"]
        assert len({p.id for p in paths}) == 2
