# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""An attack path that starts at an MCP server rather than an agent (Part 6b).

"If this MCP server were compromised, what does it reach" is not answerable from any agent's row: a
poisoned tool definition steers whichever agent happens to be connected, so the blast radius belongs
to the SERVER. The `serves` edge added with the MCP_SERVER graph node is what makes the walk possible.

WHY THIS FILE EXERCISES `_build_path` AND `_derive_paths` DIRECTLY. Every hermetic test of the
attack-paths endpoint monkeypatches `_derive_paths` away, and the only end-to-end "a path exists"
assertion lives in an integration test that skips without a live API. So the derivation — the thing
this change actually alters — has no CI coverage at all, and a non-agent origin could be added, produce
zero paths or a wrong payload, and every gate would stay green. These tests call the real functions.
"""

from __future__ import annotations

import pytest

from norviq.api.routers import threats as T
from norviq.api.synthetic import is_synthetic_identity


def _node(nid: str, ntype: str, name: str, **props) -> dict:
    return {"id": nid, "type": ntype, "name": name, "props": {"namespace": "agents", **props}}


def _graph():
    """One agent and one MCP server, both reaching the same tool, which reaches sensitive data."""
    nodes = {
        "spiffe://norviq/ns/agents/sa/support": _node(
            "spiffe://norviq/ns/agents/sa/support", "agent", "support-agent",
            agent_class="support-agent", trust_score=0.9),
        "mcp:reporting-kb": _node("mcp:reporting-kb", "mcp_server", "reporting-kb",
                                  server_id="reporting-kb", transport="http", tool_count=1),
        "tool:read_file": _node("tool:read_file", "tool", "read_file", risk_level="medium"),
        "data:pg/customers": _node("data:pg/customers", "data", "pg/customers", sensitivity="high"),
    }
    edges = {
        "spiffe://norviq/ns/agents/sa/support": [
            {"target": "tool:read_file", "type": "calls", "hist": {"allow": 5, "block": 0, "escalate": 0}}],
        "mcp:reporting-kb": [{"target": "tool:read_file", "type": "serves", "hist": {}}],
        "tool:read_file": [{"target": "data:pg/customers", "type": "accesses", "hist": {}}],
    }
    return nodes, edges


CHAIN = ["mcp:reporting-kb", "tool:read_file", "data:pg/customers"]


class TestTheOriginPredicate:
    def test_an_mcp_server_can_start_a_path(self):
        nodes, _ = _graph()
        assert T._origin_kind(nodes["mcp:reporting-kb"]) == "mcp_server"

    def test_an_agent_still_can(self):
        nodes, _ = _graph()
        assert T._origin_kind(nodes["spiffe://norviq/ns/agents/sa/support"]) == "agent"

    def test_a_tool_and_a_data_node_still_cannot(self):
        """The origin gate is what stops every tool in the estate becoming the root of its own
        kill-chain — widening it carelessly would multiply the path count by the tool count."""
        nodes, _ = _graph()
        assert T._origin_kind(nodes["tool:read_file"]) == ""
        assert T._origin_kind(nodes["data:pg/customers"]) == ""

    def test_the_agent_predicate_is_UNCHANGED(self):
        """`_is_source_agent` has four conjuncts and three encode real properties of agents — an
        identity super-node has no outgoing edges, an awaiting agent has made no calls, a class-less
        agent cannot be governed by an agent-class policy. The MCP arm is separate precisely so
        admitting a new kind could not quietly change what counts as an agent origin."""
        assert T._origin_kind(_node("x", "agent", "x", agent_class="c", is_identity=True)) == ""
        assert T._origin_kind(_node("x", "agent", "x", agent_class="c", awaiting=True)) == ""
        assert T._origin_kind(_node("x", "agent", "x", agent_class="")) == ""


class TestTheDerivedPath:
    def test_the_walk_reaches_data_through_the_serves_edge(self):
        nodes, edges = _graph()
        chains = list(T._walk_paths("mcp:reporting-kb", edges, nodes))
        assert chains, "the serves edge did not carry the traversal"
        assert any(c[-1] == "data:pg/customers" for c in chains)

    def test_the_path_reports_its_origin_kind(self):
        nodes, edges = _graph()
        p = T._build_path(CHAIN, nodes, edges)
        assert p.src_kind == "mcp_server"
        assert p.src == "reporting-kb"

    def test_an_agent_path_still_reports_agent(self):
        """The default has to hold: every path that existed before this change must be unchanged."""
        nodes, edges = _graph()
        p = T._build_path(
            ["spiffe://norviq/ns/agents/sa/support", "tool:read_file", "data:pg/customers"],
            nodes, edges)
        assert p.src_kind == "agent"
        assert p.cls == "support-agent"
        assert p.trust == 0.9

    def test_cls_and_trust_are_NULL_not_empty_and_fabricated(self):
        """The defect this replaces. `str(props.get("agent_class") or "")` produced "", which reads as
        "an agent whose class we could not determine" — a different and more alarming claim than "this
        did not start at an agent". `float(props.get("trust_score") or 0.8)` was worse: it invented a
        near-best trust that renders GREEN and feeds the severity formula."""
        nodes, edges = _graph()
        p = T._build_path(CHAIN, nodes, edges)
        assert p.cls is None
        assert p.trust is None


class TestSeverityComesFromTheRegistryNotAFabricatedTrust:
    """The operator's decisions on the MCP Servers page are what move this number."""

    def _sev(self, registry, sensitive: bool = True):
        nodes, edges = _graph()
        if not sensitive:
            # A LESS SENSITIVE target, on purpose. With a sensitive target the formula saturates —
            # `origin_risk * 0.5 + 0.35 + 0.15` is >= 1.0 for anything above origin_risk 0.5 — so both
            # an unreviewed and a registered server land in "critical" and the registry distinction is
            # invisible at severity granularity. That is a property of the shared severity buckets, not
            # of this change, and rebalancing them would move every agent path's severity too. The
            # distinction is asserted where the formula is not pinned.
            nodes["data:pg/customers"]["props"]["sensitivity"] = "low"
            nodes["data:pg/customers"]["type"] = "tool"
        return T._build_path(CHAIN, nodes, edges, mcp_registry=registry).sev

    def test_an_unreviewed_server_reaching_a_crown_jewel_is_CRITICAL(self):
        """With the old fabricated 0.8 the trust term contributed 0.10 to a formula whose other terms
        cap at 0.50, so this path could never exceed "high" — a server nobody has reviewed, reaching
        customer data, presented as one rung down from the worst thing on the page."""
        assert self._sev({}) == "critical"

    def test_a_REGISTERED_server_ranks_below_an_unreviewed_one(self):
        """An operator who vouched for a server has told us something. Ranking it identically to one
        nobody has looked at would make the registry decision cosmetic."""
        registered = self._sev({("agents", "reporting-kb"): {"status": "registered", "writable": False}},
                               sensitive=False)
        unreviewed = self._sev({}, sensitive=False)
        assert registered != unreviewed
        assert T._SEVERITY_ORDER[registered] > T._SEVERITY_ORDER[unreviewed]

    def test_the_registry_term_separates_them_even_where_severity_saturates(self):
        """The bucket can hide the difference; the term underneath must not. This is what a future
        change to the severity weights would be measured against."""
        assert T._origin_risk("mcp_server", _node("m", "mcp_server", "kb", server_id="kb"), {}) > \
               T._origin_risk("mcp_server", _node("m", "mcp_server", "kb", server_id="kb"),
                              {("agents", "kb"): {"status": "registered"}})

    def test_a_BLOCKED_server_is_not_the_worst(self):
        """Its tools are withheld at discovery, so the reach is topology enforcement already covers.
        Ranking it above the servers nobody has reviewed would put the handled ones at the top of a
        list whose job is to surface what is not."""
        blocked = self._sev({("agents", "reporting-kb"): {"status": "blocked", "writable": False}})
        assert T._SEVERITY_ORDER[blocked] >= T._SEVERITY_ORDER[self._sev({})]

    def test_a_server_with_no_registry_row_is_treated_as_unreviewed(self):
        """No row IS `discovered` — the same equivalence the registry API reports as previous_status."""
        assert self._sev({}) == self._sev(
            {("agents", "reporting-kb"): {"status": "discovered", "writable": False}})

    def test_an_UNKNOWN_origin_kind_scores_worst_case(self):
        """A future origin kind nobody has taught the risk table about must not arrive scoring safe."""
        assert T._origin_risk("something_new", _node("x", "x", "x"), {}) == T._UNKNOWN_ORIGIN_RISK


class TestTheHonestDegradations:
    def test_the_verdict_does_not_tell_the_operator_to_SIMULATE(self):
        """Decision history is keyed (agent_id, tool_name) and no audit row will ever carry
        `agent_id = "mcp:<server>"`, so this path is permanently "unsimulated" and the standard
        sentence asks for something that cannot work."""
        nodes, edges = _graph()
        p = T._build_path(CHAIN, nodes, edges)
        assert "simulate" not in p.verdict.lower()
        assert "by construction" in p.verdict.lower()

    def test_the_status_VALUE_is_reused_rather_than_invented(self):
        """`_STATUS_ORDER[p.status]` is a direct index in the dedupe, so a new string raises KeyError —
        and the same map drives the pre-cap ranking, so a new rank would decide by accident whether
        these displace agent findings in the capped view."""
        nodes, edges = _graph()
        p = T._build_path(CHAIN, nodes, edges)
        assert p.status in T._STATUS_ORDER

    def test_an_mcp_origin_is_not_mistaken_for_a_probe(self):
        """The synthetic filter takes a class; a non-agent origin has none. It falls through to the
        SVID parse, which cannot match `mcp:<server>` — so these are not silently hidden as test noise.
        Asserted rather than assumed, because being wrong here means the feature renders nothing."""
        assert is_synthetic_identity("", "mcp:reporting-kb") is False


@pytest.mark.asyncio
class TestTheEndpointAccounting:
    """The invariant `sum(class_totals) + non_agent_paths == total_paths`.

    `if p.cls:` skipped a class-less path while `total_paths = len(all_paths)` counted it, so the
    invariant broke silently — and the test that asserts it uses a fixture where every path has a
    class, so it would have stayed green.
    """

    async def _serve(self, monkeypatch, paths, cls=None):
        async def fake_derive(_s, _ns, _cls, _hours=24, cap=None):
            return list(paths), ["agents"], 0

        monkeypatch.setattr(T, "_derive_paths", fake_derive)
        monkeypatch.setattr(T, "_resolve_namespaces", lambda user, requested: ["agents"])
        # Every parameter passed explicitly: calling the route function directly bypasses FastAPI's
        # dependency resolution, so an omitted one arrives as its `Query(...)` default object rather
        # than None — which trips the route's own ns/namespace conflict check.
        return await T.get_threat_paths(ns="agents", namespace=None, cls=cls, range="24h",
                                        include_synthetic=False, session=None,
                                        user={"role": "admin", "namespace": "*"})

    def _path(self, pid, cls, src_kind="agent"):
        from norviq.api.schemas.threats import ThreatPath
        return ThreatPath(id=pid, sev="high", src="s", tgt="t", ns="agents", src_kind=src_kind,
                          cls=cls, mitre="", hops=2, blast=1, status="unsimulated", tool="read_file")

    async def test_the_totals_reconcile_with_a_non_agent_origin_present(self, monkeypatch):
        resp = await self._serve(monkeypatch, [
            self._path("a", "support-agent"),
            self._path("b", "support-agent"),
            self._path("c", None, "mcp_server"),
        ])
        assert resp.total_paths == 3
        assert resp.class_totals == {"support-agent": 2}
        assert resp.non_agent_paths == 1
        assert sum(resp.class_totals.values()) + resp.non_agent_paths == resp.total_paths

    async def test_class_totals_gains_no_synthetic_mcp_KEY(self, monkeypatch):
        """The map is keyed by agent class. An "mcp_server" key would collide with a real class of
        that name and break the contract every consumer reads it under."""
        resp = await self._serve(monkeypatch, [self._path("c", None, "mcp_server")])
        assert "mcp_server" not in resp.class_totals
        assert resp.class_totals == {}
