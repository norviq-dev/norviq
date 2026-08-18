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

    def _sev(self, registry):
        nodes, edges = _graph()
        return T._build_path(CHAIN, nodes, edges, mcp_registry=registry).sev

    def test_an_unreviewed_server_reaching_a_crown_jewel_is_CRITICAL(self):
        """With the old fabricated 0.8 the trust term contributed 0.10 to a formula whose other terms
        cap at 0.50, so this path could never exceed "high" — a server nobody has reviewed, reaching
        customer data, presented as one rung down from the worst thing on the page."""
        assert self._sev({}) == "critical"

    def test_the_THREE_registry_states_land_in_THREE_severity_buckets(self):
        """The shape that actually occurs, which is why the weights for a non-agent origin differ.

        Every MCP-origin path ends at a data node through a chokepoint, so under the agent weights
        (`origin * 0.5 + 0.35 + 0.15`) everything above origin-risk 0.5 is >= 0.75 and renders
        "critical". Measured on the kind cluster: all eight MCP paths were critical, including two
        servers an operator had REGISTERED — the registry term was computed and invisible, a control
        that reads an operator's decisions and changes nothing they can see.
        """
        assert self._sev({}) == "critical"                                                   # unreviewed
        assert self._sev({("agents", "reporting-kb"): {"status": "registered"}}) == "high"
        assert self._sev({("agents", "reporting-kb"): {"status": "blocked"}}) == "medium"

    def test_an_AGENT_path_severity_is_untouched_by_the_new_weights(self):
        """The non-agent weighting is a separate branch on purpose. If it had replaced the shared
        formula, every agent path's severity would have moved — a silent re-grading of the whole page
        under cover of an MCP feature."""
        nodes, edges = _graph()
        agent_chain = ["spiffe://norviq/ns/agents/sa/support", "tool:read_file", "data:pg/customers"]
        p = T._build_path(agent_chain, nodes, edges)
        # trust 0.9 -> (1-0.9)*0.5 + 1.0*0.35 + 0.15 = 0.55 -> "high", exactly as before this change.
        assert p.sev == "high"

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
        # STRICTLY below. `>=` passed even when `blocked` was mutated to tie `discovered`, so the test
        # named a property it could not detect the inversion of.
        assert T._SEVERITY_ORDER[blocked] > T._SEVERITY_ORDER[self._sev({})]

    def test_a_server_with_no_registry_row_is_treated_as_unreviewed(self):
        """No row IS `discovered` — the same equivalence the registry API reports as previous_status.

        Asserted on the RISK TERM, not the severity bucket: every status used to land in "critical"
        here, so the equality held for any two values and the test proved nothing.
        """
        node = _node("m", "mcp_server", "kb", server_id="reporting-kb")
        assert T._origin_risk("mcp_server", node, {}) == T._origin_risk(
            "mcp_server", node, {("agents", "reporting-kb"): {"status": "discovered"}})

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


# ── what the adversarial pass found, each with the test that would have caught it ─────────────────

@pytest.mark.asyncio
class TestTheDefectsAnAdversarialPassFound:
    """Every one of these was demonstrated against the first cut of this change.

    They are grouped rather than scattered because they share a root: an origin whose NAME an
    attacker chooses, threaded into surfaces built when the only origin was an attested agent.
    """

    async def _derive(self, nodes, edges, cls=None, registry=None):
        """Drive the REAL `_derive_paths`, stubbing only its I/O.

        The file's docstring claims this, and until now the endpoint tests below monkeypatched
        `_derive_paths` away — so the ~40 lines that actually changed had no test calling them.
        """
        async def _assemble(_s, _ns, _hours):
            return nodes, edges, ["agents"]

        async def _empty(*_a, **_k):
            return {}

        import norviq.api.routers.threats as T2
        orig = (T2._assemble, T2._verb_overrides, T2._verb_evidence, T2._governing_policies, T2._mcp_registry)
        T2._assemble, T2._verb_overrides, T2._verb_evidence = _assemble, _empty, _empty
        T2._governing_policies = _empty
        T2._mcp_registry = lambda *_a, **_k: _wrap(registry or {})
        try:
            return await T2._derive_paths(None, ["agents"], cls, 24, cap=None)
        finally:
            (T2._assemble, T2._verb_overrides, T2._verb_evidence,
             T2._governing_policies, T2._mcp_registry) = orig

    async def test_non_agent_hidden_counts_PATHS_not_raw_chains(self):
        """One server serving two tools that both reach the same data is ONE path after dedupe, and
        the count that reports it hidden must say one. Counting chains put this number on a different
        denominator from `non_agent_paths`, which the schema comment ties it to."""
        nodes, edges = _graph()
        nodes["tool:query_db"] = _node("tool:query_db", "tool", "query_db", risk_level="medium")
        edges["mcp:reporting-kb"].append({"target": "tool:query_db", "type": "serves", "hist": {}})
        edges["tool:query_db"] = [{"target": "data:pg/customers", "type": "accesses", "hist": {}}]

        _all, _seen, hidden_unfiltered = await self._derive(nodes, edges)
        _filtered, _s2, hidden = await self._derive(nodes, edges, cls="support-agent")
        assert hidden_unfiltered == 0
        assert hidden == 1, "two chains collapsing to one path must be reported as one hidden path"

    async def test_a_flood_of_fabricated_origins_cannot_evict_agent_findings(self):
        """`input.mcp.server` is PEP-reported and unvalidated, so an agent that can reach /evaluate
        chooses the names that become path origins. Measured on the first cut: 300 fabricated servers
        pushed all five real agent kill-chains out of the 200-path view — the ranking held, but the
        thing being ranked was whatever the attacker minted most of."""
        nodes, edges = _graph()
        for i in range(400):
            nid = f"mcp:flood-{i:03d}"
            nodes[nid] = _node(nid, "mcp_server", f"flood-{i:03d}", server_id=f"flood-{i:03d}")
            edges[nid] = [{"target": "tool:read_file", "type": "serves", "hist": {}}]

        paths, _seen, _hidden = await self._derive(nodes, edges)
        agent_paths = [p for p in paths if p.src_kind == "agent"]
        assert agent_paths, "the agent kill-chain must still be derived"

        # The endpoint's kind-aware truncation is what protects it.
        kept_agents = [p for p in paths if p.cls is not None][:T._MAX_PATHS - T._MAX_NON_AGENT_PATHS]
        kept_servers = [p for p in paths if p.cls is None][:T._MAX_NON_AGENT_PATHS]
        assert len(kept_agents) == len(agent_paths), "every agent finding survives the cap"
        assert len(kept_servers) == T._MAX_NON_AGENT_PATHS, "server origins are bounded, not dropped"

    async def test_a_server_NAMED_like_a_probe_is_not_hidden_as_synthetic(self):
        """`is_synthetic_identity` takes an agent class and a SPIFFE id. Handing it an MCP label means
        a server an operator happens to call `test-kb` vanishes from the console as fabricated
        traffic — a real integration disappearing because of its name."""
        from norviq.api.synthetic import is_synthetic_identity

        assert is_synthetic_identity("e2e-probe", "spiffe://x") is True   # the classifier works
        nodes, edges = _graph()
        nodes["mcp:e2e-probe"] = _node("mcp:e2e-probe", "mcp_server", "e2e-probe", server_id="e2e-probe")
        edges["mcp:e2e-probe"] = [{"target": "tool:read_file", "type": "serves", "hist": {}}]

        paths, _s, _h = await self._derive(nodes, edges)
        kept = [p for p in paths if p.cls is None or not is_synthetic_identity(p.cls, p.src)]
        assert any(p.src == "e2e-probe" for p in kept), "a server is not a probe identity"


class TestThePrescriptionMatchesTheOrigin:
    def test_the_fix_text_does_not_tell_the_operator_to_scope_a_CLASS(self):
        """`recommended_fix` is agent-class-only in all four arms, so the card prescribed an action on
        a class that does not exist — directly contradicting the note beneath it."""
        nodes, edges = _graph()
        p = T._build_path(CHAIN, nodes, edges)
        assert "MCP Servers" in p.fix
        assert "scope" not in p.fix.lower() or "class" not in p.fix.lower()

    def test_an_agent_path_keeps_the_class_scoped_recommendation(self):
        nodes, edges = _graph()
        p = T._build_path(["spiffe://norviq/ns/agents/sa/support", "tool:read_file", "data:pg/customers"],
                          nodes, edges)
        assert "MCP Servers" not in p.fix


class TestTheAgentTrustReadIsAbsentNotFalsy:
    def test_a_FROZEN_agent_reports_0_not_0_point_8(self):
        """`or 0.8` treated a measured 0.0 as missing, so the most distrusted agent in the estate
        reported the same trust as one nobody had scored — on the one input where being wrong about
        trust matters most."""
        nodes, edges = _graph()
        nodes["spiffe://norviq/ns/agents/sa/support"]["props"]["trust_score"] = 0.0
        p = T._build_path(["spiffe://norviq/ns/agents/sa/support", "tool:read_file", "data:pg/customers"],
                          nodes, edges)
        assert p.trust == 0.0

    def test_an_agent_with_NO_score_still_gets_the_documented_default(self):
        nodes, edges = _graph()
        del nodes["spiffe://norviq/ns/agents/sa/support"]["props"]["trust_score"]
        p = T._build_path(["spiffe://norviq/ns/agents/sa/support", "tool:read_file", "data:pg/customers"],
                          nodes, edges)
        assert p.trust == 0.8


class _wrap:
    """Awaitable that yields a fixed value — `_mcp_registry` is awaited, not called."""

    def __init__(self, value): self.value = value
    def __await__(self):
        async def _v(): return self.value
        return _v().__await__()


@pytest.mark.asyncio
class TestTheCapReservationIsDynamic:
    """Bounding the new origin kind must not cost the estates that do not have one."""

    async def _serve(self, monkeypatch, paths):
        async def fake_derive(_s, _ns, _cls, _hours=24, cap=None):
            return list(paths), ["agents"], 0

        monkeypatch.setattr(T, "_derive_paths", fake_derive)
        monkeypatch.setattr(T, "_resolve_namespaces", lambda user, requested: ["agents"])
        monkeypatch.setattr(T, "is_synthetic_identity", lambda cls, src: False)
        return await T.get_threat_paths(ns="agents", namespace=None, cls=None, range="24h",
                                        include_synthetic=False, session=None,
                                        user={"role": "admin", "namespace": "*"})

    def _p(self, i, cls):
        from norviq.api.schemas.threats import ThreatPath
        return ThreatPath(id=f"p{i}", sev="high", src="s", tgt="t", ns="agents",
                          src_kind="agent" if cls else "mcp_server", cls=cls, mitre="", hops=2,
                          blast=1, status="unsimulated", tool="read_file")

    async def test_an_estate_with_NO_mcp_origins_keeps_the_full_budget(self, monkeypatch):
        resp = await self._serve(monkeypatch, [self._p(i, "support-agent") for i in range(400)])
        assert len(resp.paths) == T._MAX_PATHS

    async def test_a_flood_of_mcp_origins_takes_only_its_sub_cap(self, monkeypatch):
        agents = [self._p(i, "support-agent") for i in range(400)]
        servers = [self._p(1000 + i, None) for i in range(400)]
        resp = await self._serve(monkeypatch, agents + servers)
        kept_agents = [p for p in resp.paths if p.cls is not None]
        kept_servers = [p for p in resp.paths if p.cls is None]
        assert len(kept_servers) == T._MAX_NON_AGENT_PATHS
        assert len(kept_agents) == T._MAX_PATHS - T._MAX_NON_AGENT_PATHS
        assert len(resp.paths) == T._MAX_PATHS
        assert resp.total_paths == 800, "the response still states its true size"

    async def test_a_few_mcp_origins_do_not_cost_the_agents_a_full_reservation(self, monkeypatch):
        agents = [self._p(i, "support-agent") for i in range(400)]
        resp = await self._serve(monkeypatch, agents + [self._p(9000, None)])
        assert len([p for p in resp.paths if p.cls is not None]) == T._MAX_PATHS - 1
