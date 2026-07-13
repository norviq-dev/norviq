# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""CAP→POLICY bridge: the rego generator + the generation-time tool-set resolver. The OPA input has no
data-source field, so a capability defense blocks the CONCRETE tools that reach the source with the target
verb (resolved here from the live graph) — these are the pure pieces the /capability/defend endpoint uses."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.api.routers.threats import _tools_reaching_source
from norviq.api.schemas.graphs import AssetEdge, AssetNode
from norviq.api.threat_intent import generate_capability_rego
from norviq.engine.capability import Verb, defense_meta, verb_fragments

_OPA = shutil.which("opa")


def _cap_decision(rego: str, tool_name: str, agent_class: str, normalized: str | None = None) -> str:
    """Run the generated capability rego through the real OPA binary and return the decision."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "cap.rego"
        path.write_text(rego)
        inp = {
            "tool_name": tool_name,
            "tool_name_normalized": normalized if normalized is not None else tool_name,
            "tool_params": {},
            "agent": {"agent_class": agent_class},
        }
        proc = subprocess.run(
            ["opa", "eval", "--v0-compatible", "-d", str(path),
             "-I", "data.norviq.remediation.capability[_].decision"],
            input=json.dumps(inp), capture_output=True, text=True, check=True,
        )
        vals = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
        return vals[0] if isinstance(vals, list) else vals


class TestGenerateCapabilityRego:
    def test_blocks_the_tool_set_for_the_class(self):
        meta = defense_meta("elasticsearch", [Verb.WRITE, Verb.DELETE])
        rego = generate_capability_rego(
            "elasticsearch", "Elasticsearch", "report-gen", meta["verbs"],
            ["index_document", "delete_index"], meta["rule_id"], meta["reason"],
            verb_frags=verb_fragments("elasticsearch", [Verb.WRITE, Verb.DELETE]),
        )
        # class-scoped guard, exact tool set, resolver tail — the tighten-only default-allow shape.
        assert 'input.agent.agent_class == "report-gen"' in rego
        assert '"index_document"' in rego and '"delete_index"' in rego
        assert 'default decision = "allow"' in rego
        assert 'decision = "block" { block_fired }' in rego
        assert f'blocks["{meta["rule_id"]}"]' in rego
        # evasion parity: also matches the confusable skeleton.
        assert "input.tool_name_normalized" in rego
        # forward guard: a verb pattern is emitted.
        assert "cap_verb_pattern" in rego

    def test_empty_tool_set_is_still_a_real_forward_guard(self):
        # CAP-FIX: with no observed tools, the OLD behaviour was a NO-OP (cap_tools := {} and nothing else).
        # Now the verb-pattern forward guard still blocks the verbs — a 'make read-only' defense is real
        # even before any destructive tool is seen.
        meta = defense_meta("postgresql", [Verb.DELETE])
        rego = generate_capability_rego(
            "postgresql", "PostgreSQL", "analytics", meta["verbs"], [], meta["rule_id"], meta["reason"],
            verb_frags=verb_fragments("postgresql", [Verb.DELETE]),
        )
        assert "cap_tools := {}" in rego
        assert "cap_verb_pattern" in rego

    @pytest.mark.skipif(_OPA is None, reason="opa binary required for the capability-rego decision proof")
    def test_forward_guard_blocks_UNOBSERVED_delete_tool(self):
        # The core value fix: block a destructive tool that was NEVER in the observed set.
        meta = defense_meta("postgresql", [Verb.WRITE, Verb.DELETE])
        rego = generate_capability_rego(
            "postgresql", "PostgreSQL", "etl-loader", meta["verbs"], [],  # <-- empty observed set
            meta["rule_id"], meta["reason"], verb_frags=verb_fragments("postgresql", [Verb.WRITE, Verb.DELETE]),
        )
        assert _cap_decision(rego, "delete_record", "etl-loader") == "block"
        assert _cap_decision(rego, "drop_table", "etl-loader") == "block"
        assert _cap_decision(rego, "update_row", "etl-loader") == "block"

    @pytest.mark.skipif(_OPA is None, reason="opa binary required for the capability-rego decision proof")
    def test_never_overblocks_reads_or_other_classes(self):
        meta = defense_meta("postgresql", [Verb.WRITE, Verb.DELETE])
        rego = generate_capability_rego(
            "postgresql", "PostgreSQL", "etl-loader", meta["verbs"], [],
            meta["rule_id"], meta["reason"], verb_frags=verb_fragments("postgresql", [Verb.WRITE, Verb.DELETE]),
        )
        # reads for the class are allowed (read is never a target verb)
        assert _cap_decision(rego, "get_order", "etl-loader") == "allow"
        assert _cap_decision(rego, "search_kb", "etl-loader") == "allow"
        # 'input' contains 'put' but the 'put' write-fragment must not match it at a word boundary
        assert _cap_decision(rego, "compute_input", "etl-loader") == "allow"
        # a different class is untouched even for a destructive tool
        assert _cap_decision(rego, "delete_record", "customer-support") == "allow"


class TestToolsReachingSource:
    def _graph(self):
        # report-gen → {search_kb(read), index_kb(write), delete_kb(delete)} → elasticsearch/knowledge_base
        # customer-support → send_email → smtp (different class, must NOT be pulled in)
        nodes = [
            AssetNode(id="agent:rg", type="agent", name="report-gen", properties={"agent_class": "report-gen"}),
            AssetNode(id="agent:cs", type="agent", name="customer-support", properties={"agent_class": "customer-support"}),
            AssetNode(id="tool:search_kb", type="tool", name="search_kb", properties={}),
            AssetNode(id="tool:index_kb", type="tool", name="index_kb", properties={}),
            AssetNode(id="tool:delete_kb", type="tool", name="delete_kb", properties={}),
            AssetNode(id="tool:send_email", type="tool", name="send_email", properties={}),
            AssetNode(id="data:es", type="data", name="elasticsearch/knowledge_base", properties={}),
            AssetNode(id="data:smtp", type="data", name="smtp/outbound", properties={}),
        ]
        edges = [
            AssetEdge(source="agent:rg", target="tool:search_kb", type="calls", weight=1, properties={}),
            AssetEdge(source="agent:rg", target="tool:index_kb", type="calls", weight=1, properties={}),
            AssetEdge(source="agent:rg", target="tool:delete_kb", type="calls", weight=1, properties={}),
            AssetEdge(source="agent:cs", target="tool:send_email", type="calls", weight=1, properties={}),
            AssetEdge(source="tool:search_kb", target="data:es", type="accesses", weight=1, properties={}),
            AssetEdge(source="tool:index_kb", target="data:es", type="accesses", weight=1, properties={}),
            AssetEdge(source="tool:delete_kb", target="data:es", type="accesses", weight=1, properties={}),
            AssetEdge(source="tool:send_email", target="data:smtp", type="accesses", weight=1, properties={}),
        ]
        return nodes, edges

    def test_resolves_write_delete_tools_for_the_class(self):
        nodes, edges = self._graph()
        tools = _tools_reaching_source(nodes, edges, "elasticsearch", "report-gen", {Verb.WRITE, Verb.DELETE})
        assert tools == ["delete_kb", "index_kb"]  # sorted; read tool search_kb excluded

    def test_read_verb_only_excludes_mutating_tools(self):
        nodes, edges = self._graph()
        assert _tools_reaching_source(nodes, edges, "elasticsearch", "report-gen", {Verb.READ}) == ["search_kb"]

    def test_other_class_tools_not_included(self):
        nodes, edges = self._graph()
        # customer-support's send_email reaches smtp, not elasticsearch, and report-gen doesn't call it.
        assert _tools_reaching_source(nodes, edges, "elasticsearch", "customer-support", {Verb.WRITE, Verb.DELETE}) == []
