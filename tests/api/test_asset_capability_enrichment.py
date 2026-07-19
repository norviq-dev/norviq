# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""The asset-graph capability enrichment attributes a tool's OBSERVED/DEFENDED signal from its
agent→tool ``calls`` edge (which carries decision history), not the tool→data ``accesses`` edge (which
carries none). A live-verification regression: reading the zero-count accesses edge made every verb look
'dormant/latent' even for actively-used tools."""

from norviq.api.routers.graphs import _attach_source_capability
from norviq.api.schemas.graphs import AssetEdge, AssetNode


def _graph(calls_hist):
    """agent → search_kb → elasticsearch/knowledge_base; the read traffic lives on the CALLS edge."""
    nodes = [
        AssetNode(id="agent:rg", type="agent", name="report-gen", properties={"namespace": "analytics"}),
        AssetNode(id="tool:search_kb", type="tool", name="search_kb", properties={"risk_level": "low"}),
        AssetNode(id="data:elasticsearch/knowledge_base", type="data", name="elasticsearch/knowledge_base", properties={}),
    ]
    edges = [
        AssetEdge(source="agent:rg", target="tool:search_kb", type="calls", weight=1.0,
                  properties={"decision_history": calls_hist}),
        # accesses edge intentionally carries NO decision history (mirrors the real snapshot).
        AssetEdge(source="tool:search_kb", target="data:elasticsearch/knowledge_base", type="accesses",
                  weight=1.0, properties={}),
    ]
    return nodes, edges


def _es_cap(nodes):
    data = next(n for n in nodes if n.type == "data")
    return data.properties.get("capability")


def _read(cap):
    return next(f for f in cap["findings"] if f["verb"] == "read")


def test_active_read_is_observed_not_dormant():
    # 24 allowed search_kb calls → READ is observed + undefended (a live read gap), NOT dormant.
    nodes, edges = _graph({"allow": 24, "block": 0, "escalate": 0})
    _attach_source_capability(nodes, edges)
    cap = _es_cap(nodes)
    assert cap is not None
    read = _read(cap)
    assert read["observed"] is True
    assert read["status"] == "undefended"


def test_guarded_read_is_defended():
    # a blocked search_kb call means a rule acted → READ is defended.
    nodes, edges = _graph({"allow": 10, "block": 3, "escalate": 0})
    _attach_source_capability(nodes, edges)
    read = _read(_es_cap(nodes))
    assert read["defended"] is True
    assert read["status"] == "defended"


def test_silent_tool_grant_is_dormant():
    # the tool reaches ES but never produced traffic → dormant grant (least-privilege gap).
    nodes, edges = _graph({"allow": 0, "block": 0, "escalate": 0})
    _attach_source_capability(nodes, edges)
    read = _read(_es_cap(nodes))
    assert read["observed"] is False
    assert read["status"] == "dormant_grant"


def test_accesses_edge_is_verb_tagged():
    nodes, edges = _graph({"allow": 5, "block": 0, "escalate": 0})
    _attach_source_capability(nodes, edges)
    access = next(e for e in edges if e.type == "accesses")
    assert access.properties.get("verb") == "read"


def test_unknown_source_left_untouched():
    nodes = [AssetNode(id="data:mysql/x", type="data", name="mysql/x", properties={})]
    _attach_source_capability(nodes, [])
    assert "capability" not in nodes[0].properties
