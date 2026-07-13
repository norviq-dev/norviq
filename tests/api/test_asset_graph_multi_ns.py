# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Multi-namespace Asset Graph: /asset-graph namespace="all"/comma-list union + caller scoping + the
"deployed, awaiting first tool call" state.

Covers: the namespace resolver (admin/service unrestricted, viewer pinned to its claim, cross-tenant
403, F-06 no-claim floor), the union response (per-namespace tagging, id qualification so tool ids
don't collide, namespaces field), awaiting-agent synthesis (silent namespaces + deployed-but-silent
classes, reserved __baseline__/__pack__ scopes excluded), and unchanged single-namespace shape.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import graphs as graphs_mod

ADMIN = {"sub": "root", "role": "admin", "namespace": ""}
VIEWER_A = {"sub": "alice", "role": "viewer", "namespace": "team-a"}


def _snapshot(ns: str, agent: str, klass: str, tool: str) -> dict:
    """A minimal builder-shaped graph_json: one agent calling one tool."""
    return {
        "nodes": [
            {"id": agent, "type": "agent", "label": klass, "namespace": ns,
             "properties": {"agent_class": klass, "trust_score": 0.9}},
            {"id": f"tool:{tool}", "type": "tool", "label": tool, "namespace": ns,
             "properties": {"risk_level": "low"}},
        ],
        "edges": [
            {"source": agent, "target": f"tool:{tool}", "type": "calls", "weight": 2.0, "properties": {}},
        ],
    }


@pytest.fixture
def stubbed(monkeypatch):
    """Patch the graphs data helpers; returns a dict the test mutates + a capture of resolved scopes."""
    state = {"snapshots": [], "deployed": {}, "counts": {}, "asked_namespaces": []}

    async def _snap(_s, namespaces):
        state["asked_namespaces"].append(namespaces)
        if namespaces is None:
            return state["snapshots"]
        return [(ns, g) for ns, g in state["snapshots"] if ns in namespaces]

    async def _dep(_s, namespaces):
        if namespaces is None:
            return state["deployed"]
        return {ns: cl for ns, cl in state["deployed"].items() if ns in namespaces}

    async def _counts(_s, ns, _since):
        return state["counts"].get(ns, {})

    monkeypatch.setattr(graphs_mod, "_latest_snapshots", _snap)
    monkeypatch.setattr(graphs_mod, "_deployed_classes", _dep)
    monkeypatch.setattr(graphs_mod, "_decision_counts", _counts)
    return state


def _get(user: dict, query: str):
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: user

    async def _session():
        yield SimpleNamespace()

    app.dependency_overrides[get_session] = _session
    # No context manager: entering it runs the lifespan (real DB/Redis connects) — repo convention.
    client = TestClient(app)
    try:
        return client.get(f"/api/v1/asset-graph?{query}")
    finally:
        client.close()


# --- _resolve_namespaces (scoping) ---------------------------------------------------------------


def test_admin_all_is_unrestricted_and_list_passes_through() -> None:
    assert graphs_mod._resolve_namespaces(ADMIN, "all") is None
    assert graphs_mod._resolve_namespaces(ADMIN, "a,b") == ["a", "b"]
    assert graphs_mod._resolve_namespaces({"role": "viewer", "namespace": "*"}, "all") is None
    assert graphs_mod._resolve_namespaces({"role": "service", "namespace": ""}, "all") is None


def test_viewer_all_resolves_to_own_namespace_only() -> None:
    assert graphs_mod._resolve_namespaces(VIEWER_A, "all") == ["team-a"]
    assert graphs_mod._resolve_namespaces(VIEWER_A, "team-a") == ["team-a"]


@pytest.mark.parametrize("requested", ["team-b", "team-a,team-b", "team-b,team-a"])
def test_viewer_cross_namespace_is_403(requested: str) -> None:
    with pytest.raises(HTTPException) as exc:
        graphs_mod._resolve_namespaces(VIEWER_A, requested)
    assert exc.value.status_code == 403


def test_viewer_without_claim_hits_the_floor() -> None:
    with pytest.raises(HTTPException) as exc:
        graphs_mod._resolve_namespaces({"role": "viewer", "namespace": ""}, "all")
    assert exc.value.status_code == 403


# --- endpoint: union + tagging + awaiting ---------------------------------------------------------


def test_all_unions_namespaces_with_tags_prefixes_and_awaiting(stubbed) -> None:
    stubbed["snapshots"] = [
        ("payments", _snapshot("payments", "spiffe://p/pay", "payments-bot", "execute_sql")),
        ("support", _snapshot("support", "spiffe://s/sup", "support-bot", "search_kb")),
    ]
    # hr has protection deployed but zero traffic (no snapshot) -> awaiting; support also has a second,
    # not-yet-observed class -> awaiting inside a traffic-bearing namespace.
    stubbed["deployed"] = {"hr": {"hr-bot"}, "support": {"support-bot", "escalation-bot"}}
    # A2: awaiting (real-but-never-observed) agents are hidden by default — opt back in to exercise them.
    resp = _get(ADMIN, "namespace=all&include_awaiting=true")
    assert resp.status_code == 200
    body = resp.json()
    assert body["namespaces"] == ["hr", "payments", "support"]
    by_id = {n["id"]: n for n in body["nodes"]}
    # union ids are namespace-qualified; every node tagged with its namespace
    assert "payments::spiffe://p/pay" in by_id and "support::spiffe://s/sup" in by_id
    assert by_id["payments::tool:execute_sql"]["properties"]["namespace"] == "payments"
    # awaiting nodes: silent namespace (hr) + silent class in a live namespace (escalation-bot)
    hr = by_id["hr::awaiting:hr-bot"]
    assert hr["type"] == "agent" and hr["properties"]["awaiting"] is True
    assert by_id["support::awaiting:escalation-bot"]["properties"]["awaiting"] is True
    # the OBSERVED class is not duplicated as awaiting
    assert "support::awaiting:support-bot" not in by_id
    # edges are qualified consistently with their nodes
    edge = next(e for e in body["edges"] if e["source"] == "payments::spiffe://p/pay")
    assert edge["target"] == "payments::tool:execute_sql"


def test_colliding_tool_ids_stay_distinct_across_namespaces(stubbed) -> None:
    stubbed["snapshots"] = [
        ("a", _snapshot("a", "spiffe://a/bot", "bot-a", "search_kb")),
        ("b", _snapshot("b", "spiffe://b/bot", "bot-b", "search_kb")),
    ]
    body = _get(ADMIN, "namespace=all").json()
    tool_ids = [n["id"] for n in body["nodes"] if n["type"] == "tool"]
    assert sorted(tool_ids) == ["a::tool:search_kb", "b::tool:search_kb"]


def test_single_namespace_keeps_unprefixed_shape(stubbed) -> None:
    stubbed["snapshots"] = [("payments", _snapshot("payments", "spiffe://p/pay", "payments-bot", "execute_sql"))]
    stubbed["deployed"] = {"payments": {"payments-bot", "risk-bot"}}
    # A2: awaiting agents are hidden by default — opt back in to exercise the single-namespace shape too.
    body = _get(ADMIN, "namespace=payments&include_awaiting=true").json()
    ids = {n["id"] for n in body["nodes"]}
    assert "spiffe://p/pay" in ids and "tool:execute_sql" in ids  # no ns:: prefix
    assert "awaiting:risk-bot" in ids  # awaiting rendered in single view too
    assert body["namespaces"] == ["payments"]
    # nodes still carry the namespace tag for the UI
    assert all(n["properties"]["namespace"] == "payments" for n in body["nodes"])


def test_edge_decision_history_uses_batched_counts(stubbed) -> None:
    stubbed["snapshots"] = [("payments", _snapshot("payments", "spiffe://p/pay", "payments-bot", "execute_sql"))]
    stubbed["counts"] = {"payments": {("spiffe://p/pay", "execute_sql"): {"allow": 5, "block": 2, "escalate": 1}}}
    body = _get(ADMIN, "namespace=payments").json()
    dh = body["edges"][0]["properties"]["decision_history"]
    assert dh == {"allow": 5, "block": 2, "escalate": 1}


def test_viewer_all_gets_only_its_namespace(stubbed) -> None:
    stubbed["snapshots"] = [
        ("team-a", _snapshot("team-a", "spiffe://a/bot", "bot-a", "search_kb")),
        ("team-b", _snapshot("team-b", "spiffe://b/bot", "bot-b", "execute_sql")),
    ]
    body = _get(VIEWER_A, "namespace=all").json()
    assert body["namespaces"] == ["team-a"]
    assert all(n["properties"]["namespace"] == "team-a" for n in body["nodes"])
    # the resolver narrowed the query itself (defense at the data layer, not post-filtering)
    assert stubbed["asked_namespaces"][-1] == ["team-a"]


def test_viewer_cannot_read_another_namespace_via_endpoint(stubbed) -> None:
    stubbed["snapshots"] = [("team-b", _snapshot("team-b", "spiffe://b/bot", "bot-b", "execute_sql"))]
    assert _get(VIEWER_A, "namespace=team-b").status_code == 403
    assert _get(VIEWER_A, "namespace=team-a,team-b").status_code == 403


def test_empty_namespace_still_returns_valid_empty_response(stubbed) -> None:
    body = _get(ADMIN, "namespace=ghost").json()
    # A1/A2: the response now also reports how many synthetic/awaiting nodes were filtered by default
    # (0 here — nothing to hide in an empty namespace) — see norviq/api/routers/graphs.py asset_graph.
    assert body == {"nodes": [], "edges": [], "namespaces": [], "synthetic_hidden": 0, "awaiting_hidden": 0}


# --- _deployed_classes: reserved managed scopes are not "deployed agents" -------------------------


class _Rows:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def mappings(self):
        return SimpleNamespace(all=lambda: self._rows)


class _FakeSession:
    """Returns policy rows for the first query, registry rows for the second."""

    def __init__(self, policy_rows: list[dict], registry_rows: list[dict]) -> None:
        self._batches = [policy_rows, registry_rows]
        self.calls = 0

    async def execute(self, _stmt, _params=None):
        rows = self._batches[min(self.calls, 1)]
        self.calls += 1
        return _Rows(rows)


def _multiclass_snapshot(ns: str, spiffe: str, classes: list[str], tool: str) -> dict:
    """A snapshot where one SPIFFE identity carries several agent_classes (the collapse case)."""
    return {
        "nodes": [
            {"id": spiffe, "type": "agent", "label": classes[0], "namespace": ns,
             "properties": {"agent_class": classes[-1], "agent_classes": classes, "trust_score": 0.9}},
            {"id": f"tool:{tool}", "type": "tool", "label": tool, "namespace": ns, "properties": {}},
        ],
        "edges": [{"source": spiffe, "target": f"tool:{tool}", "type": "calls", "weight": 1.0, "properties": {}}],
    }


def test_multiclass_identity_expands_into_subnodes(stubbed) -> None:
    stubbed["snapshots"] = [
        ("shared", _multiclass_snapshot("shared", "spiffe://s/svc", ["support-bot", "payments-bot"], "search_kb")),
    ]
    body = _get(ADMIN, "namespace=shared").json()
    by_id = {n["id"]: n for n in body["nodes"]}
    # a shared identity node + one distinguishable sub-node per class (keyed (spiffe, class))
    assert by_id["spiffe://s/svc"]["properties"]["is_identity"] is True
    assert by_id["spiffe://s/svc#support-bot"]["properties"]["agent_class"] == "support-bot"
    assert by_id["spiffe://s/svc#payments-bot"]["properties"]["agent_class"] == "payments-bot"
    # each sub-node belongs_to the identity (structural, not a fabricated call edge)
    belongs = [(e["source"], e["target"]) for e in body["edges"] if e["type"] == "belongs_to"]
    assert ("spiffe://s/svc#support-bot", "spiffe://s/svc") in belongs
    assert ("spiffe://s/svc#payments-bot", "spiffe://s/svc") in belongs
    # both classes surface for the agent-class filter
    assert {n["properties"].get("agent_class") for n in body["nodes"] if n["type"] == "agent"} >= {
        "support-bot",
        "payments-bot",
    }


def test_single_class_identity_is_not_expanded(stubbed) -> None:
    stubbed["snapshots"] = [("solo", _multiclass_snapshot("solo", "spiffe://s/one", ["only-bot"], "search_kb"))]
    body = _get(ADMIN, "namespace=solo").json()
    ids = {n["id"] for n in body["nodes"]}
    assert "spiffe://s/one" in ids and "spiffe://s/one#only-bot" not in ids  # no sub-node split
    assert not any(e["type"] == "belongs_to" for e in body["edges"])


@pytest.mark.asyncio
async def test_deployed_classes_excludes_reserved_scopes() -> None:
    session = _FakeSession(
        policy_rows=[
            {"namespace": "hr", "agent_class": "hr-bot"},
            {"namespace": "hr", "agent_class": "__baseline__"},      # managed baseline row
            {"namespace": "hr", "agent_class": "__pack__"},          # sector-pack overlay row
            {"namespace": "hr", "agent_class": "namespace:hr"},      # namespace-target row
            {"namespace": "__cluster__", "agent_class": "any"},      # cluster baseline scope
            {"namespace": "all", "agent_class": "wildcard-bot"},     # wildcard sentinel ns
        ],
        registry_rows=[{"namespace": "support", "agent_class": "support-bot"}],
    )
    deployed = await graphs_mod._deployed_classes(session, None)
    assert deployed == {"hr": {"hr-bot"}, "support": {"support-bot"}}
