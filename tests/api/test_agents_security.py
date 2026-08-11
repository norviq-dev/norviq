# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SECURITY regressions for the agents router:

1. GET /agents/{spiffe} must mirror list_agents' namespace scoping — a scoped tenant may not read a
   namespaceless (or other-ns) agent that the list route hides (cross-tenant IDOR).
2. DELETE /agents/{spiffe} is a cluster-scoped WRITE and must carry the same X-Nrvq-Target-Cluster
   guard (require_target_cluster) that PUT /agents/{spiffe}/trust has — a delete aimed at another
   cluster must be refused (409), never silently land on this deployment's cluster.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings
from norviq.sdk.core.trust import TrustScore

# ns/team-a/sa/... encodes namespace "team-a"; the orphan has no /ns/ segment => namespaceless.
NS_AGENT = "spiffe://norviq/ns/team-a/sa/planner"
OTHER_NS_AGENT = "spiffe://norviq/ns/team-b/sa/planner"
ORPHAN_AGENT = "spiffe://norviq/sa/planner"


class _TrustCache:
    """Minimal cache double: get_trust + _client().get() for _trust_details."""

    def __init__(self, trusted: set[str]) -> None:
        self._trusted = trusted

    def _client(self) -> "_TrustCache":
        return self

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        if spiffe_id in self._trusted:
            return TrustScore(score=0.9, category="trusted")
        return None

    async def get(self, _key: str) -> str | None:
        return None  # no trustcalc:* payload => _trust_details falls back to factors


def _client(trusted: set[str]) -> TestClient:
    app = create_app()
    app.state.cache = _TrustCache(trusted)
    return app, TestClient(app)


def _token(role: str = "admin", namespace: str | None = None) -> str:
    claims: dict[str, object] = {"sub": "u", "role": role, "exp": int(time.time()) + 3600}
    if namespace is not None:
        claims["namespace"] = namespace
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _hdr(role: str = "admin", namespace: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(role, namespace)}"}


# --- get_agent namespace scoping -----------------------------------------------------------------


def test_scoped_tenant_cannot_read_namespaceless_agent() -> None:
    """FAIL-ON-BUG: a viewer scoped to team-a reading a namespaceless agent must get 404 —
    list_agents hides it, but get_agent must also compare the resolved scope."""
    _, client = _client({ORPHAN_AGENT})
    resp = client.get(f"/api/v1/agents/{ORPHAN_AGENT}", headers=_hdr(role="viewer", namespace="team-a"))
    assert resp.status_code == 404


def test_scoped_tenant_cannot_read_other_namespace_agent() -> None:
    """A team-a viewer must not read a team-b agent's trust signals."""
    _, client = _client({OTHER_NS_AGENT})
    resp = client.get(f"/api/v1/agents/{OTHER_NS_AGENT}", headers=_hdr(role="viewer", namespace="team-a"))
    assert resp.status_code == 404


def test_scoped_tenant_reads_own_namespace_agent() -> None:
    """The legitimate case still works: a team-a viewer reads a team-a agent."""
    _, client = _client({NS_AGENT})
    resp = client.get(f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="viewer", namespace="team-a"))
    assert resp.status_code == 200
    assert resp.json()["spiffe_id"] == NS_AGENT


def test_admin_reads_namespaceless_agent() -> None:
    """Admin (no namespace filter) still reads any agent, namespaceless included."""
    _, client = _client({ORPHAN_AGENT})
    resp = client.get(f"/api/v1/agents/{ORPHAN_AGENT}", headers=_hdr(role="admin"))
    assert resp.status_code == 200


# --- deregister_agent cluster-mutation guard -----------------------------------------------------


def _session_override(app, row):
    class _FakeSession:
        async def execute(self, _stmt):
            return SimpleNamespace(scalar_one_or_none=lambda: row)

        async def delete(self, _row) -> None:
            return None

        async def commit(self) -> None:
            return None

    async def _override():
        yield _FakeSession()

    app.dependency_overrides[get_session] = _override


def test_deregister_rejects_foreign_target_cluster() -> None:
    """FAIL-ON-BUG: DELETE with a mismatched X-Nrvq-Target-Cluster must 409 (require_target_cluster).
    Before the fix the guard was absent, so the delete proceeded to the registry (404 here). served
    cluster defaults to 'local' (fleet_cluster_id unset), so 'cluster-b' never matches."""
    app, client = _client(set())
    _session_override(app, SimpleNamespace(spiffe_id=NS_AGENT, namespace="team-a"))  # row exists => old code would 200, not 409
    resp = client.request(
        "DELETE",
        f"/api/v1/agents/{NS_AGENT}",
        headers={**_hdr(role="admin"), "X-Nrvq-Target-Cluster": "cluster-b"},
    )
    assert resp.status_code == 409


def test_deregister_local_intent_still_works() -> None:
    """No target header (local intent) => the guard is a no-op and the delete proceeds."""
    app, client = _client(set())
    _session_override(app, SimpleNamespace(spiffe_id=NS_AGENT, namespace="team-a"))
    resp = client.request("DELETE", f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted"] is True and body["spiffe_id"] == NS_AGENT
    # No evaluator on app.state here, so there is no graph to prune — and the response must SAY so
    # rather than implying the console is now clean.
    assert body["graph_node_removed"] is False


# --- Cold-cache parity: get_agent falls back to the persistent registry (mirrors list_agents) --------


def _patch_registry(monkeypatch, result):
    """Stub agents._agent_from_registry (it calls get_session() directly, not via Depends)."""
    async def _fake(spiffe_id):
        return None if result is None else {**result, "spiffe_id": spiffe_id}
    import norviq.api.routers.agents as agents_mod
    monkeypatch.setattr(agents_mod, "_agent_from_registry", _fake)


def test_get_agent_cold_cache_falls_back_to_registry(monkeypatch) -> None:
    """FAIL-ON-BUG: an agent whose hot trust:* entry has expired (get_trust None) but which is still in
    the registry must return 200 from the registry snapshot — not 404. Before the fix get_agent read
    only the hot cache, so a listed agent's detail view 404'd once its TTL lapsed."""
    _, client = _client(set())  # empty trusted set => get_trust returns None (cold cache)
    _patch_registry(monkeypatch, {"score": 0.72, "category": "medium", "violation_count": 3,
                                  "signals": {}, "dominant_signal": "", "recommendation": ""})
    resp = client.get(f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))
    assert resp.status_code == 200
    assert resp.json()["score"] == 0.72
    assert resp.json()["violation_count"] == 3


def test_get_agent_cold_cache_fallback_stays_scope_gated(monkeypatch) -> None:
    """The registry fallback must NOT weaken the IDOR guard: a team-a viewer reading a team-b agent is
    404 even though the registry has it — the scope check short-circuits before the fallback runs."""
    _, client = _client(set())
    _patch_registry(monkeypatch, {"score": 0.9, "category": "high", "violation_count": 0,
                                  "signals": {}, "dominant_signal": "", "recommendation": ""})
    resp = client.get(f"/api/v1/agents/{OTHER_NS_AGENT}", headers=_hdr(role="viewer", namespace="team-a"))
    assert resp.status_code == 404


def test_get_agent_absent_from_cache_and_registry_is_404(monkeypatch) -> None:
    """Genuine not-found: cold cache AND no registry row => 404 (fallback returns None)."""
    _, client = _client(set())
    _patch_registry(monkeypatch, None)
    resp = client.get(f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))
    assert resp.status_code == 404


# --- deregister must also take the agent OFF the asset graph --------------------------------------
#
# get_asset_graph serves the union of a persisted asset_graph snapshot and the classes that are merely
# deployed (registry/policy). Deleting the registry row alone therefore only removed agents that had
# NEVER been observed; one that had actually run kept its snapshot node and stayed on the console,
# while the response still said {"deleted": true}. That is the case that matters — an agent worth
# decommissioning is usually one that ran. Observed live on kind: DELETE returned 200 and the agent
# was still in GET /asset-graph afterwards.


class _FakeGraph:
    def __init__(self, nodes: set[str]) -> None:
        self._nodes = set(nodes)
        self.graph = SimpleNamespace(number_of_nodes=lambda: len(self._nodes), number_of_edges=lambda: 0)

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            return False
        self._nodes.discard(node_id)
        return True


class _FakeEvaluator:
    def __init__(self, graph: _FakeGraph) -> None:
        self._graph = graph
        self.restored: list[str] = []

    async def _restore_graph(self, namespace: str) -> None:
        self.restored.append(namespace)

    def get_graph(self, _namespace: str) -> _FakeGraph:
        return self._graph


class _FakeStore:
    def __init__(self) -> None:
        self.saved: list[str] = []

    async def save(self, namespace: str, _graph) -> None:
        self.saved.append(namespace)


def test_deregister_removes_the_agents_node_from_the_asset_graph() -> None:
    """FAIL-ON-BUG: an OBSERVED agent (node baked into the snapshot) must leave the graph too.

    Before the fix this asserted nothing about the graph, the node survived the delete, and the
    console kept rendering a decommissioned identity.
    """
    app, client = _client(set())
    graph = _FakeGraph({NS_AGENT})
    evaluator = _FakeEvaluator(graph)
    store = _FakeStore()
    app.state.evaluator = evaluator
    app.state.graph_store = store
    _session_override(app, SimpleNamespace(spiffe_id=NS_AGENT, namespace="team-a"))

    resp = client.request("DELETE", f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))

    assert resp.status_code == 200
    assert resp.json()["graph_node_removed"] is True
    assert graph.remove_node(NS_AGENT) is False, "the node must be gone from the live builder"
    # The snapshot has to be rewritten, or the node returns on the next read of the persisted graph.
    assert store.saved == ["team-a"], "the pruned graph was never saved back"
    # And the namespace's persisted snapshot must be restored FIRST, or a pod that has not yet touched
    # this namespace prunes an empty in-memory graph and saves that over a populated snapshot.
    assert evaluator.restored == ["team-a"]


def test_deregister_reports_false_when_the_agent_had_no_graph_node() -> None:
    """A never-observed agent has no snapshot node. That is not a failure — but it must not be
    reported as a graph removal either, or `graph_node_removed` stops meaning anything."""
    app, client = _client(set())
    app.state.evaluator = _FakeEvaluator(_FakeGraph(set()))
    app.state.graph_store = _FakeStore()
    _session_override(app, SimpleNamespace(spiffe_id=NS_AGENT, namespace="team-a"))

    resp = client.request("DELETE", f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))

    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert resp.json()["graph_node_removed"] is False


def test_deregister_still_succeeds_when_the_graph_prune_raises() -> None:
    """The registry row is committed before the prune. If the prune explodes there is nothing to roll
    back, so the delete must still report success — and must NOT claim the graph node went with it."""
    class _Exploding(_FakeEvaluator):
        async def _restore_graph(self, namespace: str) -> None:
            raise RuntimeError("graph store unreachable")

    app, client = _client(set())
    app.state.evaluator = _Exploding(_FakeGraph({NS_AGENT}))
    app.state.graph_store = _FakeStore()
    _session_override(app, SimpleNamespace(spiffe_id=NS_AGENT, namespace="team-a"))

    resp = client.request("DELETE", f"/api/v1/agents/{NS_AGENT}", headers=_hdr(role="admin"))

    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert resp.json()["graph_node_removed"] is False
