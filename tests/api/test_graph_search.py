# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Attack-path namespace scoping + ⌘K search regression (fail-on-bug).

``/threats/attack-paths`` named its scope param ``ns`` while the sibling graph endpoints name it
``namespace`` — so ``?namespace=X`` was SILENTLY ignored and the caller got every namespace's kill-chains.
``namespace`` is an accepted alias; conflicting values are a 400; the ``?ns=`` (empty string) edge is
preserved rather than flipped to "all".

``GET /api/v1/search`` is a bounded, namespace-scoped endpoint backing the ⌘K palette. Tenant isolation
comes from the namespace COLUMN filter, never the substring match; the no-claim floor still 403s.
"""

from __future__ import annotations

from fnmatch import fnmatch
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import agents as agents_router
from norviq.api.routers import search as search_router
from norviq.api.routers import threats as threats_router
from norviq.sdk.core.trust import TrustScore

_ADMIN = {"sub": "admin", "role": "admin", "namespace": "*"}
_VIEWER_DEFAULT = {"sub": "v", "role": "viewer", "namespace": "default"}
_VIEWER_NO_CLAIM = {"sub": "v0", "role": "viewer", "namespace": ""}


class _FakeSession:
    """Returns no DB rows — these tests assert scoping/routing, not row content."""

    async def execute(self, _stmt):
        return SimpleNamespace(all=lambda: [], scalar_one_or_none=lambda: None, scalars=lambda: SimpleNamespace(all=lambda: []))

    async def commit(self) -> None:
        return None

    async def close(self) -> None:
        return None


def _client(user: dict | None = _ADMIN, policies: dict | None = None) -> TestClient:
    app = create_app()

    async def _session():
        yield _FakeSession()

    app.dependency_overrides[get_session] = _session
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.state.loader = SimpleNamespace(_policies=policies or {})
    return TestClient(app)


# --- P2-1: the namespace alias on /threats/attack-paths ------------------------------------------


@pytest.fixture
def captured(monkeypatch) -> list:
    """Capture the namespace list the route hands to _derive_paths (the scoping decision itself)."""
    seen: list = []

    # `cap` is part of the real signature: the route asks for the UNCAPPED list so it can count each
    # class before truncating. A double that silently swallowed it with **kwargs would keep passing if
    # the route stopped passing it, which is the regression that matters — so it is named explicitly.
    # The third element is `non_agent_hidden` — paths excluded by an agent-class filter because their
    # origin is not an agent. Named explicitly for the same reason `cap` is: a double that returned a
    # 2-tuple would fail loudly here rather than letting the route quietly drop the count.
    async def _fake_derive(_session, namespaces, _cls, _hours=24, cap=None):
        seen.append(namespaces)
        return [], [], 0

    monkeypatch.setattr(threats_router, "_derive_paths", _fake_derive)
    return seen


@pytest.fixture
def captured_hours(monkeypatch) -> list:
    """Capture the decision-history WINDOW the route hands to _derive_paths."""
    seen: list = []

    async def _fake_derive(_session, _namespaces, _cls, hours=24, cap=None):
        seen.append(hours)
        return [], [], 0

    monkeypatch.setattr(threats_router, "_derive_paths", _fake_derive)
    return seen


@pytest.mark.parametrize(("range_token", "expected_hours"), [("1h", 1), ("24h", 24), ("7d", 168), ("30d", 720)])
def test_attack_paths_range_reaches_the_decision_window(captured_hours, range_token, expected_hours) -> None:
    """`range` must actually select the decision-history window.

    It used to be discarded into `_` at the route, while `_assemble` hardcoded 24h — each site
    commenting that the OTHER one applied it. So 7d and 30d silently behaved as 24h, and a chain whose
    only decisions were older than a day rendered "unsimulated" despite history inside the asked-for range.
    """
    r = _client().get(f"/api/v1/threats/attack-paths?ns=devops&range={range_token}")
    assert r.status_code == 200
    assert captured_hours == [expected_hours]  # pre-fix: always 24


def test_namespace_alias_is_honored(captured) -> None:
    """?namespace=devops must scope to devops. Pre-fix it was ignored → None (every namespace)."""
    r = _client().get("/api/v1/threats/attack-paths?namespace=devops")
    assert r.status_code == 200
    assert captured == [["devops"]]  # pre-fix: [None] (unrestricted)


def test_ns_still_canonical(captured) -> None:
    r = _client().get("/api/v1/threats/attack-paths?ns=devops")
    assert r.status_code == 200 and captured == [["devops"]]


def test_no_param_is_all(captured) -> None:
    r = _client().get("/api/v1/threats/attack-paths")
    assert r.status_code == 200 and captured == [None]  # admin + "all" => unrestricted


def test_empty_ns_edge_is_preserved(captured) -> None:
    """?ns= (empty) resolves to an EMPTY namespace list → 0 paths. A truthy merge (`ns or namespace or
    "all"`) would flip this to None (EVERY namespace) — reintroducing the very bug P2-1 fixes."""
    r = _client().get("/api/v1/threats/attack-paths?ns=")
    assert r.status_code == 200
    assert captured == [[]]  # empty scope list, NOT None (unrestricted)


def test_conflicting_ns_and_namespace_is_400() -> None:
    """A caller sending both with different values had `namespace` silently dropped. Now it's a 400."""
    r = _client().get("/api/v1/threats/attack-paths?ns=default&namespace=devops")
    assert r.status_code == 400  # pre-fix: 200 with ['default'], namespace silently ignored
    assert "conflicting" in r.json()["detail"]


def test_matching_ns_and_namespace_is_ok(captured) -> None:
    r = _client().get("/api/v1/threats/attack-paths?ns=default&namespace=default")
    assert r.status_code == 200 and captured == [["default"]]


def test_scoped_viewer_cannot_use_alias_to_cross_tenant(captured) -> None:
    """REGRESSION GUARD: the alias must not become a scoping bypass — _resolve_namespaces still rules."""
    r = _client(user=_VIEWER_DEFAULT).get("/api/v1/threats/attack-paths?namespace=devops")
    assert r.status_code == 403  # intentional tightening: pre-fix it silently served the viewer's own ns
    assert captured == []


def test_scoped_viewer_all_is_pinned_to_own_namespace(captured) -> None:
    r = _client(user=_VIEWER_DEFAULT).get("/api/v1/threats/attack-paths?ns=all")
    assert r.status_code == 200 and captured == [["default"]]  # never the whole cluster


def test_no_claim_viewer_floor_holds(captured) -> None:
    r = _client(user=_VIEWER_NO_CLAIM).get("/api/v1/threats/attack-paths?ns=all")
    assert r.status_code == 403 and captured == []  # no-claim floor


# --- P2-2: the scoped /api/v1/search endpoint ----------------------------------------------------


def test_search_exists_and_requires_auth() -> None:
    """Pre-fix the route did not exist at all (404)."""
    app = create_app()

    async def _session():
        yield _FakeSession()

    app.dependency_overrides[get_session] = _session
    app.state.loader = SimpleNamespace(_policies={})
    r = TestClient(app).get("/api/v1/search?q=refund")
    assert r.status_code == 401  # unauthenticated — NOT 404


def test_search_admin_ok_and_q_is_required() -> None:
    c = _client()
    assert c.get("/api/v1/search?q=refund").status_code == 200
    assert c.get("/api/v1/search").status_code == 422  # q required
    assert c.get("/api/v1/search?q=").status_code == 422  # min_length=1
    assert c.get(f"/api/v1/search?q={'x' * 129}").status_code == 422  # max_length=128


def test_search_no_claim_viewer_is_403() -> None:
    assert _client(user=_VIEWER_NO_CLAIM).get("/api/v1/search?q=a").status_code == 403


def test_search_policies_are_namespace_isolated() -> None:
    """A scoped tenant must never see another namespace's policy rows — the ns filter is exact, not substring."""
    policies = {"default:support-bot": {}, "devops:deploy-bot": {}, "default-evil:x": {}}
    rows = search_router._search_policies(
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(loader=SimpleNamespace(_policies=policies)))),
        "bot", "default",
    )
    assert [r["namespace"] for r in rows] == ["default"]  # devops + the "default-evil" prefix are excluded


def test_search_policies_admin_sees_all_and_skips_reserved() -> None:
    policies = {"default:support-bot": {}, "devops:deploy-bot": {}, "default:__baseline__": {}, "__cluster__:x": {}}
    rows = search_router._search_policies(
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(loader=SimpleNamespace(_policies=policies)))),
        "o", None,  # admin: no namespace filter
    )
    classes = {r["agent_class"] for r in rows}
    assert "support-bot" in classes and "deploy-bot" in classes
    assert "__baseline__" not in classes  # managed scopes are not user-facing search hits


def test_search_policies_never_fabricate_an_enforcement_mode() -> None:
    """The loader entry holds only {rego, priority} — inventing a `mode` would mislabel every
    audit/escalate policy in the ⌘K dropdown (no fabricated console data)."""
    policies = {"default:support-bot": {"rego": "package x", "priority": 100}}
    rows = search_router._search_policies(
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(loader=SimpleNamespace(_policies=policies)))),
        "bot", "default",
    )
    assert rows == [{"namespace": "default", "agent_class": "support-bot"}]
    assert "mode" not in rows[0]


def test_search_policies_respects_cap() -> None:
    policies = {f"default:bot-{i}": {} for i in range(20)}
    rows = search_router._search_policies(
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(loader=SimpleNamespace(_policies=policies)))),
        "bot", "default",
    )
    assert len(rows) == search_router._LIMIT


class _AgentRowsSession(_FakeSession):
    """Answers the agent query with registry rows; the tool query (audit_log) with none."""

    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    async def execute(self, stmt):
        is_agents = "agent_registry" in str(stmt)
        return SimpleNamespace(all=lambda: self.rows if is_agents else [])


class _Store:
    """A Redis double over one key/value map, for the agent reads search shares with GET /agents."""

    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.broken = False

    def _client(self) -> "_Store":
        return self

    async def scan_iter(self, match: str):
        for key in list(self.values):
            if fnmatch(key, match):
                yield key

    async def mget(self, keys: list[str]) -> list[str | None]:
        if self.broken and any(k.startswith(("agent_frozen:", "agent_trust_override:")) for k in keys):
            raise ConnectionError("store unavailable")
        return [self.values.get(k) for k in keys]

    async def get_ns_settings(self, _namespace: str) -> dict | None:
        return None


_NS = "spiffe://norviq/ns/payments/sa/"


def _registry_hit(sid: str, score: float, category: str, frozen: bool = False, cap: float | None = None):
    """One agent_registry row as the search query selects it (frozen/trust_cap are the durable copy)."""
    return SimpleNamespace(spiffe_id=_NS + sid, namespace="payments", agent_class=sid, trust_score=score,
                           trust_category=category, last_seen=None, frozen=frozen, trust_cap=cap)


def _search_and_list(monkeypatch, rows: list[SimpleNamespace], store: _Store) -> tuple[dict, dict]:
    """The ⌘K agent hits and the GET /agents rows, from one app over the same registry and store."""
    app = create_app()

    async def _session():
        yield _AgentRowsSession(rows)

    async def _roster(_ns):
        return [{"spiffe_id": r.spiffe_id, "namespace": r.namespace, "agent_class": r.agent_class,
                 "last_seen": None, "score": r.trust_score, "category": r.trust_category.lower(),
                 "violation_count": 0, "signals": {}, "dominant_signal": "", "recommendation": "",
                 "synthetic": False, "frozen": r.frozen, "trust_cap": r.trust_cap} for r in rows]

    async def _last_seen(_ns):
        return {}

    monkeypatch.setattr(agents_router, "_agents_from_registry", _roster)
    monkeypatch.setattr(agents_router, "_registry_last_seen", _last_seen)
    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_current_user] = lambda: _ADMIN
    app.state.loader = SimpleNamespace(_policies={})
    app.state.cache = store
    client = TestClient(app)
    found = client.get("/api/v1/search?q=a")
    listed = client.get("/api/v1/agents?namespace=payments")
    assert found.status_code == 200 and listed.status_code == 200, (found.text, listed.text)
    return ({a["agent_class"]: a for a in found.json()["agents"]},
            {a["agent_class"]: a for a in listed.json()})


def test_search_agents_show_the_freeze_and_cap_the_engine_enforces(monkeypatch) -> None:
    """The ⌘K hits took the freeze and the cap from agent_registry's durable copy and the score from its snapshot,
    while GET /agents (the Agent Monitor) and the engine read both controls from the store and the score from the
    warm trust:<id> row. A freeze only in the store read "not frozen" here, a freeze lifted in the store but not
    yet in the registry read "frozen", and a fresher score was ignored. Every hit now matches /agents."""
    rows = [
        _registry_hit("store-frozen", 0.455, "Medium"),                 # frozen in the store, not (yet) the registry
        _registry_hit("store-lifted", 0.455, "Medium", frozen=True),    # the registry's copy is stale
        _registry_hit("store-capped", 0.9, "High"),                     # the cap only in the store
        _registry_hit("lifted", 0.0, "Frozen"),                         # a frozen snapshot, freeze since lifted
        _registry_hit("warm", 0.82, "High"),                            # a fresher score in trust:<id>
        _registry_hit("cap-above", 0.455, "Medium", cap=0.8),
    ]
    store = _Store({
        f"agent_frozen:{_NS}store-frozen": "1",
        f"agent_trust_override:{_NS}store-capped": "0.5",
        f"agent_trust_override:{_NS}cap-above": "0.8",
        f"trust:{_NS}warm": TrustScore(score=0.61, category="Medium").model_dump_json(),
    })
    found, listed = _search_and_list(monkeypatch, rows, store)
    shown = {k: (a["trust_score"], a["frozen"], a["trust_cap"], a["controls"]) for k, a in found.items()}
    assert shown == {
        "store-frozen": (0.0, True, None, "live"),
        "store-lifted": (0.455, False, None, "live"),
        "store-capped": (0.5, False, 0.5, "live"),
        "lifted": (None, False, None, "live"),
        "warm": (0.61, False, None, "live"),
        "cap-above": (0.455, False, 0.8, "live"),
    }
    for name, hit in found.items():
        row = listed[name]
        assert (hit["trust_score"], hit["category"], hit["frozen"], hit["trust_cap"]) == (
            row["score"], row["category"], row["frozen"], row["trust_cap"]), name


def test_search_agents_say_the_freeze_is_unknown_when_the_store_cannot_be_read(monkeypatch) -> None:
    """The engine blocks every call while it cannot read the store; a "not frozen" from the registry copy here
    contradicted it."""
    rows = [_registry_hit("never-frozen", 0.455, "Medium"), _registry_hit("frozen", 0.455, "Medium", frozen=True)]
    store = _Store({})
    store.broken = True
    found, _ = _search_and_list(monkeypatch, rows, store)
    for hit in found.values():
        assert (hit["frozen"], hit["trust_cap"], hit["trust_score"], hit["category"], hit["controls"]) == (
            None, None, None, "unknown", "unavailable")
