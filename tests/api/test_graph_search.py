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

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import search as search_router
from norviq.api.routers import threats as threats_router

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

    async def _fake_derive(_session, namespaces, _cls):
        seen.append(namespaces)
        return [], []

    monkeypatch.setattr(threats_router, "_derive_paths", _fake_derive)
    return seen


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
    audit/escalate policy in the ⌘K dropdown (F046: no fabricated console data)."""
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
