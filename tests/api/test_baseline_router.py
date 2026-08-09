# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""GET /baseline/controls + admin-only PUT.

Covers the catalog (defaults and stored deviations), that a PUT materializes a recompiled baseline
through the loader, non-admin 403, bad input 422 with nothing written, and the two storage decisions
that are easy to get wrong: only deviations are persisted, and the materialized policy stays in
`block` mode so `deny` remains reachable.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api import baseline as baseline_lib
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """In-memory NamespaceBaselineControl store, filtered by the statement's bound namespace."""

    def __init__(self, rows: list | None = None) -> None:
        self.rows = list(rows or [])
        self.added: list = []
        self.committed = False
        self.deleted_for: list[str] = []

    async def execute(self, stmt):
        sql = str(stmt)
        try:
            params = stmt.compile().params
        except Exception:
            params = {}
        ns = params.get("namespace_1")
        if sql.strip().upper().startswith("DELETE"):
            self.deleted_for.append(ns)
            self.rows = [r for r in self.rows if r.namespace != ns]
            return SimpleNamespace(rowcount=1)
        matched = [r for r in self.rows if r.namespace == ns] if "namespace_baseline_controls" in sql else []
        # The route is not the only thing that queries: `assert_apply_allowed` (the shared dry-run-only
        # gate) also reads settings off this session and calls scalar_one_or_none(). Answer every shape
        # rather than just the one this router uses, or the test fails inside a dependency and the
        # failure looks like a bug in the code under test.
        return SimpleNamespace(
            all=lambda: matched,
            scalar_one_or_none=lambda: None,   # no dry-run-only override for this namespace
            scalars=lambda: SimpleNamespace(all=lambda: []),
        )

    def add(self, row) -> None:
        self.rows.append(row)
        self.added.append(row)

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:
        return None


class _FakeLoader:
    def __init__(self) -> None:
        self.created: list = []
        self._cache = None

    async def create(self, ns, agent_class, rego, **kw):
        self.created.append({"ns": ns, "agent_class": agent_class, "rego": rego, **kw})
        return 1

    async def delete(self, ns, agent_class):
        return True


def _client(rows: list | None = None) -> tuple[TestClient, _FakeSession, _FakeLoader]:
    app = create_app()
    session = _FakeSession(rows)
    loader = _FakeLoader()
    app.state.loader = loader

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app), session, loader


def _h(role: str = "admin", namespace: str = "default") -> dict:
    token = jwt.encode(
        {"sub": "u", "role": role, "namespace": namespace, "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _row(control_id: str, effect: str, namespace: str = "default"):
    return SimpleNamespace(namespace=namespace, control_id=control_id, effect=effect)


# --- catalog ---------------------------------------------------------------------------------------

def test_catalog_lists_every_control_at_the_default() -> None:
    client, _, _ = _client(rows=[])
    body = client.get("/api/v1/baseline/controls?namespace=default", headers=_h()).json()
    ids = {c["id"] for c in body["controls"]}
    assert {"deny_shell_execution", "pii_detection", "strict_default_block"} <= ids
    assert all(c["effect"] == "monitor" for c in body["controls"]), "fresh namespace must drop nothing"
    assert body["default_effect"] == "monitor"
    assert body["counts"]["monitor"] == len(body["controls"])


def test_catalog_surfaces_the_false_positive_caveat() -> None:
    """The operator needs the cost of promotion at the moment they are deciding to promote."""
    client, _, _ = _client(rows=[])
    body = client.get("/api/v1/baseline/controls", headers=_h()).json()
    shell = next(c for c in body["controls"] if c["id"] == "deny_shell_execution")
    assert "1 in 8" in shell["caveat"]


def test_catalog_reflects_stored_deviations() -> None:
    client, _, _ = _client(rows=[_row("deny_shell_execution", "off"), _row("pii_detection", "deny")])
    body = client.get("/api/v1/baseline/controls", headers=_h()).json()
    by_id = {c["id"]: c["effect"] for c in body["controls"]}
    assert by_id["deny_shell_execution"] == "off"
    assert by_id["pii_detection"] == "deny"
    assert by_id["llm01_prompt_injection"] == "monitor"  # untouched, still default


# --- writes ----------------------------------------------------------------------------------------

def test_put_materializes_a_recompiled_baseline() -> None:
    client, _, loader = _client(rows=[])
    resp = client.put(
        "/api/v1/baseline/controls",
        json={"namespace": "default", "effects": {"deny_sql_injection": "deny"}},
        headers=_h(),
    )
    assert resp.status_code == 200
    assert resp.json()["enforcing"] == ["deny_sql_injection"]
    assert len(loader.created) == 1
    written = loader.created[0]
    assert written["ns"] == "default"
    assert written["agent_class"] == "__baseline__"
    assert 'blocks["deny_sql_injection"]' in written["rego"]
    # everything else stayed at monitor -> registered as audits, not blocks
    assert 'audits["llm01_prompt_injection"]' in written["rego"]


def test_the_materialized_policy_stays_in_block_mode() -> None:
    """The trap. Each control's effect lives in the MODULE, so the policy must not also be softened.

    If the policy were written with enforcement_mode="audit", `_apply_policy_mode` would soften every
    block the module produced and `deny` would become unreachable — three effects collapsing into two,
    with the console still cheerfully showing "deny".
    """
    client, _, loader = _client(rows=[])
    client.put(
        "/api/v1/baseline/controls",
        json={"effects": {cid: "deny" for cid in baseline_lib.control_ids("strict")}},
        headers=_h(),
    )
    assert loader.created[0]["enforcement_mode"] == "block"


def test_only_deviations_are_persisted() -> None:
    """A namespace at the default keeps zero rows, so a future release's changed default reaches it."""
    client, session, _ = _client(rows=[])
    client.put(
        "/api/v1/baseline/controls",
        json={"effects": {"pii_detection": "deny", "llm01_prompt_injection": "monitor"}},
        headers=_h(),
    )
    stored = {r.control_id: r.effect for r in session.added}
    assert stored == {"pii_detection": "deny"}, "a control left at the default must not be written"


def test_put_replaces_rather_than_merges() -> None:
    """Setting a control back to the default must clear its stored row, not leave the old value."""
    client, session, _ = _client(rows=[_row("deny_shell_execution", "off")])
    client.put("/api/v1/baseline/controls", json={"effects": {}}, headers=_h())
    assert "default" in session.deleted_for
    assert session.added == [], "everything is back at the default, so nothing should be stored"


# --- refusals --------------------------------------------------------------------------------------

def test_non_admin_cannot_change_controls() -> None:
    client, session, loader = _client(rows=[])
    resp = client.put(
        "/api/v1/baseline/controls", json={"effects": {"pii_detection": "deny"}}, headers=_h(role="viewer")
    )
    assert resp.status_code == 403
    assert loader.created == [] and session.added == []


def test_unknown_control_is_422_and_writes_nothing() -> None:
    """Validated before the delete, so a bad request cannot leave the namespace half-updated."""
    client, session, loader = _client(rows=[_row("pii_detection", "deny")])
    resp = client.put(
        "/api/v1/baseline/controls", json={"effects": {"no_such_control": "deny"}}, headers=_h()
    )
    assert resp.status_code == 422
    assert "unknown control" in resp.json()["detail"]
    assert session.deleted_for == [], "the existing rows must survive a rejected request"
    assert loader.created == []


def test_invalid_effect_is_422() -> None:
    client, _, loader = _client(rows=[])
    resp = client.put(
        "/api/v1/baseline/controls", json={"effects": {"pii_detection": "audit"}}, headers=_h()
    )
    assert resp.status_code == 422
    assert loader.created == []


def test_a_viewer_can_still_read_the_catalog() -> None:
    client, _, _ = _client(rows=[])
    assert client.get("/api/v1/baseline/controls", headers=_h(role="viewer")).status_code == 200
