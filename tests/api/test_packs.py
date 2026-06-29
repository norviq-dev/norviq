# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F047: GET /policy-packs catalog + admin-only enable/disable. Covers list (with/without enabled),
enable materializes the combined rego via the loader, non-admin 403, unknown pack 404, idempotency,
and disable re-materialize/delete."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient
from jose import jwt

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Param-aware in-memory NamespacePack store (filters by the statement's bound namespace/pack_id)."""

    def __init__(self, rows: list | None = None) -> None:
        self.rows = list(rows or [])
        self.added: list = []
        self.committed = False

    async def execute(self, stmt):
        sql = str(stmt)
        try:
            params = stmt.compile().params
        except Exception:
            params = {}
        ns = params.get("namespace_1")
        pid = params.get("pack_id_1")
        if sql.strip().upper().startswith("DELETE"):
            self.rows = [r for r in self.rows if not (r.namespace == ns and r.pack_id == pid)]
            return SimpleNamespace(rowcount=1)
        if sql.strip().startswith("SELECT namespace_packs.pack_id "):
            ids = [r.pack_id for r in self.rows if r.namespace == ns]
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: ids))
        match = next((r for r in self.rows if r.namespace == ns and r.pack_id == pid), None)
        return SimpleNamespace(scalar_one_or_none=lambda: match)

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
        self.deleted: list = []

    async def create(self, ns, agent_class, rego, **kw):
        self.created.append({"ns": ns, "agent_class": agent_class, "rego": rego, **kw})
        return 1

    async def delete(self, ns, agent_class):
        self.deleted.append((ns, agent_class))
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


def _token(role: str = "admin", namespace: str = "default") -> str:
    return jwt.encode({"sub": "u", "role": role, "namespace": namespace}, settings.api_secret_key, algorithm="HS256")


def _h(role: str = "admin") -> dict:
    return {"Authorization": f"Bearer {_token(role)}"}


def test_catalog_lists_all_packs_default_disabled() -> None:
    client, _, _ = _client(rows=[])
    resp = client.get("/api/v1/policy-packs?namespace=default", headers=_h())
    assert resp.status_code == 200
    rows = resp.json()
    ids = {r["id"] for r in rows}
    assert {"energy-ot", "finance-money-movement", "healthcare-phi", "government-cui", "telecom-cpni"} <= ids
    assert all(r["enabled"] is False for r in rows)  # default-OFF
    energy = next(r for r in rows if r["id"] == "energy-ot")
    assert energy["sector"] == "Energy" and "ot_control_command_blocked" in energy["rule_ids"]


def test_catalog_reflects_enabled_state() -> None:
    client, _, _ = _client(rows=[SimpleNamespace(namespace="default", pack_id="energy-ot")])
    rows = client.get("/api/v1/policy-packs?namespace=default", headers=_h()).json()
    assert next(r for r in rows if r["id"] == "energy-ot")["enabled"] is True
    assert next(r for r in rows if r["id"] == "finance-money-movement")["enabled"] is False


def test_enable_admin_materializes_combined_policy() -> None:
    client, session, loader = _client(rows=[])
    resp = client.post("/api/v1/policy-packs/energy-ot/enable", json={"namespace": "default"}, headers=_h())
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True and resp.json()["enabled_packs"] == ["energy-ot"]
    assert len(session.added) == 1 and session.added[0].pack_id == "energy-ot"
    # materialized as the (default,__pack__) policy carrying the energy block rule
    assert len(loader.created) == 1
    mat = loader.created[0]
    assert mat["ns"] == "default" and mat["agent_class"] == "__pack__"
    assert "ot_control_command_blocked" in mat["rego"] and mat["priority"] == 800


def test_enable_non_admin_forbidden() -> None:
    client, _, loader = _client(rows=[])
    resp = client.post("/api/v1/policy-packs/energy-ot/enable", json={"namespace": "default"}, headers=_h("viewer"))
    assert resp.status_code == 403
    assert loader.created == []  # nothing materialized


def test_enable_unknown_pack_404() -> None:
    client, _, _ = _client(rows=[])
    resp = client.post("/api/v1/policy-packs/bogus-pack/enable", json={"namespace": "default"}, headers=_h())
    assert resp.status_code == 404


def test_enable_idempotent() -> None:
    client, session, loader = _client(rows=[SimpleNamespace(namespace="default", pack_id="energy-ot")])
    resp = client.post("/api/v1/policy-packs/energy-ot/enable", json={"namespace": "default"}, headers=_h())
    assert resp.status_code == 200
    assert session.added == []  # already enabled -> no duplicate row
    assert loader.created[0]["agent_class"] == "__pack__"  # still re-materialized idempotently


def test_disable_last_pack_deletes_policy() -> None:
    client, session, loader = _client(rows=[SimpleNamespace(namespace="default", pack_id="energy-ot")])
    resp = client.post("/api/v1/policy-packs/energy-ot/disable", json={"namespace": "default"}, headers=_h())
    assert resp.status_code == 200 and resp.json()["enabled"] is False
    assert resp.json()["enabled_packs"] == []
    assert loader.deleted == [("default", "__pack__")]  # no packs left -> policy removed
    assert loader.created == []


def test_disable_keeps_remaining_packs() -> None:
    client, session, loader = _client(
        rows=[
            SimpleNamespace(namespace="default", pack_id="energy-ot"),
            SimpleNamespace(namespace="default", pack_id="finance-money-movement"),
        ]
    )
    resp = client.post("/api/v1/policy-packs/energy-ot/disable", json={"namespace": "default"}, headers=_h())
    assert resp.status_code == 200 and resp.json()["enabled_packs"] == ["finance-money-movement"]
    # re-materialized with the remaining pack (finance), not deleted
    assert loader.deleted == [] and len(loader.created) == 1
    assert "wire_over_threshold_escalate" in loader.created[0]["rego"]
    assert "ot_control_command_blocked" not in loader.created[0]["rego"]


def test_packs_requires_auth() -> None:
    client, _, _ = _client(rows=[])
    assert client.get("/api/v1/policy-packs").status_code in (401, 403)
