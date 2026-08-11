# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Control-plane MCP pin API: authorization, tenant scoping, and the verdict state machine.

Uses an in-memory stand-in for the session rather than Postgres, because what is under test here is
the ROUTER's logic — who may write, whose namespace they write to, and when a digest change becomes
a drift. The storage round trip is covered by the live-cluster integration test
(`tests/mcp/test_mcp_api_live.py`), which runs against the real database.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from norviq.api.db.models import McpToolPin
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Enough SQLAlchemy surface for this router: scalars/get/add/commit/execute(delete)."""

    def __init__(self, rows: list[McpToolPin]) -> None:
        self.rows = rows
        self.committed = 0

    async def scalars(self, stmt):
        # Read the WHERE clause's bound values rather than re-implementing SQL: the router only ever
        # filters on namespace/server_id equality, so matching on those is faithful.
        wanted = {}
        for crit in getattr(stmt, "_where_criteria", ()):  # noqa: SLF001 - test double
            try:
                wanted[crit.left.name] = crit.right.value
            except AttributeError:
                continue
        rows = [
            r for r in self.rows
            if all(getattr(r, k, None) == v for k, v in wanted.items())
        ]
        return SimpleNamespace(all=lambda: rows)

    async def get(self, _model, key):
        ns, server, tool = key
        for r in self.rows:
            if (r.namespace, r.server_id, r.tool_name) == (ns, server, tool):
                return r
        return None

    def add(self, row) -> None:
        self.rows.append(row)

    async def execute(self, stmt):
        wanted = {}
        for crit in getattr(stmt, "_where_criteria", ()):  # noqa: SLF001
            try:
                wanted[crit.left.name] = crit.right.value
            except AttributeError:
                continue
        keep = [r for r in self.rows if not all(getattr(r, k, None) == v for k, v in wanted.items())]
        removed = len(self.rows) - len(keep)
        self.rows[:] = keep
        return SimpleNamespace(rowcount=removed)

    async def commit(self) -> None:
        self.committed += 1

    async def close(self) -> None:
        return None


def _client(rows: list[McpToolPin] | None = None) -> tuple[TestClient, _FakeSession]:
    app = create_app()
    session = _FakeSession(rows if rows is not None else [])

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app), session


def _tok(role: str = "admin", namespace: str = "*", sub: str = "u") -> str:
    claims = {"sub": sub, "role": role, "namespace": namespace, "exp": int(time.time()) + 3600}
    if role == "service":
        claims["spiffe_id"] = f"spiffe://norviq/ns/{namespace}/sa/default"
        claims["agent_class"] = "mcp-agent"
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _hdr(**kw) -> dict:
    return {"Authorization": f"Bearer {_tok(**kw)}"}


def _observe(server="fs", tools=None, namespace="agents", mode="tofu") -> dict:
    return {
        "namespace": namespace, "server_id": server, "mode": mode,
        "tools": tools or [{"tool_name": "read_file", "digest": "a" * 64,
                            "canonical": '{"name":"read_file"}', "scan_severity": "none"}],
    }


# ── the verdict state machine ───────────────────────────────────────────────────────────────────
def test_first_sight_is_pinned_under_tofu():
    client, session = _client()
    r = client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=_hdr(role="service", namespace="agents"))
    assert r.status_code == 200
    assert r.json()["verdicts"]["read_file"]["status"] == "first_seen"
    assert session.rows[0].approved is True


def test_first_sight_is_quarantined_under_strict():
    client, session = _client()
    r = client.post("/api/v1/mcp/pins/observe", json=_observe(mode="strict"),
                    headers=_hdr(role="service", namespace="agents"))
    assert r.json()["verdicts"]["read_file"]["status"] == "quarantined"
    assert session.rows[0].approved is False


def test_unknown_mode_falls_to_the_stricter_posture():
    """A typo in the proxy's config must not silently disable the gate."""
    client, session = _client()
    r = client.post("/api/v1/mcp/pins/observe", json=_observe(mode="tofu-ish"),
                    headers=_hdr(role="service", namespace="agents"))
    assert r.json()["mode"] == "strict"
    assert session.rows[0].approved is False


def test_same_digest_stays_pinned():
    client, _ = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=hdr)
    r = client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=hdr)
    assert r.json()["verdicts"]["read_file"]["status"] == "pinned"


def test_changed_digest_is_drift_and_the_approval_does_not_move():
    client, session = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=hdr)
    changed = _observe(tools=[{"tool_name": "read_file", "digest": "b" * 64,
                              "canonical": '{"name":"read_file","description":"changed"}',
                              "scan_severity": "critical"}])
    r = client.post("/api/v1/mcp/pins/observe", json=changed, headers=hdr)
    assert r.json()["verdicts"]["read_file"]["status"] == "drift"
    row = session.rows[0]
    # THE property that makes a rug pull cost more than one blocked call.
    assert row.approved_digest == "a" * 64
    assert row.last_digest == "b" * 64
    assert row.drift_count == 1


def test_drift_persists_across_repeated_observations():
    client, _ = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=hdr)
    changed = _observe(tools=[{"tool_name": "read_file", "digest": "b" * 64, "canonical": "{}",
                               "scan_severity": "none"}])
    for _ in range(3):
        r = client.post("/api/v1/mcp/pins/observe", json=changed, headers=hdr)
        assert r.json()["verdicts"]["read_file"]["status"] == "drift"


# ── approval ────────────────────────────────────────────────────────────────────────────────────
def test_admin_can_approve_the_served_digest_and_clear_drift():
    client, session = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=hdr)
    client.post("/api/v1/mcp/pins/observe",
                json=_observe(tools=[{"tool_name": "read_file", "digest": "b" * 64,
                                      "canonical": "{}", "scan_severity": "none"}]), headers=hdr)
    r = client.post("/api/v1/mcp/pins/approve",
                    json={"namespace": "agents", "server_id": "fs",
                          "tool_name": "read_file", "digest": "b" * 64},
                    headers=_hdr())
    assert r.status_code == 200
    assert r.json()["status"] == "pinned"
    assert session.rows[0].approved_digest == "b" * 64


def test_approving_an_unseen_digest_is_refused():
    """An approval must name a definition somebody actually reviewed."""
    client, _ = _client()
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=_hdr(role="service", namespace="agents"))
    r = client.post("/api/v1/mcp/pins/approve",
                    json={"namespace": "agents", "server_id": "fs",
                          "tool_name": "read_file", "digest": "f" * 64},
                    headers=_hdr())
    assert r.status_code == 409


def test_approve_requires_admin():
    client, _ = _client()
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=_hdr(role="service", namespace="agents"))
    r = client.post("/api/v1/mcp/pins/approve",
                    json={"namespace": "agents", "server_id": "fs",
                          "tool_name": "read_file", "digest": "a" * 64},
                    headers=_hdr(role="viewer", namespace="agents"))
    assert r.status_code == 403


def test_revoke_withdraws_approval():
    client, session = _client()
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=_hdr(role="service", namespace="agents"))
    r = client.post("/api/v1/mcp/pins/revoke",
                    json={"namespace": "agents", "server_id": "fs", "tool_name": "read_file"},
                    headers=_hdr())
    assert r.status_code == 200
    assert r.json()["status"] == "quarantined"
    assert session.rows[0].approved is False


# ── tenant scoping ──────────────────────────────────────────────────────────────────────────────
def test_observe_binds_the_namespace_to_the_caller_not_the_body():
    """A service token scoped to one tenant must not be able to write another tenant's pins."""
    client, _ = _client()
    r = client.post("/api/v1/mcp/pins/observe",
                    json=_observe(namespace="victim-ns"),
                    headers=_hdr(role="service", namespace="agents"))
    assert r.status_code == 403


def test_viewer_without_namespace_scope_is_refused():
    client, _ = _client()
    r = client.get("/api/v1/mcp/pins", headers=_hdr(role="viewer", namespace=""))
    assert r.status_code == 403


def test_unauthenticated_is_refused():
    client, _ = _client()
    assert client.get("/api/v1/mcp/pins").status_code == 401
    assert client.post("/api/v1/mcp/pins/observe", json=_observe()).status_code == 401


# ── inventory roll-up ───────────────────────────────────────────────────────────────────────────
def test_server_inventory_rolls_up_health_worst_first():
    client, _ = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(server="clean"), headers=hdr)
    client.post("/api/v1/mcp/pins/observe",
                json=_observe(server="poisoned",
                              tools=[{"tool_name": "add", "digest": "c" * 64, "canonical": "{}",
                                      "scan_severity": "critical"}]), headers=hdr)
    client.post("/api/v1/mcp/pins/observe", json=_observe(server="rug"), headers=hdr)
    client.post("/api/v1/mcp/pins/observe",
                json=_observe(server="rug", tools=[{"tool_name": "read_file", "digest": "d" * 64,
                                                    "canonical": "{}", "scan_severity": "none"}]),
                headers=hdr)

    rows = client.get("/api/v1/mcp/servers?namespace=agents", headers=_hdr()).json()
    health = {r["server_id"]: r["health"] for r in rows}
    assert health == {"clean": "ok", "poisoned": "flagged", "rug": "drift"}
    # Anything not "ok" sorts first, so a triaging operator sees the problems without scrolling.
    assert rows[-1]["server_id"] == "clean"


def test_pins_can_be_filtered_by_status():
    client, _ = _client()
    hdr = _hdr(role="service", namespace="agents")
    client.post("/api/v1/mcp/pins/observe", json=_observe(server="rug"), headers=hdr)
    client.post("/api/v1/mcp/pins/observe",
                json=_observe(server="rug", tools=[{"tool_name": "read_file", "digest": "e" * 64,
                                                    "canonical": "{}", "scan_severity": "none"}]),
                headers=hdr)
    drifted = client.get("/api/v1/mcp/pins?namespace=agents&status=drift", headers=_hdr()).json()
    assert [r["tool_name"] for r in drifted] == ["read_file"]
    assert client.get("/api/v1/mcp/pins?namespace=agents&status=pinned", headers=_hdr()).json() == []


def test_forget_server_is_admin_only():
    client, _ = _client()
    client.post("/api/v1/mcp/pins/observe", json=_observe(), headers=_hdr(role="service", namespace="agents"))
    assert client.delete("/api/v1/mcp/servers/agents/fs",
                         headers=_hdr(role="viewer", namespace="agents")).status_code == 403
    r = client.delete("/api/v1/mcp/servers/agents/fs", headers=_hdr())
    assert r.status_code == 200 and r.json()["removed"] == 1


@pytest.mark.parametrize("field", ["server_id"])
def test_missing_required_fields_are_rejected(field):
    body = _observe()
    body[field] = ""
    r = client_and_post(body)
    assert r.status_code == 400


def client_and_post(body):
    client, _ = _client()
    return client.post("/api/v1/mcp/pins/observe", json=body,
                       headers=_hdr(role="service", namespace="agents"))
