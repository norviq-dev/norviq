# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""F-37: the generic POST /api/v1/policies must reject a direct write to the managed `__pack__` scope (it is
owned by the packs router and silently wiped by _materialize), pointing the caller at the packs enable API.
`__guardrail__` (operator-loaded, F-14) and normal class policies are NOT rejected by this guard."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app

_VALID_REGO = 'package norviq.x\ndefault decision = "allow"\nrule_id = "r"\nreason = "x"\ndecision = "block" { input.tool_name == "drop_table" }\n'


class _StubLoader:
    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []

    async def create(self, namespace, agent_class, rego_source, **kw):
        self.created.append((namespace, agent_class))
        return 1

    def get_versions(self, namespace, agent_class):
        return []


class _NoSettingsSession:
    """No persisted settings row -> apply_mode falls back to enforce (F-51 gate is a no-op for this test)."""

    async def execute(self, stmt):
        _ = stmt
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def close(self) -> None:
        return None


def _client() -> tuple[TestClient, _StubLoader]:
    app = create_app()
    loader = _StubLoader()
    app.state.loader = loader
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default", "sub": "admin"}

    async def _session():
        yield _NoSettingsSession()

    app.dependency_overrides[get_session] = _session
    return TestClient(app), loader


def test_direct_pack_write_is_rejected():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__pack__",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 422
    assert "policy-packs" in resp.json()["detail"]      # points at the real enable path
    assert loader.created == []                          # never reached loader.create


def test_guardrail_scope_is_allowed():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__guardrail__",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 200                       # F-14 operator-loaded guardrail still works
    assert ("default", "__guardrail__") in loader.created


def test_normal_class_policy_is_allowed():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 200
    assert ("default", "finance-agent") in loader.created


def test_apply_to_reserved_scope_is_rejected():
    # F-42: the apply path (sibling of create) must also reject __pack__/__baseline__ — it returned 200 before.
    client, _ = _client()
    body = {"target_type": "agent_class", "target_namespace": "default"}
    for scope in ("__pack__", "__baseline__"):
        resp = client.post(f"/api/v1/policies/default/{scope}/apply", json=body)
        assert resp.status_code == 422, scope
        assert "managed scope" in resp.json()["detail"]
