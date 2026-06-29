# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-01 + F-06: /evaluate binds the evaluated namespace to the CALLER; scoped_namespace denies the
empty-claim least-privilege floor. The agent's own service/workload credential (hot path) is unaffected."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jose import jwt

from norviq.api import auth as auth_mod
from norviq.api.main import create_app
from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision


def _token(role: str = "admin", namespace: str = "default") -> str:
    claims = {"sub": f"{role}-{namespace}", "role": role}
    if namespace is not None:
        claims["namespace"] = namespace
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _client() -> TestClient:
    app = create_app()

    async def _evaluate(_event):
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    app.state.evaluator = SimpleNamespace(evaluate=_evaluate)
    app.state.emitter = None
    app.state.audit_hub = None
    return TestClient(app)


def _eval(client: TestClient, token: str, ns: str) -> int:
    body = {
        "tool_name": "get_order",
        "tool_params": {},
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{ns}/sa/x", "namespace": ns, "agent_class": "x"},
        "session_id": "s",
    }
    return client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {token}"}).status_code


def test_viewer_cross_namespace_evaluate_forbidden() -> None:
    """F-01: a viewer scoped to team-a may not evaluate in another tenant."""
    client = _client()
    assert _eval(client, _token("viewer", "team-a"), "payments") == 403


def test_viewer_same_namespace_evaluate_ok() -> None:
    client = _client()
    assert _eval(client, _token("viewer", "team-a"), "team-a") == 200


def test_admin_any_namespace_ok() -> None:
    client = _client()
    assert _eval(client, _token("admin", "default"), "payments") == 200


def test_service_any_namespace_ok_hotpath() -> None:
    """The agent's own service/workload credential (sidecar/SDK/break-glass) is the trusted hot path."""
    client = _client()
    assert _eval(client, _token("service", ""), "payments") == 200


def test_viewer_empty_claim_evaluate_forbidden() -> None:
    """F-06: the empty-claim floor user has no namespace scope -> 403 (was: reached any namespace)."""
    client = _client()
    assert _eval(client, _token("viewer", ""), "payments") == 403


# --- F-06 unit coverage of scoped_namespace directly ---
def test_scoped_namespace_empty_floor_denied() -> None:
    with pytest.raises(HTTPException) as exc:
        auth_mod.scoped_namespace({"role": "viewer", "namespace": ""}, "payments")
    assert exc.value.status_code == 403


def test_scoped_namespace_service_empty_allowed() -> None:
    assert auth_mod.scoped_namespace({"role": "service", "namespace": ""}, "payments") == "payments"


def test_scoped_namespace_admin_any() -> None:
    assert auth_mod.scoped_namespace({"role": "admin", "namespace": ""}, "payments") == "payments"


def test_scoped_namespace_mapped_viewer_match() -> None:
    assert auth_mod.scoped_namespace({"role": "viewer", "namespace": "team-a"}, "team-a") == "team-a"
    with pytest.raises(HTTPException):
        auth_mod.scoped_namespace({"role": "viewer", "namespace": "team-a"}, "payments")
