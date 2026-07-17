# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-51: per-namespace apply governance (apply_mode = enforce | dry_run_only). When a namespace is dry_run_only
the API must REJECT policy applies + pack enables (server-enforced, admin too) with 409, while dry-run/drafts and
the enforcement of EXISTING policies are unaffected."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


class _FakeSession:
    """Returns a NamespaceSettings-like row carrying the given apply_mode for the settings lookup."""

    def __init__(self, apply_mode: str | None) -> None:
        self.apply_mode = apply_mode

    async def execute(self, stmt):
        _ = stmt
        row = SimpleNamespace(apply_mode=self.apply_mode) if self.apply_mode is not None else None
        return SimpleNamespace(scalar_one_or_none=lambda: row)

    async def close(self) -> None:
        return None


class _StubLoader:
    def get_current(self, ns, ac):
        return ""  # no saved policy -> apply would 404 (past the F-51 gate)

    def get_entry(self, ns, ac):
        return {}


def _client(apply_mode: str | None) -> TestClient:
    app = create_app()
    app.state.loader = _StubLoader()

    async def _override():
        yield _FakeSession(apply_mode)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _admin() -> dict:
    return {"Authorization": f"Bearer {jwt.encode({'sub': 'a', 'role': 'admin', 'exp': int(time.time()) + 3600}, settings.api_secret_key, algorithm='HS256')}"}


_BODY = {"target_type": "agent_class", "target_namespace": "default"}


def test_apply_rejected_when_dry_run_only():
    # F-51: a dry-run-only namespace returns 409 (admin too) BEFORE any write.
    resp = _client("dry_run_only").post("/api/v1/policies/default/finance-agent/apply", json=_BODY, headers=_admin())
    assert resp.status_code == 409
    assert "dry-run-only" in resp.json()["detail"]


def test_apply_allowed_when_enforce():
    # enforce (or unset) -> the gate passes; with no saved rego the handler then 404s (proves it got past the gate).
    resp = _client("enforce").post("/api/v1/policies/default/finance-agent/apply", json=_BODY, headers=_admin())
    assert resp.status_code == 404  # "Policy not found. Save it first." — past the F-51 gate


def test_apply_allowed_when_unset():
    resp = _client(None).post("/api/v1/policies/default/finance-agent/apply", json=_BODY, headers=_admin())
    assert resp.status_code == 404  # null apply_mode falls back to enforce


def test_pack_enable_rejected_when_dry_run_only():
    # F-51: pack mutations honor the same gate.
    resp = _client("dry_run_only").post(
        "/api/v1/policy-packs/finance-money-movement/enable", json={"namespace": "default"}, headers=_admin()
    )
    assert resp.status_code == 409
