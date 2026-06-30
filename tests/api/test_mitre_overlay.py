# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""F-39: /mitre/coverage overlays per-technique observed-attempt + blocked counts from audit (best-effort)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Session:
    """Stub async session: returns audit aggregate rows (rule_id, decision, count)."""

    def __init__(self, rows):
        self._rows = rows

    async def execute(self, _stmt):
        return _Result(self._rows)


class _Loader:
    # rego that "covers" the prompt-injection technique (AML.T0048 -> llm01_prompt_injection)
    _policies = {"default:__baseline__": {"rego": 'blocks["llm01_prompt_injection"] { x }', "priority": 100}}


def _client(rows):
    app = create_app()
    app.state.loader = _Loader()
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default"}

    async def _sess():
        yield _Session(rows)

    app.dependency_overrides[get_session] = _sess
    return TestClient(app)


def test_mitre_overlay_counts_attempts_and_blocked():
    # 7 prompt-injection blocks + 2 escalates + 1 allow = 10 observed, 9 blocked for AML.T0048
    rows = [("llm01_prompt_injection", "block", 7), ("llm01_prompt_injection", "escalate", 2),
            ("llm01_prompt_injection", "allow", 1)]
    resp = _client(rows).get("/api/v1/mitre/coverage?namespace=default&range=24h")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observed"] == 10 and body["blocked"] == 9
    t = next(t for t in body["techniques"] if t["technique_id"] == "AML.T0048")
    assert t["observed"] == 10 and t["blocked"] == 9 and t["covered"] is True


def test_mitre_overlay_zero_activity_still_returns_mapping():
    resp = _client([]).get("/api/v1/mitre/coverage?namespace=default")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observed"] == 0 and body["total"] > 0  # mapping intact even with no audit activity
