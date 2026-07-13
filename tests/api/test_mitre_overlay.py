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
    """Stub async session. Base rows are (rule_id, decision, count); the stub reshapes them per query:
    _activity_by_rule now selects agent_class+framework (5-tuple, real events), _blocked_by_rule_class
    selects agent_class (3-tuple, block/escalate only)."""

    def __init__(self, rows, cls="customer-support"):
        self._rows = rows
        self._cls = cls

    async def execute(self, _stmt):
        sql = str(_stmt)
        if "framework" in sql:  # _activity_by_rule → (rule_id, decision, agent_class, framework, count)
            shaped = [(rid, dec, self._cls, "", n) for (rid, dec, n) in self._rows]
        else:  # _blocked_by_rule_class → (rule_id, agent_class, count) for block/escalate only
            shaped = [(rid, self._cls, n) for (rid, dec, n) in self._rows if dec in ("block", "escalate")]
        return _Result(shaped)

    async def scalar(self, *a, **k):  # snapshot/last-exported best-effort reads
        return None

    def add(self, *a, **k):
        return None

    async def commit(self):
        return None


class _Loader:
    # rego that "covers" the prompt-injection technique (B0 corrected: llm01_prompt_injection -> AML.T0051)
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
    # 7 prompt-injection blocks + 2 escalates + 1 allow = 10 observed, 9 blocked for AML.T0051
    # (B0: llm01_prompt_injection is officially "LLM Prompt Injection" = AML.T0051, not AML.T0048).
    rows = [("llm01_prompt_injection", "block", 7), ("llm01_prompt_injection", "escalate", 2),
            ("llm01_prompt_injection", "allow", 1)]
    resp = _client(rows).get("/api/v1/mitre/coverage?namespace=default&range=24h")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observed"] == 10 and body["blocked"] == 9
    t = next(t for t in body["techniques"] if t["technique_id"] == "AML.T0051")
    assert t["observed"] == 10 and t["blocked"] == 9 and t["covered"] is True


def test_mitre_overlay_zero_activity_still_returns_mapping():
    resp = _client([]).get("/api/v1/mitre/coverage?namespace=default")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observed"] == 0 and body["total"] > 0  # mapping intact even with no audit activity
