# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Data-loss fix: "Generate enforcing policy" for a compliance gap technique must persist its
draft at the dedicated per-class overlay key ``"<real class>__remediation__"`` — NEVER at the real class's
own key — so that "Review & Apply" (which POSTs the draft's ns/class straight into the loader's full-replace
`ON CONFLICT ... DO UPDATE SET rego_source = EXCLUDED.rego_source` upsert) can only ever create/update the
overlay row and never destroy the class's existing comprehensive enforcing policy.

Uses the same `_StubSession`/`_StubLoader` harness as tests/api/test_wave4_compliance.py, extended to CAPTURE
the `IntentDraft` ORM object(s) passed to `session.add()` so the persisted `agent_class`/`affected_class`
can be asserted directly (the response dict alone doesn't prove what got written to the DB)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.db.models import IntentDraft


class _StubResult:
    def all(self):
        return []


class _CapturingSession:
    """Same no-op audit/write behaviour as test_wave4_compliance's _StubSession, but records every
    `IntentDraft` passed to `add()` plus every `execute()` call's (sql text, params) — so a test can assert
    exactly what was persisted / deduped, not just what the HTTP response echoes back."""

    def __init__(self) -> None:
        self.added: list[IntentDraft] = []
        self.executed: list[tuple[str, dict]] = []

    async def execute(self, stmt, params=None, *a, **k):
        # SQLAlchemy `text(...)` objects stringify to the raw SQL; params may arrive positionally (a dict)
        # for the `session.execute(text(...), {...})` calling convention mitre.py uses.
        self.executed.append((str(stmt), params if isinstance(params, dict) else {}))
        return _StubResult()

    async def scalar(self, *a, **k):
        return None

    def add(self, obj, *a, **k):
        if isinstance(obj, IntentDraft):
            self.added.append(obj)
        return None

    async def commit(self):
        return None


class _StubLoader:
    def __init__(self, rego: str = "package norviq.strict") -> None:
        self._policies = {"__cluster__:__baseline__": {"rego": rego}}


def _client(session: _CapturingSession) -> TestClient:
    from norviq.api.auth import get_current_user
    from norviq.api.db.session import get_session
    from norviq.api.main import create_app

    app = create_app()
    app.state.loader = _StubLoader()
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def test_generate_persists_draft_at_the_compound_overlay_key_not_the_real_class():
    session = _CapturingSession()
    client = _client(session)
    resp = client.post(
        "/api/v1/mitre/coverage/generate",
        json={"technique_id": "LLM06:2025", "namespace": "default",
              "agent_class": "report-gen", "framework": "owasp"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "draft"
    # The HTTP response still reports the REAL class for display/messaging (UI-facing "cls" field).
    assert body["cls"] == "report-gen"

    assert len(session.added) == 1, "exactly one IntentDraft row must be written"
    draft = session.added[0]
    # THE FIX: agent_class (the persistence/loader key) is the COMPOUND overlay key, never the bare real class —
    # a bare "report-gen" here is exactly the pre-fix data-loss bug (Review & Apply would replace the base policy).
    assert draft.agent_class == "report-gen__remediation__"
    assert draft.agent_class != "report-gen"
    # The real affected class is retained separately for UI display/traceability.
    assert draft.affected_class == "report-gen"


def test_generate_dedup_delete_targets_the_compound_key_and_the_legacy_bare_key():
    session = _CapturingSession()
    client = _client(session)
    resp = client.post(
        "/api/v1/mitre/coverage/generate",
        json={"technique_id": "LLM06:2025", "namespace": "default",
              "agent_class": "report-gen", "framework": "owasp"},
    )
    assert resp.status_code == 200
    # Scope to the dedup DELETE specifically (retention's enforce_draft_cap also issues an unrelated
    # DELETE FROM intent_drafts on the same request — filter it out by its distinctive "agent_class IN" clause).
    deletes = [(sql, params) for sql, params in session.executed
               if "DELETE FROM intent_drafts" in sql and "agent_class IN" in sql]
    assert len(deletes) == 1
    sql, params = deletes[0]
    # The dedup DELETE covers BOTH the new compound key AND the legacy bare-class key (self-healing: any
    # STALE pre-fix draft sitting at the destructive bare key is cleared so it can never later be applied).
    assert "agent_class IN" in sql
    assert params["cls"] == "report-gen__remediation__"
    assert params["legacy_cls"] == "report-gen"
    assert params["fw"] == "owasp"
    assert params["cid"] == "LLM06:2025"


def test_regenerating_the_same_control_updates_one_draft_not_the_base_class():
    # Dedup parity check, now against the compound key: re-generating the same (framework, control, class)
    # must still write exactly ONE new IntentDraft row per call (idempotent), never touch "report-gen" bare.
    session = _CapturingSession()
    client = _client(session)
    for _ in range(2):
        resp = client.post(
            "/api/v1/mitre/coverage/generate",
            json={"technique_id": "LLM06:2025", "namespace": "default",
                  "agent_class": "report-gen", "framework": "owasp"},
        )
        assert resp.status_code == 200
    assert len(session.added) == 2  # one IntentDraft row added per call (dedup happens via the DELETE, not by skipping add)
    assert {d.agent_class for d in session.added} == {"report-gen__remediation__"}
    assert {d.affected_class for d in session.added} == {"report-gen"}
