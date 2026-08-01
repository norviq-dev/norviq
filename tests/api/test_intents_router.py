# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`/api/v1/intents/*` — compile, propose, dry-run, draft.

The security property these guard is the one the whole feature rests on: **nothing here can start
enforcing**. A draft lands in `intent_drafts`, the dedicated table `_collect_candidates` never reads,
and applying stays the existing gated Policies flow. A second path into `policies` would be a second
way to enforce, one of which nobody reviews.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import intents as intents_router

_GOOD_INTENT = {
    "name": "support-bot-refunds",
    "class": "support-bot",
    "call": [{
        "id": "notify-customer",
        "match": {"verb": "send", "param_paths.to": {"matches": r"^[^@]+@acme\.com$"}},
        "require": {"data_classes": {"noneOf": ["secret"]}},
    }],
}


class _FakeResult:
    def __init__(self, rows): self._rows = rows
    def scalars(self): return self
    def all(self): return self._rows


class _FakeSession:
    """Records what was added; never writes anything anywhere."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.added = []
        self.committed = False

    async def execute(self, _stmt): return _FakeResult(self.rows)
    def add(self, obj): self.added.append(obj)
    async def commit(self): self.committed = True


def _client(session: _FakeSession | None = None, user: dict | None = None) -> TestClient:
    app = create_app()
    sess = session or _FakeSession()

    async def _session_override():
        yield sess

    app.dependency_overrides[get_session] = _session_override
    app.dependency_overrides[get_current_user] = lambda: (
        user if user is not None else {"sub": "admin", "role": "admin", "namespace": "agents"}
    )
    client = TestClient(app)
    client._fake_session = sess  # type: ignore[attr-defined]
    return client


class _Row:
    """An audit row shaped the way the endpoint reads one."""

    def __init__(self, tool_name, namespace="agents", payload=None):
        self.tool_name = tool_name
        self.namespace = namespace
        self.payload = payload
        self.agent_class = "support-bot"
        self.timestamp_utc = None


# --- compile -----------------------------------------------------------------------------------


def test_compile_returns_rego_and_rule_ids() -> None:
    resp = _client().post("/api/v1/intents/compile", json={"intent": _GOOD_INTENT})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "package norviq.custom" in body["rego"]
    assert 'default decision = "block"' in body["rego"]
    assert body["rule_ids"] == ["notify-customer"]
    assert len(body["sha256"]) == 64


def test_compile_rejects_an_invalid_intent_with_the_reason() -> None:
    """422 with the offending rule and key, not a generic failure — the operator has to fix it."""
    bad = {"name": "n", "class": "c", "call": [{"id": "r", "match": {"recipeint": "a@b.com"}}]}
    resp = _client().post("/api/v1/intents/compile", json={"intent": bad})
    assert resp.status_code == 422
    assert "unknown field" in resp.json()["detail"]


def test_compile_is_deterministic_across_requests() -> None:
    """The console shows this Rego before an operator approves it; it must not change between the
    screen they read and the draft they store."""
    c = _client()
    a = c.post("/api/v1/intents/compile", json={"intent": _GOOD_INTENT}).json()
    b = c.post("/api/v1/intents/compile", json={"intent": _GOOD_INTENT}).json()
    assert a["sha256"] == b["sha256"]


# --- propose -----------------------------------------------------------------------------------


def test_propose_builds_an_intent_from_supplied_calls() -> None:
    resp = _client().post("/api/v1/intents/propose", json={
        "ns": "agents", "cls": "support-bot", "name": "proposed",
        "calls": [{"tool_name": "send_email", "tool_params": {"to": "a@acme.com"}},
                  {"tool_name": "send_email", "tool_params": {"to": "b@acme.com"}},
                  {"tool_name": "send_email", "tool_params": {"to": "c@acme.com"}}],
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is True
    rule = body["intent"]["call"][0]
    assert rule["match"]["tool_name"]["in"] == ["send_email"]
    assert rule["match"]["param_paths.to"]["matches"] == r"^[^@]+@acme\.com$"


def test_propose_reports_when_audit_rows_carry_no_parameters() -> None:
    """Audit param capture is opt-in and OFF by default, and even on it masks. Without params a
    proposal cannot reach a recipient domain, a data class or a SQL table — a real ceiling on how
    tight a rule can be proposed, so it is reported rather than hidden behind a confident-looking
    intent the operator would over-trust."""
    session = _FakeSession(rows=[_Row("send_email"), _Row("search_docs")])
    resp = _client(session).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is False
    assert body["sampled"] == 2
    # tool names still reachable; destination constraints are not invented from nothing
    for rule in body["intent"]["call"]:
        assert "param_paths.to" not in rule["match"]


def test_propose_refuses_when_there_is_no_traffic() -> None:
    """An intent proposed from nothing would allow nothing — a silent outage dressed as a policy."""
    resp = _client().post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 422
    assert "no recorded traffic" in resp.json()["detail"]


def test_propose_refuses_a_managed_scope() -> None:
    resp = _client().post("/api/v1/intents/propose", json={"ns": "agents", "cls": "__baseline__"})
    assert resp.status_code == 422
    assert "managed scope" in resp.json()["detail"]


# --- drafts ------------------------------------------------------------------------------------


def test_draft_is_persisted_non_enforcing_to_the_dedicated_table() -> None:
    """The load-bearing assertion: an IntentDraft row, never a Policy row."""
    from norviq.api.db.models import IntentDraft, Policy  # noqa: F401  (Policy imported to name it)

    client = _client()
    resp = client.post("/api/v1/intents/drafts",
                       json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT})
    assert resp.status_code == 200, resp.text
    assert resp.json()["enforcing"] is False
    added = client._fake_session.added  # type: ignore[attr-defined]
    assert len(added) == 1
    assert isinstance(added[0], IntentDraft)
    assert type(added[0]).__name__ != "Policy"
    assert added[0].agent_class == "support-bot"
    assert 'default decision = "block"' in added[0].rego_source


def test_draft_round_trips_the_intent_so_the_console_can_re_edit_it() -> None:
    """Storing only generated Rego would leave the operator with output they cannot map back to the
    sentences that produced it."""
    client = _client()
    client.post("/api/v1/intents/drafts",
                json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT})
    stored = client._fake_session.added[0]  # type: ignore[attr-defined]
    assert stored.toggles["intent"] == _GOOD_INTENT
    assert stored.toggles["kind"] == "intent-v2"


def test_draft_rejects_an_invalid_intent_before_storing_anything() -> None:
    client = _client()
    resp = client.post("/api/v1/intents/drafts",
                       json={"ns": "agents", "cls": "support-bot",
                             "intent": {"name": "n", "class": "c", "call": [{"id": "r"}]}})
    assert resp.status_code == 422
    assert client._fake_session.added == []  # type: ignore[attr-defined]


def test_draft_requires_admin() -> None:
    """Creating a draft is a privileged action even though it does not enforce: it lands in the
    catalog an admin later applies from."""
    client = _client(user={"sub": "v", "role": "viewer", "namespace": "agents"})
    resp = client.post("/api/v1/intents/drafts",
                       json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT})
    assert resp.status_code in (401, 403)
    assert client._fake_session.added == []  # type: ignore[attr-defined]


def test_draft_refuses_a_managed_scope() -> None:
    client = _client()
    resp = client.post("/api/v1/intents/drafts",
                       json={"ns": "agents", "cls": "__pack__", "intent": _GOOD_INTENT})
    assert resp.status_code == 422
    assert client._fake_session.added == []  # type: ignore[attr-defined]


def test_list_drafts_reports_them_as_non_enforcing() -> None:
    class _D:
        id = "intent-abc"
        namespace = "agents"
        agent_class = "support-bot"
        would_block = 0
        total = 0
        created_at = None

        def __init__(self):
            self.toggles = {"kind": "intent-v2"}
            self.allow_tools = {"rule_ids": ["notify-customer"]}

    resp = _client(_FakeSession(rows=[_D()])).get("/api/v1/intents/drafts")
    assert resp.status_code == 200, resp.text
    draft = resp.json()["drafts"][0]
    assert draft["enforcing"] is False
    assert draft["rule_ids"] == ["notify-customer"]


# --- the router must not offer a way to enforce ---------------------------------------------------


def test_there_is_no_apply_endpoint() -> None:
    """Applying stays the gated Policies flow. A second route into `policies` would be a second way
    to start enforcing, and only one of them has a review step."""
    paths = {r.path for r in intents_router.router.routes}
    assert not any("apply" in p or "enforce" in p for p in paths), paths


def test_no_intent_endpoint_writes_a_policy_row() -> None:
    from norviq.api.routers import intents as mod
    src = (mod.__file__ or "")
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert "Policy(" not in text, "an intent endpoint must never construct a Policy row"
