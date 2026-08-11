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

    def __init__(self, tool_name, namespace="agents", payload=None, framework="sidecar", agent_class="support-bot"):
        self.tool_name = tool_name
        self.namespace = namespace
        self.payload = payload
        self.agent_class = agent_class
        # A red-team row keeps the TARGET's real agent_class and is distinguished only by this tag
        # (redteam.py `_build_event`), which is exactly why it reaches a class-keyed query.
        self.framework = framework
        self.agent_id = f"spiffe://norviq/ns/{namespace}/sa/{agent_class}"
        self.timestamp_utc = None


# --- compile -----------------------------------------------------------------------------------


def test_compile_returns_rego_and_rule_ids() -> None:
    resp = _client().post("/api/v1/intents/compile", json={"intent": _GOOD_INTENT})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # norviq.intent.<class> — the prefix coverage.py classifies as kind="intent".
    assert "package norviq.intent." in body["rego"]
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


def _allowlisted_tools(intent: dict) -> list[str]:
    names: set[str] = set()
    for rule in intent.get("call", []):
        got = rule.get("match", {}).get("tool_name", {})
        names.update(got.get("in", []) if isinstance(got, dict) else [])
    return sorted(names)


def test_propose_never_grants_a_tool_only_the_red_team_called() -> None:
    """A red-team run targets the class's OWN identity — same namespace, same agent_class, only
    `framework="redteam"` separates it from work the class really did. `propose_intent` turns every
    observed tool name into `match.tool_name.in`, so folding the attack into the sample makes a
    DEFAULT-DENY allowlist permanently grant the exact tools the attack used, in a class that never
    legitimately called them. The count the console prints as "Calls sampled" must exclude them too."""
    rows = [_Row("generate_report") for _ in range(8)]
    rows += [
        _Row(t, framework="redteam")
        for t in ("execute_sql", "send_email", "delete_record")
    ]
    body = _client(_FakeSession(rows)).post(
        "/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"}
    ).json()
    assert _allowlisted_tools(body["intent"]) == ["generate_report"]
    assert body["sampled"] == 8  # not 11


def test_propose_ignores_synthetic_probe_identities() -> None:
    """The same rule for the other half of `audit_row_is_non_real`: a policy-tester / e2e / probe
    identity is a harness, not evidence that a tool is real."""
    rows = [_Row("generate_report") for _ in range(4)]
    rows += [_Row("drop_table", agent_class="policy-tester-9f2") for _ in range(3)]
    body = _client(_FakeSession(rows)).post(
        "/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"}
    ).json()
    assert _allowlisted_tools(body["intent"]) == ["generate_report"]
    assert body["sampled"] == 4


def test_propose_query_excludes_non_real_rows_in_sql_too() -> None:
    """The Python guard above is belt-and-braces; the DB must not ship the rows in the first place,
    or the `limit` fills with attack traffic and crowds out the real calls before Python ever sees it."""
    import asyncio

    from norviq.api.routers.intents import _recorded_calls

    class _Capturing(_FakeSession):
        def __init__(self):
            super().__init__([])
            self.sql = ""

        async def execute(self, stmt):
            self.sql = str(stmt)
            return _FakeResult([])

    sess = _Capturing()
    asyncio.run(_recorded_calls(sess, ["agents"], "support-bot", 200))
    assert "framework" in sess.sql and "WHERE" in sess.sql
    assert "audit_log.framework != " in sess.sql or "NOT (" in sess.sql


def test_dry_run_replays_real_traffic_only() -> None:
    """/intents/dry-run reports would-allow over the SAME sample. Replaying the attack calls against
    a proposal derived from them would report the attack as permitted and call it evidence."""
    import asyncio

    from norviq.api.routers.intents import _recorded_calls

    rows = [_Row("generate_report") for _ in range(5)]
    rows += [_Row("execute_sql", framework="redteam")]
    calls, _ = asyncio.run(_recorded_calls(_FakeSession(rows), ["agents"], "support-bot", 200))
    assert [c["tool_name"] for c in calls] == ["generate_report"] * 5


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


# --- ARGUMENT NAMES: the three-state `params_detail` ----------------------------------------------
#
# Two operators (fintech, legal) independently reported the same failure in almost the same words:
# they authored a rule they believed covered a call, the engine enforced it correctly, and the model
# emitted arguments none of their predicates mentioned — `{"tool_name": "issue_refund", "tool_params":
# {"txn_id": "TXN-8891", "amount": 25.0}}`. The authoring surface showed argument names from the
# SCHEMA and never the ones recorded traffic actually carries, so there was no point at which the
# mismatch was visible before it mattered.
#
# `params_available` answers "are VALUES present" and is unchanged. `params_detail` answers "how much
# is known about the arguments AT ALL", and its middle rung — names captured, values not — is the
# state that used to be indistinguishable from knowing nothing.


def _keys_row(tool: str, keys, **extra) -> "_Row":
    """An audit row from the key-capture path: argument NAMES, never a value."""
    return _Row(tool, payload={"param_keys": keys, **extra})


def _captured_row(tool: str, params: dict) -> "_Row":
    """A key-only audit row built by the SHIPPED capture path, from a real params object.

    Hand-written `param_keys` fixtures are how a test ends up asserting behaviour no install can
    reach: the capture path writes FOUR fields and a fixture that omits `param_keys_pinnable` is a
    row no engine produces, so a test built on one pins the behaviour of a state that does not
    exist. This runs the real derivation and stores what it returns, so the fixture and the product
    cannot drift. No value is stored — that is the point of the field.
    """
    from norviq.api.routers.evaluate import _param_key_set
    from norviq.engine.evaluator import OPAEvaluator

    keys, ambiguous, pinnable, truncated = _param_key_set(OPAEvaluator, params)
    assert keys is not None, "the capture path could not derive names; the fixture proves nothing"
    return _Row(tool, payload={"param_keys": keys, "param_keys_ambiguous": ambiguous,
                               "param_keys_pinnable": pinnable, "param_keys_truncated": truncated})


def test_key_only_capture_is_a_third_state_and_does_not_widen_params_available() -> None:
    """`param_keys` on the row must NOT be reported as `params_available`.

    The boolean means "values are present" and the console suppresses every value-level affordance on
    it. Widening it to cover key-only capture would tell every existing reader that recipient
    domains and data classes were checked when nothing of the sort was recorded.
    """
    session = _FakeSession(rows=[_keys_row("issue_refund", ["amount", "txn_id"])])
    resp = _client(session).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is False          # values: still none
    assert body["params_detail"] == "keys"            # names: recorded
    observed = body["observed_params"]["issue_refund"]
    assert observed["keys"] == ["amount", "txn_id"]
    assert observed["detail"] == "keys"


def test_an_old_row_is_none_not_keys() -> None:
    """A row written before key capture existed knows NOTHING about arguments.

    Absent must degrade to "none", never to "keys" with an empty list — that would assert "this tool
    takes no arguments" from no evidence, which is the fail-open shape this codebase keeps hitting.
    """
    session = _FakeSession(rows=[_Row("send_email"), _Row("search_docs", payload={"masked_params": {}})])
    resp = _client(session).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_detail"] == "none"
    assert body["observed_params"]["send_email"]["detail"] == "none"
    assert body["observed_params"]["send_email"]["keys"] == []
    assert any("absence of evidence" in note for note in body["params_notes"])


def test_no_arguments_captured_and_captured_with_no_arguments_do_not_render_the_same() -> None:
    """THE distinction this project keeps collapsing.

    `ping` was observed by a capture-enabled engine and genuinely takes no arguments. `legacy_tool`
    was observed by an engine that recorded nothing about arguments. Both have an empty key list and
    they must NOT be the same object, or a console renders "no arguments" over both and the operator
    cannot tell a fact from a blind spot.
    """
    session = _FakeSession(rows=[_Row("legacy_tool"), _keys_row("ping", [])])
    resp = _client(session).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    observed = resp.json()["observed_params"]
    assert observed["legacy_tool"]["keys"] == observed["ping"]["keys"] == []
    assert observed["legacy_tool"]["detail"] == "none"
    assert observed["ping"]["detail"] == "keys"
    assert observed["legacy_tool"] != observed["ping"]


def test_the_fintech_moment_an_argument_in_traffic_that_the_rule_never_mentions() -> None:
    """The reported failure, end to end, on a DEFAULT install.

    `audit_capture_param_keys` is on by default and `audit_capture_masked_params` is not, so this is
    what the fintech operator's own traffic looks like — and the rows are built by the SHIPPED
    capture path from the reported payload, not hand-written, so the fixture is a state a real
    install reaches. Before this change the proposal could name `issue_refund` and nothing else, and
    `amount` was invisible at every point in the flow. It is now on the response, attributed to the
    tool, next to a rule that does not mention it.
    """
    rows = [_captured_row("issue_refund", {"txn_id": "TXN-8891", "amount": 25.0}) for _ in range(3)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["issue_refund"]
    assert observed["keys"] == ["amount", "txn_id"]
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    mentioned = set(rule.get("match", {})) | set(rule.get("require", {}))
    assert {f"param_paths.{k}" for k in observed["keys"]} - mentioned, (
        "the rule mentions every observed argument, so there is no mismatch left to flag"
    )


def test_a_name_only_row_asserts_the_vouched_path_and_never_the_type_erased_one() -> None:
    """The outage this endpoint must not propose, and the blind spot it must not invent.

    REWRITTEN (was `..._never_produces_a_predicate_because_it_cannot_vouch_for_the_type`, which
    asserted `existence_predicates == {}` from a hand-written row carrying only `param_keys`). The
    shipped capture path writes FOUR fields, and `param_keys_pinnable` is the one that answers
    exactly the question the old test assumed was unanswerable — which leaf TYPE stood at the end of
    each path. No install produces the row that test described, so it pinned the behaviour of a
    state that does not exist. The row here is built by the capture path itself.

    Both halves still have to hold, and they pull in opposite directions:

      * `amount` is a NUMBER. `input.derived.param_paths` carries string leaves only, so
        `param_paths.amount` is never present at enforcement time; a rule requiring it can never
        match, and a rule that never matches under `default decision = "block"` refuses EVERY call
        to `issue_refund`. It must be SHOWN and never asserted — and the dry run cannot catch a
        mistake here, because a name-only row replays with no `param_paths` at all.
      * `txn_id` is a STRING and capture vouched for it. Reporting `pinnable: []` for this tool
        would tell the console nothing about `issue_refund` can be constrained, which is false and
        is the blind spot this work exists to remove.
    """
    rows = [_captured_row("issue_refund", {"txn_id": "TXN-8891", "amount": 25.0}) for _ in range(3)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is False          # no values were stored, and none were invented
    assert body["params_detail"] == "keys"
    observed = body["observed_params"]["issue_refund"]
    assert observed["keys"] == ["amount", "txn_id"]   # both SHOWN
    assert observed["pinnable"] == ["txn_id"]         # only one vouched for
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert "param_paths.txn_id" in rule["require"]
    assert "param_paths.amount" not in rule["require"]
    assert body["existence_predicates"][rule["id"]] == ["param_paths.txn_id"]
    assert any("no value this engine can constrain" in note for note in body["params_notes"])


def test_a_vouched_name_the_operator_was_never_shown_is_never_asserted() -> None:
    """`param_keys_pinnable` is attacker-reachable text like every other field on the row.

    A row claiming a path is pinnable that is NOT in the key set is a row asserting something the
    operator cannot see on their screen. The two lists are reconciled in the safe direction: the
    shown set wins, and a name outside it is neither rendered nor compiled into a rule.
    """
    rows = [_keys_row("issue_refund", ["txn_id"],
                      param_keys_pinnable=["txn_id", "not_shown"],
                      param_keys_ambiguous=[]) for _ in range(2)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["issue_refund"]
    assert observed["keys"] == ["txn_id"]
    assert observed["pinnable"] == ["txn_id"]
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert "param_paths.not_shown" not in rule["require"]
    assert body["existence_predicates"][rule["id"]] == ["param_paths.txn_id"]


def test_a_name_only_row_that_vouches_for_nothing_asserts_nothing() -> None:
    """The kill-switch / old-capture case: `param_keys` without `param_keys_pinnable`.

    A reader that finds the field absent must pin NOTHING — the positive set is published precisely
    so its absence fails closed. `param_keys` alone still buys the operator the names, which is the
    whole operator moment; it does not buy a predicate.
    """
    rows = [_keys_row("issue_refund", ["amount", "txn_id"]) for _ in range(3)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["observed_params"]["issue_refund"]["keys"] == ["amount", "txn_id"]
    assert body["observed_params"]["issue_refund"]["pinnable"] == []
    assert body["existence_predicates"] == {}
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert not any(f.startswith("param_paths.") for f in rule.get("require", {}))


def test_a_proposal_asserts_the_arguments_traffic_always_carried_and_states_that_it_did() -> None:
    """Where the engine ITSELF derived the path, an existence predicate is sound and is emitted.

    Masked capture records values, so `input.derived.param_paths` names exactly the paths that will
    be present in production. Every recorded `issue_refund` carried both, so the rule requires both
    to be PRESENT and unambiguously derived. It constrains no value, and the response says so rather
    than leaving the operator to infer it from the generated Rego.
    """
    rows = [_Row("issue_refund", payload={"masked_params": {"txn_id": "T-1", "reason": "dup"}})
            for _ in range(3)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert "param_paths.txn_id" in rule["require"]
    assert "param_paths.reason" in rule["require"]
    assert sorted(body["existence_predicates"][rule["id"]]) == ["param_paths.reason", "param_paths.txn_id"]
    assert any("existence predicate" in note for note in body["params_notes"])


def test_an_argument_only_some_calls_carry_is_shown_but_never_asserted() -> None:
    """A proposal must never be narrower than the traffic it was proposed from.

    `reason` appears on one of two recorded calls. Asserting it would make the rule refuse the calls
    that do not carry it — a silent outage dressed as a tighter policy. So it is NOT asserted, and it
    IS shown: an argument the operator's rule does not mention, which is the whole deliverable.
    """
    rows = [_Row("issue_refund", payload={"masked_params": {"txn_id": "T-1", "reason": "dup"}}),
            _Row("issue_refund", payload={"masked_params": {"txn_id": "T-2"}})]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert "param_paths.txn_id" in rule["require"]
    assert "param_paths.reason" not in rule["require"]
    assert "reason" in body["observed_params"]["issue_refund"]["keys"]


def test_a_forgeable_argument_name_is_flagged_and_never_asserted() -> None:
    """A name a caller can MINT is a trap, not a constraint.

    The path grammar uses `.` and `[i]` as structure, so `{"message": {"to": [...]}}` and a literal
    key `message.to[0].addr` reach the SAME name and whichever the caller ordered last wins the dict.
    A rule pinned there reads the attacker's chosen value as compliant — the exact bypass
    `param_paths_ambiguous` exists to name. The capture path publishes those names deliberately, so
    they are SHOWN (a shorter, confident list would be worse) and never turned into a predicate.
    """
    rows = [_keys_row("send_note", ["message.to[0].addr"],
                      param_keys_ambiguous=["message.to[0].addr"]) for _ in range(2)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["send_note"]
    assert observed["keys"] == ["message.to[0].addr"]
    assert observed["ambiguous"] == ["message.to[0].addr"]
    assert observed["pinnable"] == []
    assert body["existence_predicates"] == {}
    assert any("caller chooses which value answers them" in note for note in body["params_notes"])


def test_a_forgeable_name_is_not_asserted_even_when_values_were_recorded() -> None:
    """The value-bearing path must refuse it too, or the guard is only half present.

    Masked capture would otherwise let the engine's own derivation vouch for the path; the engine
    flags it ambiguous in the same breath, and the flag has to win.
    """
    forged = {"message": {"to": [{"addr": "ops@acme.com"}]},
              "message.to[0].addr": "collector@attacker.example"}
    rows = [_Row("send_note", payload={"masked_params": forged}) for _ in range(2)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["send_note"]
    assert "message.to[0].addr" in observed["ambiguous"]
    assert "message.to[0].addr" not in observed["pinnable"]
    rule = next(r for r in body["intent"]["call"] if "send_note" in r["match"]["tool_name"]["in"])
    assert "param_paths.message.to[0].addr" not in rule.get("require", {})


def test_a_numeric_argument_is_shown_to_the_operator_and_never_pinned_by_a_rule() -> None:
    """`{"txn_id": "TXN-8891", "amount": 25.0}` — the reported payload, verbatim.

    `input.derived.param_paths` carries STRING leaves only, so `amount` is not a path any rule can
    ever match. Two consequences, and they pull in opposite directions:

      * it must still be SHOWN, or the one argument the fintech operator needed to notice stays
        invisible exactly as it was before this work;
      * it must NOT be asserted, because `param_paths.amount` is never present in production either —
        the rule would match nothing and deny-by-default would turn that into an outage.

    So it is in `keys` and not in `pinnable`, and the response says why.
    """
    rows = [_Row("issue_refund", payload={"masked_params": {"txn_id": "TXN-8891", "amount": 25.0}})]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is True
    assert body["params_detail"] == "masked"
    observed = body["observed_params"]["issue_refund"]
    assert observed["keys"] == ["amount", "txn_id"]
    assert observed["pinnable"] == ["txn_id"]
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert "param_paths.txn_id" in rule["require"]
    assert "param_paths.amount" not in rule["require"]
    assert any("no value this engine can constrain" in note for note in body["params_notes"])


def test_a_value_arriving_in_a_key_position_never_reaches_the_response() -> None:
    """`param_keys` is a KEYS-ONLY field, and a key is not always a schema fact.

    `mask_params` masks VALUES and preserves KEYS — by design, and it is what makes argument names
    available at all. So `{"balances": {"4111111111111111": 25.0}}` puts a PAN on the audit row
    verbatim, inside `masked_params`, on an install whose whole reason for enabling masked capture
    was PCI 10.3. A key-name walk that copies keys through publishes that PAN into `observed_params`
    and from there into the console and into any rule proposed over it.

    The capture path already solved this — derived NAMES go through the same PAN/SSN masker the
    value capture uses — so this endpoint derives names the same way rather than a second way.
    Asserted on the WHOLE response body, not on one field, because the leak's route is whichever
    field forgets.
    """
    rows = [_Row("export_rows", payload={"masked_params": {
        "balances": {"4111111111111111": 25.0}, "people": {"123-45-6789": "ok"}}})]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    assert "4111111111111111" not in resp.text
    assert "123-45-6789" not in resp.text
    keys = resp.json()["observed_params"]["export_rows"]["keys"]
    assert keys == ["balances.****1111", "people.***-**-6789"]


def test_a_supplied_call_is_the_unmasked_route_and_is_masked_too() -> None:
    """`calls` in the request body arrive UNMASKED — the one raw payload this router ever sees.

    A PAN in a key position there would be echoed straight back in the same response, which is the
    shortest possible path from payload to console.
    """
    resp = _client().post("/api/v1/intents/propose", json={
        "ns": "agents", "cls": "support-bot",
        "calls": [{"tool_name": "export_rows", "tool_params": {"balances": {"4111111111111111": 25.0}}}],
    })
    assert resp.status_code == 200, resp.text
    assert "4111111111111111" not in resp.text
    assert resp.json()["observed_params"]["export_rows"]["keys"] == ["balances.****1111"]


def test_an_over_long_argument_name_is_not_reported_under_a_spelling_it_never_had() -> None:
    """A name CLIPPED at the key bound is a name that was not observed under that spelling.

    Two long keys sharing a 256-character prefix land on ONE path, so a clipped name silently
    understates the argument surface AND names a position it did not come from — "I could not derive
    this fact" wearing the costume of "here is the fact". The engine flags exactly this case as
    ambiguous; so must the authoring surface, or the operator pins a rule to a name no call carries.

    The leaves here are NUMBERS, and that is the whole test. `param_paths` never carries a non-string
    leaf, so the engine's flag over the real values is silent for these — and a name-derivation that
    leans on it inherits the silence and reports the clipped name as an ordinary observation.
    """
    long_a, long_b = "k" * 260 + "ONE", "k" * 260 + "TWO"
    rows = [_Row("bulk_tool", payload={"masked_params": {long_a: 1.0, long_b: 2.0, "ok": "v"}})
            for _ in range(2)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["bulk_tool"]
    # Both 263-character names arrive at the SAME 256-character path. It is shown — hiding it would
    # be its own blind spot — and it is NAMED as one the payload does not unambiguously support.
    clipped = [k for k in observed["keys"] if set(k) == {"k"}]
    assert clipped == ["k" * 256], observed["keys"]
    assert clipped[0] in observed["ambiguous"], "a clipped name must not be presented as observed"
    assert clipped[0] not in observed["pinnable"]
    rule = next(r for r in body["intent"]["call"] if "bulk_tool" in r["match"]["tool_name"]["in"])
    assert f"param_paths.{clipped[0]}" not in rule.get("require", {})
    assert "param_paths.ok" in rule["require"], "the honest name beside it must still be assertable"


def test_argument_names_that_render_identically_are_flagged_not_shown_as_two_plain_names() -> None:
    """A homoglyph name impersonating another is the console's problem before it is Rego's.

    `amount` and `amоunt` (Cyrillic `о`) are different dict keys and RENDER IDENTICALLY. Listed as
    two ordinary names, the operator sees `amount` twice, believes their rule covers it, and the
    flag this whole feature exists to raise fires on a name they cannot tell apart from a covered
    one. The engine folds paths for exactly this and names both twins; the authoring surface has to
    do the same or the flag is worse than useless.

    Both leaves are NUMBERS — the reported payload's own type for `amount`. `param_paths` carries no
    non-string leaf, so the engine's fold over the real values never sees these two and raises
    nothing; a name-derivation that takes its ambiguity from there alone shows the twins as two
    ordinary, unflagged names.
    """
    cyrillic = "amоunt"
    rows = [_Row("issue_refund", payload={"masked_params": {"amount": 25.0, cyrillic: 99.0}})
            for _ in range(2)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["issue_refund"]
    assert set(observed["keys"]) == {"amount", cyrillic}      # both shown, neither rewritten
    assert set(observed["ambiguous"]) == {"amount", cyrillic}  # and both NAMED as indistinguishable
    assert observed["pinnable"] == []
    assert body["existence_predicates"] == {}
    assert any("caller chooses which value answers them" in note for note in body["params_notes"])


def test_argument_names_are_treated_as_attacker_controlled_text() -> None:
    """Key names come from the agent, which is to say from whoever compromised it.

    A name carrying a newline is the exact class that escaped a generated policy's header comment
    before (`builderCompile.ts`), and these names are rendered in the console and can reach a
    compiled rule. A control-charactered name, an over-long one and a non-string are DROPPED and
    COUNTED — never rendered, never turned into a predicate — and the count means the drop is not
    silent.
    """
    rows = [
        # Names arriving as a declared key set...
        _keys_row("notify", ["ok_name", 'evil\ndecision = "allow"', "x" * 500, 5]),
        # ...and names arriving on a value-bearing row, which is the path that can reach a PREDICATE.
        _Row("issue_refund", payload={"masked_params": {
            "ok_name": "v", 'evil\ndecision = "allow"': "v", "space is fine? no": "v"}}),
    ]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose",
                                            json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    declared = body["observed_params"]["notify"]
    assert declared["keys"] == ["ok_name"]
    assert declared["dropped"] == 3  # the newline name, the over-long one, and the non-string
    walked = body["observed_params"]["issue_refund"]
    assert not any("\n" in k or len(k) > 256 for k in walked["keys"])
    rule = next(r for r in body["intent"]["call"] if "issue_refund" in r["match"]["tool_name"]["in"])
    assert not any("\n" in field for field in rule["require"])
    # A name the intent schema cannot address is shown to the operator and never compiled — emitting
    # it would hand back a candidate that /intents/compile rejects on the very next request.
    assert "space is fine? no" in walked["keys"]
    assert "param_paths.space is fine? no" not in rule["require"]
    assert "param_paths.ok_name" in rule["require"]


def test_a_proposal_carrying_existence_predicates_still_compiles() -> None:
    """The proposal's next stop is `/intents/compile`, and an argument name is attacker-chosen text.

    A predicate the intent schema cannot address raises `IntentError` — so a proposal that emitted one
    would hand the operator a candidate the very next request rejects, with the traffic that caused it
    long out of view. Every emitted `param_paths.*` field must survive compilation, and the guard the
    compiler AND-s onto it (path present, not ambiguous) must be in the generated Rego.
    """
    rows = [_Row("issue_refund", payload={"masked_params": {
        "txn_id": "T-1", "meta": {"reason_code": "dup"}}}) for _ in range(2)]
    client = _client(_FakeSession(rows))
    proposal = client.post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"}).json()
    assert proposal["existence_predicates"], "nothing was asserted, so this proves nothing"
    resp = client.post("/api/v1/intents/compile", json={"intent": proposal["intent"]})
    assert resp.status_code == 200, resp.text
    rego = resp.json()["rego"]
    assert 'default decision = "block"' in rego
    # The existence half is the compiler's derivation guard, not the always-true regex.
    assert 'object.get(input.derived.param_paths, "meta.reason_code", null) != null' in rego


def test_a_truncated_key_set_is_reported_as_truncated() -> None:
    """A partial key set reported as complete is worse than none.

    An operator shown 12 of 400 argument names who believes that is all of them will author a rule
    they think is exhaustive. The row says it was cut; the response must repeat that, loudly.
    """
    rows = [_keys_row("issue_refund", ["amount"], param_keys_truncated=True)]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["observed_params"]["issue_refund"]["truncated"] is True
    assert body["params_truncated"] is True
    # The console reads this spelling; they must never disagree, or one reader is told the list is
    # complete while the other is told it is not.
    assert body["observed_params_truncated"] is body["params_truncated"]
    assert any("TRUNCATED" in note for note in body["params_notes"])


def test_a_name_rejected_as_unsafe_also_reports_the_list_as_incomplete() -> None:
    """A dropped name is a name the operator will not be shown.

    `dropped` alone is a count only a careful reader looks at, and a console that renders the key
    list beside a "complete" affordance would be wrong. Rejecting a hostile name is still a reason
    the list is short, so it reports as truncation too — with `dropped` keeping the precise reason.
    """
    rows = [_keys_row("notify", ["ok_name", "bad\nname"])]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    observed = resp.json()["observed_params"]["notify"]
    assert observed["keys"] == ["ok_name"]
    assert observed["dropped"] == 1
    assert observed["truncated"] is True


def test_the_reported_key_set_is_bounded_and_every_cut_is_visible() -> None:
    """Argument names are attacker-chosen, unbounded in number, and rendered in a console.

    2000 rows x 256 paths is half a million strings in one response. The union is bounded — and every
    bound REPORTS. Two of them fire here:

      * the per-tool key-set bound, which must set `truncated` rather than silently return a prefix;
      * the per-rule existence bound, which must be stated rather than dropping the remainder quietly.

    And the invariant that ties them together: no rule may assert a path the operator was not shown.
    """
    rows = [_Row("bulk_tool", payload={"masked_params": {f"k{i:03d}": "v" for i in range(300)}})]
    resp = _client(_FakeSession(rows)).post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    observed = body["observed_params"]["bulk_tool"]
    assert len(observed["keys"]) == 256          # the engine's own walk bound, applied to the union
    assert observed["truncated"] is True
    assert body["params_truncated"] is True
    rule = next(r for r in body["intent"]["call"] if "bulk_tool" in r["match"]["tool_name"]["in"])
    asserted = body["existence_predicates"][rule["id"]]
    assert len(asserted) == 40                   # per-rule bound
    assert any("per-rule bound" in note for note in body["params_notes"])
    # Nothing asserted that was not shown.
    shown = {f"param_paths.{k}" for k in observed["keys"]}
    assert set(asserted) <= shown


def test_supplied_calls_with_no_arguments_are_an_observation_not_a_blind_spot() -> None:
    """A caller who supplies `tool_params: {}` has SAID the call takes no arguments.

    `params_available` stays true — its historical meaning, which the console reads — while
    `params_detail` reports the truth for this case: names are known (there are none), values are not.
    """
    resp = _client().post("/api/v1/intents/propose", json={
        "ns": "agents", "cls": "support-bot",
        "calls": [{"tool_name": "ping", "tool_params": {}}],
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["params_available"] is True
    assert body["params_detail"] == "keys"
    assert body["observed_params"]["ping"] == {
        "detail": "keys", "keys": [], "pinnable": [], "ambiguous": [],
        "calls": 1, "truncated": False, "dropped": 0,
    }


def test_propose_refuses_when_there_is_no_traffic() -> None:
    """An intent proposed from nothing would allow nothing — a silent outage dressed as a policy.

    The message must also say WHICH traffic it counted. Now that red-team and probe rows are excluded
    from the sample, a class whose only window is a red-team run hits this branch with rows plainly
    visible in the Audit Log — "no recorded traffic" would send the operator to debug a healthy
    emitter. Asserting the new sentence, not relaxing the old one."""
    resp = _client().post("/api/v1/intents/propose", json={"ns": "agents", "cls": "support-bot"})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "no real recorded traffic" in detail
    assert "red-team" in detail  # names the exclusion rather than implying the log is empty
    assert "monitor mode" in detail  # keeps the original next step


def test_dry_run_refusal_names_the_same_exclusion() -> None:
    """The replay corpus is the same helper, so its refusal must not describe a different world."""
    resp = _client().post(
        "/api/v1/intents/dry-run",
        json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT},
    )
    assert resp.status_code == 422
    assert "no real recorded traffic" in resp.json()["detail"]


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


# --- dry-run: the replay's own ceiling is reported, not folded into would_block -------------------


def _fake_opa(monkeypatch, decision: str = "block") -> None:
    """Replace the OPA-backed evaluator. The replay's ACCOUNTING is under test here, not Rego."""

    class _Client:
        async def stop(self) -> None:
            return None

    async def _evaluator(_scope: str):
        async def evaluate(_rego: str, _payload: dict) -> dict:
            return {"decision": decision, "rule_id": "", "reason": "no intent rule matched"}

        async def load(_rego: str) -> None:
            return None

        async def unload() -> None:
            return None

        return evaluate, load, unload, _Client()

    monkeypatch.setattr(intents_router, "_opa_evaluator", _evaluator)


def test_dry_run_reports_the_ceiling_the_replay_itself_imposes(monkeypatch) -> None:
    """A refusal caused by what the AUDIT LOG lacks is not a refusal the policy would make.

    A key-only row reconstructs to an input document with no `param_paths` at all, so every
    argument-level predicate reads as unsatisfied and the call replays as a block. That is the
    fail-closed direction and therefore the right one — but reporting it as an ordinary would-block
    tells the operator their candidate refuses traffic it would in fact allow in production. The
    count is published separately, and named.

    The OPA transport is faked — what is under test is the replay's ACCOUNTING, not Rego semantics —
    so nothing here is asserted about `would_block`, which the fake decides.
    """
    _fake_opa(monkeypatch)
    rows = [_keys_row("send_email", ["to"]), _keys_row("send_email", ["to"])]
    resp = _client(_FakeSession(rows)).post(
        "/api/v1/intents/dry-run", json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["total"] == 2
    assert out["params_available"] is False   # unchanged boolean, unchanged meaning
    assert out["params_detail"] == "keys"
    assert out["replayed_without_values"] == 2
    assert out["observed_params"]["send_email"]["keys"] == ["to"]
    assert any("over-report" in note for note in out["params_notes"])


def test_dry_run_over_value_bearing_rows_reports_no_replay_ceiling(monkeypatch) -> None:
    """The counterpart: with masked values recorded, the replay is not handicapped and says so.

    Without this assertion the ceiling count could be a constant and the test above would still pass.
    """
    _fake_opa(monkeypatch, decision="allow")
    rows = [_Row("send_email", payload={"masked_params": {"to": "a@acme.com"}})]
    resp = _client(_FakeSession(rows)).post(
        "/api/v1/intents/dry-run", json={"ns": "agents", "cls": "support-bot", "intent": _GOOD_INTENT})
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["params_detail"] == "masked"
    assert out["replayed_without_values"] == 0
    assert not any("over-report" in note for note in out["params_notes"])


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


# --- the drafts LIST endpoint tolerates every shape the column actually holds ---------------------

class _DraftRow:
    """An `IntentDraft` shaped the way `list_drafts` reads one."""

    def __init__(self, draft_id: str, toggles, allow_tools):
        self.id = draft_id
        self.namespace = "agents"
        self.agent_class = "support-bot"
        self.toggles = toggles
        self.allow_tools = allow_tools
        self.would_block = 0
        self.total = 0
        self.created_at = None


def test_list_drafts_survives_a_list_shaped_toggles_column():
    """One row must not 500 the whole inbox.

    `IntentDraft.toggles` and `.allow_tools` are typed `dict | None`, and THREE shipped producers
    store a LIST in them instead: `threats.py`'s intent generator (`enabled_keys()`), its
    verb-promotion path, and `mitre.py`'s control mapping. `threats.py` reads those back as
    `list(r["toggles"] or [])`, so the list shape is long-standing and legitimate.

    `list_drafts` did `(r.toggles or {}).get("kind", ...)`, which raises AttributeError on a list.
    Because this is a LIST endpoint, one such row returned 500 for EVERY caller and EVERY namespace —
    so creating a draft from the Attack Graph or from MITRE permanently broke the drafts inbox.
    Observed on a live cluster: a plain GET /api/v1/intents/drafts returned 500.
    """
    rows = [
        _DraftRow("d-list", toggles=["sql_injection", "pii_egress"], allow_tools=["search_kb"]),
        _DraftRow("d-dict", toggles={"kind": "intent-v2"}, allow_tools={"rule_ids": ["r1", "r2"]}),
        _DraftRow("d-none", toggles=None, allow_tools=None),
    ]
    resp = _client(_FakeSession(rows)).get("/api/v1/intents/drafts?ns=all")
    assert resp.status_code == 200, resp.text

    drafts = {d["draft_id"]: d for d in resp.json()["drafts"]}
    assert len(drafts) == 3
    # A list-shaped row degrades to the documented defaults rather than taking the endpoint down.
    assert drafts["d-list"]["kind"] == "intent"
    assert drafts["d-list"]["rule_ids"] == []
    # ...and the dict-shaped row still reads exactly as before.
    assert drafts["d-dict"]["kind"] == "intent-v2"
    assert drafts["d-dict"]["rule_ids"] == ["r1", "r2"]
    assert drafts["d-none"]["kind"] == "intent"
