# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A recorded call without argument VALUES cannot answer an argument-level predicate.

The audit log keeps argument names by default and values only with masked capture on. Replayed, such a
row has no `param_paths`, so a rule that needs `to` to match anything fails on it, and the call used to
be reported as one the intent "would block". That is a fact about the log, not about the policy. These
tests pin the split: refused only on value predicates -> `cannot_evaluate`; refused on anything else
(the tool name, the plane, an engine-availability guard) -> still `would_block`.
"""

from __future__ import annotations

import shutil

import pytest

from norviq.api.routers.intents import _policy_input
from norviq.engine.intent import compile_intent, dry_run

_OPA = shutil.which("opa")

_INTENT = {
    "name": "support-bot",
    "class": "support-bot",
    "call": [
        {"id": "read-orders", "match": {"tool_name": {"in": ["get_order"]}}},
        {
            "id": "send-mail",
            "match": {"tool_name": {"in": ["send_email"]}},
            "require": {
                "param_paths.to": {"matches": ".*"},
                "param_paths.subject": {"matches": ".*"},
                "data_classes": {"noneOf": ["secret"]},
            },
        },
    ],
}


def _call(tool: str, params: dict | None = None) -> dict:
    return _policy_input(tool, params or {}, "support-bot", "agents")


def test_the_compiler_marks_exactly_the_predicates_that_read_argument_values() -> None:
    compiled = compile_intent(_INTENT)
    assert compiled.value_labels["read-orders"] == ()
    assert set(compiled.value_labels["send-mail"]) == {
        "param_paths.to matches .*",
        "param_paths.subject matches .*",
        "data_classes noneOf ['secret']",
    }
    # The tool name, the plane and the engine-availability guards are not value predicates: a failure
    # on any of them is a real refusal whatever the arguments were.
    for label in compiled.labels["send-mail"]:
        if label.startswith(("tool_name", "direction", "param_paths is published", "data_classes is published")):
            assert label not in compiled.value_labels["send-mail"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_value_less_call_refused_only_on_argument_predicates_cannot_be_evaluated() -> None:
    """Two rules, so the near miss names the WRONG one: `read-orders` fails one clause (the tool
    name), `send-mail` fails two (both argument values). Only the module's full `_failed` map shows
    that `send-mail` is waiting on values; reading the closest rule alone would call it a block."""
    report = dry_run(_INTENT, [_call("send_email")], values_missing=[True])
    assert (report.would_block, report.cannot_evaluate, report.would_allow) == (0, 1, 0)
    assert report.unevaluated == {"send-mail": 1}
    assert "send-mail" not in report.unused_rules
    out = report.as_dict()
    assert out["cannot_evaluate"] == 1
    assert out["blocked"] == []
    assert out["unevaluable"][0]["tool_name"] == "send_email"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_same_call_with_its_values_known_is_still_a_block() -> None:
    """Control for the test above. A call the caller says had no arguments at all is replayed
    exactly, so the policy really does refuse it."""
    report = dry_run(_INTENT, [_call("send_email")], values_missing=[False])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)
    assert report.unused_rules == ["read-orders", "send-mail"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_value_less_call_to_a_tool_no_rule_names_is_still_a_block() -> None:
    """No rule names `delete_record`, so every rule fails on the tool name. Values would not change
    that, and hiding it under 'cannot evaluate' would turn a real refusal into a shrug."""
    report = dry_run(_INTENT, [_call("delete_record")], values_missing=[True])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_value_bearing_call_that_fails_an_argument_predicate_is_a_block() -> None:
    report = dry_run(_INTENT, [_call("send_email", {"to": "a@acme.com"})], values_missing=[False])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)
    assert report.unevaluable == []


def test_without_the_failed_map_the_closest_rule_is_the_evidence() -> None:
    """An evaluator that returns only decision/rule_id/reason. The near miss is then the only view of
    which clauses failed, and it is enough when the closest rule is the one waiting on values."""
    def _ev(_rego: str, _payload: dict) -> dict:
        return {
            "decision": "block",
            "rule_id": "intent_no_match",
            "reason": "no intent rule matched; closest send-mail met 7/8, failed: param_paths.to matches .*",
        }

    report = dry_run(_INTENT, [_call("send_email")], evaluator=_ev, values_missing=[True])
    assert (report.would_block, report.cannot_evaluate) == (0, 1)
    # ...and the same sentence on a call whose values were recorded is a block.
    report = dry_run(_INTENT, [_call("send_email")], evaluator=_ev, values_missing=[False])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)


def test_values_missing_is_ignored_for_an_allowed_call() -> None:
    def _ev(_rego: str, _payload: dict) -> dict:
        return {"decision": "allow", "rule_id": "read-orders", "reason": "allowed by intent rule read-orders"}

    report = dry_run(_INTENT, [_call("get_order")], evaluator=_ev, values_missing=[True])
    assert (report.would_allow, report.would_block, report.cannot_evaluate) == (1, 0, 0)


# --- derived.verb: name-only for most tools, a fact about the arguments for some ---------------------
#
# `classify_tool` takes the verb from the payload when the tool's name says nothing (`acme_widget`) or
# when a run qualifier governs it (`run_query`). Replayed without values, such a call publishes the
# NAME's verb (`unknown`, or `read`) instead of the real one. A rule asking for `verb == "read"` then
# refuses `acme_widget` whatever the real call carried, and that refusal is a fact about the log.

_VERB_INTENT = {
    "name": "reader",
    "class": "reader",
    "call": [{"id": "reads", "match": {"verb": "read"}}],
}


def test_the_compiler_marks_verb_predicates_apart_from_value_predicates() -> None:
    compiled = compile_intent(_VERB_INTENT)
    assert compiled.verb_labels["reads"] == ("verb == read",)
    assert compiled.value_labels["reads"] == ()


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_value_less_call_whose_verb_comes_from_its_payload_cannot_be_evaluated() -> None:
    report = dry_run(_VERB_INTENT, [_call("acme_widget")], values_missing=[True])
    assert (report.would_block, report.cannot_evaluate) == (0, 1)
    assert report.unevaluated == {"reads": 1}


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_value_less_call_whose_name_fixes_the_verb_is_still_a_block() -> None:
    """`delete_record` is `delete` whatever its arguments, so the refusal is real."""
    report = dry_run(_VERB_INTENT, [_call("delete_record")], values_missing=[True])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_payload_verb_call_with_values_known_is_judged() -> None:
    """Control: with values recorded the replay sees the real verb. A DROP is `delete`, so a block."""
    report = dry_run(_VERB_INTENT, [_call("acme_widget", {"q": "drop table orders"})], values_missing=[False])
    assert (report.would_block, report.cannot_evaluate) == (1, 0)
