# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""The near miss, as data rather than as a sentence.

A denial that says only "no rule matched" is the absence of a rule — nothing an operator can act on.
The compiler already formats a sentence naming the closest rule, how many of its clauses were met, and
which failed. This decomposes that sentence so a console can tick each clause off individually.

The decomposition lives here, next to the `sprintf` that produces the string, for the reason the
module docstring gives for the replay itself: a second implementation in another language would drift
from this one, and the drifted one would be what the operator was shown before they approved.

`test_the_console_can_reconcile_met_n_of_m` is the guard. It runs a real intent through real OPA and
asserts the published clause list adds up against the `met M/N` in the same reason — so the moment the
compiler changes a label or adds a predicate, this fails rather than the console silently rendering a
tick-list that contradicts its own headline.
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
from norviq.engine.intent import compile_intent
from norviq.engine.intent.dryrun import dry_run, split_failed_labels

_OPA = shutil.which("opa")

_INTENT = {
    "name": "support-bot-intent",
    "class": "support-bot",
    "call": [
        {
            "id": "send-send-email",
            "match": {"verb": "send", "param_paths.to": {"matches": r"^[^@]+@acme\.com$"}},
            "require": {"data_classes": {"noneOf": ["secret"]}},
        },
    ],
}


def _call(tool: str, params: dict) -> dict:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    return {
        "tool_name": tool,
        "tool_params": params,
        "derived": ev._derived_input(SimpleNamespace(tool_name=tool, tool_params=params)),
        "trust_category": "high",
        "mcp": {},
        "agent": {"agent_class": "support-bot", "namespace": "agents"},
    }


def _opa_evaluator(rego: str, payload: dict) -> dict:
    package = re.search(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*$", rego).group(1)
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "intent.rego"
        path.write_text(rego, encoding="utf-8")
        for key in ("decision", "rule_id", "reason"):
            proc = subprocess.run(
                ["opa", "eval", "--v0-compatible", "-d", str(path), "-I", f"data.{package}.{key}"],
                input=json.dumps(payload), capture_output=True, text=True, check=True,
            )
            result = json.loads(proc.stdout).get("result") or []
            out[key] = result[0]["expressions"][0]["value"] if result else None
    return out


# =====================================================================================================
# split_failed_labels — the part a naive split gets wrong
# =====================================================================================================

def test_a_label_containing_a_comma_survives():
    """`tool_name in ['a', 'b']` contains the very separator the labels are joined with.

    `joined.split(", ")` shreds one clause into three, none of which matches a real predicate — and
    the resulting count then contradicts the `met M/N` printed in the same sentence.
    """
    candidates = ["direction == call", "tool_name in ['run_query', 'send_email']", "verb == send"]
    joined = "direction == call, tool_name in ['run_query', 'send_email']"
    assert split_failed_labels(candidates, joined) == [
        "direction == call",
        "tool_name in ['run_query', 'send_email']",
    ]
    assert len(joined.split(", ")) == 3  # what the naive form would have produced


def test_one_label_that_prefixes_another_resolves_to_the_longer():
    # Longest-first matching is not an optimisation: `x in [1]` is a strict prefix of `x in [1, 2]`,
    # so shortest-first would consume the wrong clause and leave unparseable text behind.
    candidates = ["x in [1]", "x in [1, 2]"]
    assert split_failed_labels(candidates, "x in [1, 2]") == ["x in [1, 2]"]


def test_unaccountable_text_yields_nothing_rather_than_a_partial_list():
    """A clause wrongly shown as PASSED is a restriction the operator believes is in force.

    Half a parse is worse than none here, so anything unrecognised collapses the whole result. The
    caller then falls back to the raw sentence.
    """
    assert split_failed_labels(["a == 1"], "a == 1, something the compiler never emitted") == []


def test_an_empty_tail_is_no_failures():
    assert split_failed_labels(["a == 1"], "") == []
    assert split_failed_labels(["a == 1"], "   ") == []


# =====================================================================================================
# End to end, through real OPA
# =====================================================================================================

@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_console_can_reconcile_met_n_of_m():
    """Every clause the rule asserts is published, and the arithmetic closes.

    This is the acceptance criterion for the near-miss card: the operator sees a tick beside each
    clause that held and a cross beside the one that did not, and the ticks plus crosses equal the
    "met 3 of 4" in the heading. It only closes if the compiler-added predicates — the plane, and the
    availability guard for a version-gated root — are published too.
    """
    compiled = compile_intent(_INTENT)
    # A send to a NON-acme recipient: the tool and plane hold, the recipient regex does not.
    calls = [_call("send_email", {"to": "ops@contractor.io", "body": "hi"})]
    report = dry_run(compiled, calls, evaluator=_opa_evaluator)

    assert report.would_block == 1
    blocked = report.blocked[0]
    assert blocked.closest_rule == "send-send-email"
    # The arithmetic the card's heading claims.
    assert blocked.met + len(blocked.failed) == len(blocked.predicates)
    assert f"met {blocked.met}/{len(blocked.predicates)}" in blocked.reason
    # Every failed clause is one the rule actually asserts — not a fragment of one.
    assert set(blocked.failed) <= set(blocked.predicates)
    assert any("param_paths.to matches" in f for f in blocked.failed)
    # And the compiler-added clauses are present, or the count could never have closed.
    assert any(p.startswith("direction ==") for p in blocked.predicates)


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_dict_the_api_returns_carries_the_clause_list():
    compiled = compile_intent(_INTENT)
    calls = [_call("send_email", {"to": "ops@contractor.io"})]
    out = dry_run(compiled, calls, evaluator=_opa_evaluator).as_dict()

    row = out["blocked"][0]
    assert row["closest_rule"] == "send-send-email"
    assert isinstance(row["predicates"], list) and row["predicates"]
    assert isinstance(row["failed"], list) and row["failed"]
    assert row["met"] + len(row["failed"]) == len(row["predicates"])
    # The sentence is still there: a console that does not use the structured form loses nothing.
    assert "closest send-send-email" in row["reason"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_an_allowed_call_publishes_no_near_miss():
    # There is no "closest rule" for a call that matched one; an empty list is the honest answer.
    compiled = compile_intent(_INTENT)
    calls = [_call("send_email", {"to": "kate@acme.com"})]
    report = dry_run(compiled, calls, evaluator=_opa_evaluator)
    assert report.would_block == 0
    assert report.blocked == []


def test_a_reason_that_does_not_parse_publishes_nothing_rather_than_guessing():
    """A stub evaluator returning an unrecognised reason must not produce a half-filled card.

    The fallback is the raw sentence, which is what the screen showed before this existed — degraded,
    but never contradicting itself.
    """
    compiled = compile_intent(_INTENT)

    def _stub(_rego: str, _payload: dict) -> dict:
        return {"decision": "block", "rule_id": "intent_no_match", "reason": "something else entirely"}

    report = dry_run(compiled, [_call("send_email", {"to": "x@y.z"})], evaluator=_stub)
    blocked = report.blocked[0]
    assert blocked.closest_rule == ""
    assert blocked.predicates == ()
    assert blocked.reason == "something else entirely"
