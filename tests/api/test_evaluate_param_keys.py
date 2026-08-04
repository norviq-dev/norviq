# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The audit row records the argument NAMES a call carried (`param_keys`).

WHY THIS EXISTS. An audit row recorded that `issue_refund` ran and nothing about what it ran WITH,
because arguments were persisted only under audit_capture_masked_params (default OFF, because it
stores values). So a rule proposed from recorded traffic could name tools and nothing else — and the
control that matters on a refund tool is on its ARGUMENTS. Two design partners independently shipped
a rule they believed covered a call and watched the model emit `{"txn_id": ..., "amount": 25.0}`,
which none of their predicates matched. There was no point at which the authoring surface could have
shown them the mismatch, because the mismatch was in data nothing had ever written down.

The properties under test are therefore: the names are there, the VALUES are not, the set says so
when it is incomplete, and "we did not look" is never spelled the same way as "there was nothing".
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

from norviq.api.main import create_app
from norviq.api.routers import evaluate as evaluate_route
from norviq.config import NorviqSettings, settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.decisions import PolicyDecision


class _RecordingEmitter:
    """Captures exactly what the route hands to the fire-and-forget audit emitter."""

    def __init__(self) -> None:
        self.payloads: list[dict | None] = []

    def emit(self, event, decision, payload=None) -> None:
        self.payloads.append(payload)


def _token(namespace: str = "default") -> str:
    return jwt.encode(
        {"sub": f"admin-{namespace}", "role": "admin", "namespace": namespace, "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


def _client(evaluator: object | None = None) -> tuple[TestClient, _RecordingEmitter]:
    app = create_app()

    async def _evaluate(_event):
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    if evaluator is None:
        evaluator = SimpleNamespace(evaluate=_evaluate)
    app.state.evaluator = evaluator
    emitter = _RecordingEmitter()
    app.state.emitter = emitter
    app.state.audit_hub = None
    return TestClient(app), emitter


def _evaluate(client: TestClient, tool_name: str, tool_params: dict) -> int:
    body = {
        "tool_name": tool_name,
        "tool_params": tool_params,
        "agent_identity": {
            "spiffe_id": "spiffe://norviq/ns/default/sa/agent",
            "namespace": "default",
            "agent_class": "support",
        },
        "session_id": "s",
    }
    return client.post(
        "/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {_token()}"}
    ).status_code


def _capture(tool_name: str, tool_params: dict, evaluator: object | None = None) -> dict:
    client, emitter = _client(evaluator)
    assert _evaluate(client, tool_name, tool_params) == 200
    assert len(emitter.payloads) == 1, "the route must emit exactly one audit record per call"
    return emitter.payloads[0]


# --- the moment the operators never got ---------------------------------------------------------


def test_the_numeric_argument_the_rule_forgot_is_recorded() -> None:
    """The fintech report, verbatim: `{"txn_id": "TXN-8891", "amount": 25.0}`.

    `amount` is a FLOAT. The engine's flattener publishes a path only for a STRING leaf — right for
    its own job, wrong here — so a key-set taken straight off `param_paths` would report `txn_id`,
    stay silent about `amount`, and reproduce the exact blind spot this work exists to remove: the
    argument the money moves through is the one the operator's rule never mentioned.
    """
    payload = _capture("issue_refund", {"txn_id": "TXN-8891", "amount": 25.0})
    assert payload is not None, "the audit row carried no argument names at all"
    assert payload["param_keys"] == ["amount", "txn_id"], (
        "an operator authoring a rule for issue_refund must be able to SEE that traffic carries `amount`"
    )


def test_the_legal_wildcard_arguments_are_recorded() -> None:
    """The legal report: `search_matter` with `matter_id="all"`, `q="*"`."""
    payload = _capture("search_matter", {"matter_id": "all", "q": "*"})
    assert payload["param_keys"] == ["matter_id", "q"]


def test_names_are_sorted_and_de_duplicated_across_nesting() -> None:
    """Nested arguments use the ENGINE's path grammar (dots for keys, [i] for list indices), so a
    name an operator sees here is a name the enforcement layer can actually be pinned to."""
    payload = _capture("send_report", {"filters": {"ids": ["C-91", "C-92"]}, "to": "ops@acme.com"})
    assert payload["param_keys"] == ["filters.ids[0]", "filters.ids[1]", "to"]


# --- keys only. never a value. -------------------------------------------------------------------


def test_no_value_reaches_the_row_not_even_a_masked_one() -> None:
    """`param_keys` is a schema fact. A value in it — raw, masked or truncated — is a new PII sink
    on the hot path, in a field whose whole justification is that it stores no payload data.

    THE SECOND HALF OF THIS FIXTURE IS THE POINT, and it was added by the verify pass because the
    first half alone cannot produce the state this test's NAME claims. Erasing leaves proves nothing
    about a value that arrives through a KEY, and keys are copied verbatim by design: an argument
    that is a MAP KEYED BY DATA — `{"balances": {"<pan>": 25.0}}`, `{"rows": {"<ssn>": ...}}` — put
    a PAN and an SSN into the audit row of a default install whose value capture is deliberately OFF.
    """
    secret = "sk-live-4242424242424242"
    payload = _capture(
        "charge_card",
        {
            "pan": "4111111111111111",
            "ssn": "123-45-6789",
            "api_key": secret,
            "note": "hunter2",
            # …and the same data one level over, in key position.
            "balances": {"4111111111111111": 25.0},
            "rows": {"123-45-6789": "x"},
        },
    )
    blob = repr(payload)
    for leaked in ("4111111111111111", "123-45-6789", "hunter2", secret, "sk-live"):
        assert leaked not in blob, f"a VALUE ({leaked!r}) reached the audit row through param_keys"
    # The name is still REPORTED — the argument `balances` exists and an operator must see it — it is
    # only the payload riding inside it that is masked, by the same masker the value path already uses.
    assert "balances.****1111" in payload["param_keys"]
    assert "rows.***-**-6789" in payload["param_keys"]


def test_a_name_the_masker_rewrote_is_never_offered_as_pinnable() -> None:
    """A masked name is not the path the engine derives, so it is a name to SHOW and never one to
    assert. Publishing it as pinnable would hand an author a predicate that is false on every call."""
    payload = _capture("charge_card", {"balances": {"4111111111111111": "25.00"}, "txn_id": "T-1"})
    assert "balances.****1111" in payload["param_keys"]
    assert payload["param_keys_pinnable"] == ["txn_id"]


def test_key_capture_is_independent_of_masked_value_capture(monkeypatch) -> None:
    """The default install captures NAMES and no values — that is the whole point of the split. If
    names only appeared when audit_capture_masked_params was on, the default install would still
    propose rules that can name nothing but tools."""
    monkeypatch.setattr(settings, "audit_capture_masked_params", False)
    payload = _capture("issue_refund", {"amount": 25.0})
    assert payload["param_keys"] == ["amount"]
    assert "masked_params" not in payload, "values must not be captured by the key-capture switch"


def test_param_keys_default_is_on_and_masked_capture_default_is_off() -> None:
    """Defaults are the contract: names on (no values stored), values off (values stored)."""
    loaded = NorviqSettings(_env_file=None)
    assert loaded.audit_capture_param_keys is True
    assert loaded.audit_capture_masked_params is False


# --- "nothing captured" must not look like "nothing there" ---------------------------------------


def test_a_call_with_no_arguments_records_an_empty_set_not_an_absent_one() -> None:
    """`param_keys: []` is a positive statement: we looked, the call carried nothing. It must be
    distinguishable from the field being absent, or a console cannot tell an argument-less tool from
    a tool whose arguments were never recorded — and those demand opposite reactions from an author."""
    payload = _capture("healthcheck", {})
    assert payload is not None
    assert payload["param_keys"] == []
    assert payload["param_keys_truncated"] is False
    assert payload["param_keys_ambiguous"] == []


def test_the_kill_switch_omits_the_fields_entirely(monkeypatch) -> None:
    """Operators for whom the key NAMES are themselves sensitive turn this off. Off must mean the
    field is ABSENT (readers render "not captured"), never an empty list (readers would render "this
    call carried no arguments" — a claim the row is in no position to make)."""
    monkeypatch.setattr(settings, "audit_capture_param_keys", False)
    monkeypatch.setattr(settings, "audit_capture_masked_params", False)
    payload = _capture("issue_refund", {"amount": 25.0})
    assert payload is None, "with capture off the audit payload must be exactly what it was before"


def test_a_broken_derivation_omits_the_fields_rather_than_claiming_an_empty_set(monkeypatch) -> None:
    """Two properties at once. The enrichment must never fail a tool call (it sits on the enforcement
    hot path), and a failed derivation must not degrade into the confident answer "no arguments"."""

    def boom(*_a, **_k):
        raise RuntimeError("flattener exploded")

    monkeypatch.setattr(evaluate_route, "_param_key_shadow", boom)
    payload = _capture("issue_refund", {"amount": 25.0})
    assert payload is None or "param_keys" not in payload


# --- an incomplete set must say so ---------------------------------------------------------------


def test_truncation_by_count_is_visible_and_uses_the_engines_bound() -> None:
    """An operator shown 256 of 400 argument names, believing that is all of them, is worse off than
    one shown none: they will conclude their rule covers the surface. The cap is the ENGINE's, not a
    second bound invented here — two bounds drift on the first tuning change."""
    many = {f"arg_{i:04d}": f"v{i}" for i in range(OPAEvaluator._MAX_PATHS + 150)}
    payload = _capture("bulk_update", many)
    assert payload["param_keys_truncated"] is True
    assert len(payload["param_keys"]) <= OPAEvaluator._MAX_PATHS


def test_truncation_by_depth_is_visible() -> None:
    """The count cap is not the only way the set is cut short: a subtree deeper than the engine's
    depth cap is dropped silently, and `len(param_keys)` is small and innocent-looking when it is."""
    node: dict = {"leaf": "bottom"}
    for i in range(OPAEvaluator._MAX_PATH_DEPTH + 4):
        node = {f"level_{i}": node}
    payload = _capture("deep_call", node)
    assert payload["param_keys_truncated"] is True, "a dropped subtree was reported as a complete set"
    assert not any(name.endswith("leaf") for name in payload["param_keys"])


def test_an_honest_call_is_not_reported_as_truncated() -> None:
    """The flag has to mean something. If it were set on ordinary traffic the console would warn on
    every row and operators would learn to ignore the one warning that matters."""
    payload = _capture("send_email", {"to": "ops@acme.com", "body": "x" * 512, "cc": ["a@acme.com"]})
    assert payload["param_keys_truncated"] is False


# --- a forgeable name is a trap, and must be named as one ----------------------------------------


def test_a_minted_argument_name_is_flagged_ambiguous() -> None:
    """A caller-supplied key can MINT a name some other route also reaches, and whichever the caller
    orders last wins the dict. An operator who writes a rule against such a name is being led into a
    trap by the very screen meant to protect them, so the name is listed AND named as untrustworthy —
    not dropped (the list would look shorter and more confident) and not rewritten (the screen would
    then disagree with the policy)."""
    payload = _capture(
        "send_email",
        {
            "message": {"toRecipients": [{"emailAddress": {"address": "collector@attacker.example"}}]},
            "message.toRecipients[0].emailAddress.address": "ops@acme.com",
        },
    )
    forged = "message.toRecipients[0].emailAddress.address"
    assert forged in payload["param_keys"], "the observed name must still be shown"
    assert forged in payload["param_keys_ambiguous"], "…and must be shown as one that cannot be trusted"


def test_ordinary_dotted_argument_names_are_not_flagged() -> None:
    """OpenTelemetry-style `http.method` and JSON:API `filter[status]` are ordinary arguments. If
    path SHAPE were treated as forgery every such argument would be permanently unscopable, and the
    ambiguity flag would be noise rather than a signal."""
    payload = _capture("emit_span", {"attributes": {"http.method": "GET"}, "filter[status]": "open"})
    assert payload["param_keys_ambiguous"] == []
    assert "attributes.http.method" in payload["param_keys"]


# --- the derivation is the engine's, whichever evaluator is wired --------------------------------


def test_a_real_evaluator_instance_produces_the_same_names() -> None:
    """The route prefers the live evaluator's own flattener. Same names, same grammar, same bounds —
    an operator authoring against these paths is authoring against what enforcement evaluates."""
    instance = OPAEvaluator.__new__(OPAEvaluator)

    async def _decide(_event):
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    instance.evaluate = _decide  # type: ignore[method-assign]
    payload = _capture("issue_refund", {"txn_id": "TXN-8891", "amount": 25.0}, evaluator=instance)
    assert payload["param_keys"] == ["amount", "txn_id"]


def test_an_unbound_flattener_falls_back_instead_of_failing_every_request() -> None:
    """`callable()` is not the test. An `app.state.evaluator` holding the CLASS (or any unbound
    function) passes it and then gets the params as its own `self` — failing on every request, and
    failing INVISIBLY, because the safe branch writes nothing and a console renders nothing as "this
    call carried no arguments". The fallback has to catch that, not just a missing attribute."""

    async def _decide(_event):
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    class _ClassAsEvaluator:
        _walk_paths = OPAEvaluator._walk_paths          # unbound: takes (self, node)
        _MAX_PATHS = OPAEvaluator._MAX_PATHS
        _MAX_PATH_DEPTH = OPAEvaluator._MAX_PATH_DEPTH
        evaluate = staticmethod(_decide)

    payload = _capture("issue_refund", {"amount": 25.0}, evaluator=_ClassAsEvaluator)
    assert payload["param_keys"] == ["amount"]


def test_names_match_the_paths_the_engine_publishes_for_string_arguments() -> None:
    """One notion of an argument path, not two: for the string arguments `_walk_paths` does emit,
    the captured names are exactly its keys."""
    params = {"filters": {"ids": ["C-91"]}, "to": "ops@acme.com", "nested": {"a": {"b": "c"}}}
    engine_paths, _ambiguous = OPAEvaluator._walk_paths(OPAEvaluator, params)
    payload = _capture("send_report", params)
    assert payload["param_keys"] == sorted(engine_paths)


# --- a name being OBSERVED is not the same fact as a rule being able to CONSTRAIN it -------------


def test_the_numeric_argument_is_shown_but_never_offered_as_pinnable() -> None:
    """The fintech payload again, asking the question the first test does not: now that `amount` is
    visible, may a rule be pinned to it?

    No. `param_keys` is type-ERASED so that `amount` gets named at all, which loses the fact that it
    was a NUMBER — and at enforcement time `input.derived.param_paths` carries STRING leaves only.
    The compiler AND-s every `param_paths.*` predicate with
    `object.get(input.derived.param_paths, "amount", null) != null`, false on every call carrying a
    numeric amount. Under `default decision = "block"` an intent is a set of ALLOW arms, so a rule
    pinned on `amount` refuses EVERY call to issue_refund — a total outage the operator did not
    author, and one the dry run cannot surface, because a replay over key-only rows has no
    `param_paths` at all and blocks the sound predicates too.

    So the row separates the two facts. Show everything; assert only `param_keys_pinnable`.
    """
    payload = _capture("issue_refund", {"txn_id": "TXN-8891", "amount": 25.0})
    assert payload["param_keys"] == ["amount", "txn_id"], "both names must be VISIBLE"
    assert payload["param_keys_pinnable"] == ["txn_id"], (
        "`amount` has no path at enforcement time; offering it as pinnable authorises a rule that "
        "can never fire"
    )


def test_the_pinnable_set_is_exactly_what_the_engine_derives_from_real_values() -> None:
    """Pinnability is not a second opinion about paths: it is the engine's own answer, taken from
    the leaf TYPE the flattener already reported, so it moves if `_walk_paths` moves."""
    params = {"to": "ops@acme.com", "amount": 25.0, "retries": 3, "meta": {"ref": "R-1", "n": None},
              "ids": ["C-91", "C-92"]}
    engine_paths, engine_ambiguous = OPAEvaluator._walk_paths(OPAEvaluator, params)
    payload = _capture("send_report", params)
    assert payload["param_keys_pinnable"] == sorted(set(engine_paths) - set(engine_ambiguous))
    # …and every name the engine cannot derive is still SHOWN, just not offered.
    assert set(payload["param_keys"]) - set(payload["param_keys_pinnable"]) == {
        "amount", "retries", "meta.n"
    }


def test_a_forged_name_is_shown_but_never_pinnable() -> None:
    """The forgeable name is the one an operator is most likely to pin, because it looks the most
    specific. It is listed, flagged, and kept out of the set a rule may be built from."""
    payload = _capture(
        "send_email",
        {
            "message": {"toRecipients": [{"emailAddress": {"address": "collector@attacker.example"}}]},
            "message.toRecipients[0].emailAddress.address": "ops@acme.com",
        },
    )
    forged = "message.toRecipients[0].emailAddress.address"
    assert forged in payload["param_keys"]
    assert forged in payload["param_keys_ambiguous"]
    assert forged not in payload["param_keys_pinnable"]


def test_the_pinnable_set_is_always_a_subset_of_the_names_and_always_written() -> None:
    """The POSITIVE set is published rather than its complement, and it is written whenever names
    are. A reader that finds it absent must pin nothing; a reader subtracting an absent "unpinnable"
    list would treat every observed name as safe to assert — the same "unknown spelled as compliant"
    the rest of this file exists to prevent."""
    for params in ({}, {"a": "x"}, {"a": 1}, {"a": {"b": ["x", 2]}}):
        payload = _capture("t", params)
        assert "param_keys_pinnable" in payload, "the fact must be present even when it is empty"
        assert set(payload["param_keys_pinnable"]) <= set(payload["param_keys"])


# --- the capture may not become a lever on the enforcement hot path ------------------------------


def test_empty_containers_cannot_make_the_capture_walk_the_whole_body() -> None:
    """A leaf budget bounds nothing when the body carries no leaves.

    `{"a": [[], [], ...]}` costs zero leaves, so a leaves-only cap let this derivation walk — and
    MATERIALISE a copy of — an entire request body: measured at 1.7 s and 26 MB for ~1 MB of JSON,
    synchronously, on the enforcement path, which is an availability defect aimed at every other
    request in flight rather than at the caller. The node budget is the engine's own two bounds
    multiplied (a kept leaf has at most `_MAX_PATH_DEPTH` ancestors and there are at most
    `_MAX_PATHS` of them), so nothing that could still contribute a name is lost — and what IS
    dropped is reported, because a caller who can shrink the key-set must not also be able to make
    the remains look complete.
    """
    import time as _time

    hostile = {"a": [[] for _ in range(300_000)]}
    started = _time.perf_counter()
    keys, ambiguous, pinnable, truncated = evaluate_route._param_key_set(
        OPAEvaluator.__new__(OPAEvaluator), hostile
    )
    elapsed = _time.perf_counter() - started
    assert truncated is True, "work was dropped and the row would have called the result complete"
    assert keys == [] and pinnable == []
    assert elapsed < 0.4, f"derivation is not bounded by the engine's caps: took {elapsed:.2f}s"


@pytest.mark.parametrize(
    "params,expected",
    [
        ({"flag": True}, ["flag"]),
        ({"count": 0}, ["count"]),
        ({"ratio": 1.5}, ["ratio"]),
        ({"missing": None}, ["missing"]),
        ({"amounts": [1, 2]}, ["amounts[0]", "amounts[1]"]),
    ],
)
def test_non_string_arguments_are_named(params: dict, expected: list[str]) -> None:
    """Every one of these is invisible to `param_paths`, and every one of them is an argument an
    operator may need to constrain."""
    assert _capture("t", params)["param_keys"] == expected
