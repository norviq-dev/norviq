# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`input.derived` — the primitives a USER-AUTHORED policy needs and otherwise cannot reach.

The bundled presets carry their own walk/normalize/alias-match logic. A hand-written policy has no way
to call it: the engine evaluates every policy as a single self-contained module, and this OPA cannot
import across packages (the same constraint that forces comprehensive.rego and _shared/horizontal.rego
to be two copies guarded by a parity test). Shipping the primitives as INPUT sidesteps that.

Why it matters, concretely: the obvious "only these SQL statements may run" policy — written the way
the console template leads you to write it — has three bypasses and three false-positives. The
bypasses let unapproved SQL through; the false-positives block legitimate traffic, which is what gets
a policy switched off in week one. `tests/policies/test_sql_allowlist_template.py` proves the
deny-by-default template built on these fields closes all six.
"""

from __future__ import annotations

from types import SimpleNamespace

from norviq.engine.evaluator import OPAEvaluator


def _derived(tool: str, params: dict) -> dict:
    ev = OPAEvaluator.__new__(OPAEvaluator)  # only the pure helpers are exercised
    return ev._derived_input(SimpleNamespace(tool_name=tool, tool_params=params))


# --- param_values: defeats param-name renaming ------------------------------------------------------


def test_param_values_flattens_arbitrary_nesting() -> None:
    """A rule keyed on `tool_params.query` misses `tool_params.sql` — and misses a nested payload
    entirely. Every leaf string must be reachable regardless of the key that held it."""
    d = _derived("execute_sql", {"a": "one", "b": {"c": "two", "d": [{"e": "three"}]}})
    assert set(d["param_values"]) == {"one", "two", "three"}


def test_param_values_lower_is_provided_for_case_insensitive_matching() -> None:
    d = _derived("x", {"k": "MiXeD"})
    assert d["param_values_lower"] == ["mixed"]


def test_non_string_leaves_are_dropped_not_stringified() -> None:
    """Numbers/bools must not become matchable text — `1` should never satisfy a substring rule."""
    d = _derived("x", {"n": 42, "b": True, "s": "real"})
    assert d["param_values"] == ["real"]


# --- tool_kind: defeats tool renaming ---------------------------------------------------------------


def test_renamed_sql_tool_is_still_classified_sql() -> None:
    """The bypass: a rule keyed on `tool_name == "execute_sql"` misses a renamed `run_report`."""
    for name in ("execute_sql", "run_query", "db_query", "run_report", "sales_report", "SQL"):
        assert _derived(name, {})["tool_kind"] == "sql", name


def test_unrelated_tool_is_not_classified_sql() -> None:
    for name in ("search_kb", "send_email", "delete_record"):
        assert _derived(name, {})["tool_kind"] == "other", name


# --- sql_normalized / sql_statements: defeats formatting --------------------------------------------


def test_formatting_differences_normalize_to_one_form() -> None:
    """The false-positives that get an allowlist switched off: case, padding, trailing semicolon,
    and collapsed internal whitespace must all reach the same string."""
    forms = [
        "SELECT * FROM orders",
        "select * from orders",
        "  SELECT   *   FROM   orders  ",
        "SELECT * FROM orders;",
        "select * from orders ;",
    ]
    assert {_derived("execute_sql", {"query": f})["sql_normalized"] for f in forms} == {
        "select * from orders"
    }


def test_sql_is_found_regardless_of_param_name() -> None:
    """The statement is located by its SHAPE, not by the key it arrived under."""
    for key in ("query", "sql", "statement", "q", "anything"):
        assert _derived("execute_sql", {key: "SELECT 1"})["sql_normalized"] == "select 1"


def test_stacked_statements_are_split_so_an_allowlist_sees_all_of_them() -> None:
    """`SELECT ...; DROP TABLE users` must not pass by having an approved FIRST statement."""
    d = _derived("execute_sql", {"query": "SELECT * FROM orders; DROP TABLE users"})
    assert d["sql_statements"] == ["select * from orders", "drop table users"]


def test_no_sql_yields_empty_not_missing() -> None:
    """Absent SQL must be an empty string/list, never a missing key — a missing key makes a Rego rule
    body undefined, which silently falls through to the policy default."""
    d = _derived("search_kb", {"q": "refund window"})
    assert d["sql_normalized"] == ""
    assert d["sql_statements"] == []


def test_empty_params_are_safe() -> None:
    """`execute_sql` with no params at all — the shape that made the naive allowlist fail open."""
    d = _derived("execute_sql", {})
    assert d["param_values"] == []
    assert d["sql_statements"] == []
    assert d["tool_kind"] == "sql"  # still a SQL tool, so a deny-by-default rule still governs it


# --- contract stability ------------------------------------------------------------------------------


def test_derived_keys_are_stable() -> None:
    """User policies bind to these names; dropping or renaming one silently breaks every policy that
    reads it (a missing key makes the rule body undefined rather than raising)."""
    assert set(_derived("execute_sql", {"query": "SELECT 1"})) == {
        "verb",
        "param_values",
        "param_values_lower",
        "tool_kind",
        "sql_normalized",
        "sql_statements",
    }


def test_risk_is_deliberately_not_exposed() -> None:
    """Verb is a FACT about the call; risk is a JUDGEMENT that shifts as the registry is updated. A
    policy pinned to risk could change behaviour on an upgrade without the policy changing, so risk
    stays a console-only signal and out of the enforcement input."""
    assert "risk" not in _derived("milvus_delete", {})


def test_verb_classifies_by_operation_across_vendors() -> None:
    """The point of verb gating: express "reads only" without enumerating every vendor's tool names."""
    for tool, expected in (
        ("milvus_search", "read"),
        ("milvus_query", "read"),
        ("milvus_insert", "write"),
        ("milvus_delete", "delete"),
        ("milvus_drop_collection", "delete"),
        ("send_email", "send"),
    ):
        assert _derived(tool, {})["verb"] == expected, tool


def test_unclassified_tool_is_unknown_not_guessed_safe() -> None:
    """An unrecognised name must surface as `unknown` — a first-class value a policy can match on —
    rather than being guessed into a benign verb. Guessing safe is how a novel name gets through."""
    assert _derived("some_unknown_vendor_tool", {})["verb"] == "unknown"
