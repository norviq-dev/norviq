# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The shipped deny-by-default allowlist template, attacked.

"Only these SQL statements may run, block everything else" is one of the most common real asks, and
the obvious policy — written the way the console's default template leads you to write it — fails
six ways:

    default decision = "allow"
    decision = "block" { input.tool_name == "execute_sql"
                         not allowed[input.tool_params.query] }

  BYPASSES        param named `sql` not `query`; a renamed `run_report`; no params at all
                  (undefined body -> rule never fires -> default allow)
  FALSE-POSITIVES lowercase; trailing whitespace; trailing semicolon

The bypasses let unapproved SQL through. The false-positives block legitimate traffic, which is what
gets a policy switched off in week one — so they are pinned just as hard here.

This suite runs the SHIPPED template against all of them, with `derived` computed by the real engine
helper (not a fixture), so the template and the engine cannot drift apart silently.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from norviq.engine.evaluator import OPAEvaluator

_OPA = shutil.which("opa")
_TEMPLATE = Path(__file__).resolve().parents[2] / "policies" / "templates" / "sql-allowlist-deny-by-default.rego"

# The template's allowlist: "select * from orders", "select id, status from shipments".
_CASES = [
    # (label, tool, params, expected)
    ("exact_allowed_query", "execute_sql", {"query": "SELECT * FROM orders"}, "allow"),
    ("second_allowed_query", "execute_sql", {"query": "SELECT id, status FROM shipments"}, "allow"),
    ("disallowed_delete", "execute_sql", {"query": "DELETE FROM orders"}, "block"),
    ("disallowed_but_harmless_select", "execute_sql", {"query": "SELECT * FROM salaries"}, "block"),

    # --- false-positives: these MUST stay allowed or the policy gets turned off ---------------------
    ("lowercase", "execute_sql", {"query": "select * from orders"}, "allow"),
    ("trailing_whitespace", "execute_sql", {"query": "SELECT * FROM orders "}, "allow"),
    ("trailing_semicolon", "execute_sql", {"query": "SELECT * FROM orders;"}, "allow"),
    ("collapsed_whitespace", "execute_sql", {"query": "SELECT   *   FROM   orders"}, "allow"),

    # --- bypasses: these MUST block ----------------------------------------------------------------
    ("stacked_statement", "execute_sql", {"query": "SELECT * FROM orders; DROP TABLE users"}, "block"),
    ("param_named_sql", "execute_sql", {"sql": "DROP TABLE users"}, "block"),
    ("renamed_tool", "run_report", {"query": "DROP TABLE users"}, "block"),
    ("nested_param", "execute_sql", {"payload": {"inner": {"stmt": "DROP TABLE users"}}}, "block"),
    ("no_params_at_all", "execute_sql", {}, "block"),

    # --- scope: a non-SQL tool falls through to the platform baseline, not this policy -------------
    ("non_sql_tool_out_of_scope", "search_kb", {"q": "refund window"}, "allow"),
    # An approved statement arriving on an aliased SQL tool under an unusual key is still approved.
    ("allowed_via_alias_tool_and_param", "run_query", {"sql": "select * from orders"}, "allow"),
]


def _decision(tool: str, params: dict) -> str:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    payload = {
        "tool_name": tool,
        "tool_params": params,
        "derived": ev._derived_input(SimpleNamespace(tool_name=tool, tool_params=params)),
    }
    proc = subprocess.run(
        ["opa", "eval", "--v0-compatible", "-d", str(_TEMPLATE), "-I", "data.norviq.custom.decision"],
        input=json.dumps(payload), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("label,tool,params,expected", _CASES, ids=[c[0] for c in _CASES])
def test_deny_by_default_allowlist(label: str, tool: str, params: dict, expected: str) -> None:
    got = _decision(tool, params)
    assert got == expected, f"{label}: expected {expected}, got {got}"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_template_defaults_to_block() -> None:
    """The property the whole template rests on: anything not explicitly allowed is denied. A template
    that defaulted to allow would silently permit every case its author failed to anticipate."""
    assert "default decision = \"block\"" in _TEMPLATE.read_text(encoding="utf-8")
