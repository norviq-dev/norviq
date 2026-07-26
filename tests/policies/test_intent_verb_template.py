# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Intent policy by VERB — "allow reads on the vector store, block the rest".

Gating on what a call DOES rather than what the tool is CALLED. A tool-name allowlist is brittle in
the dangerous direction under deny-by-default: a missed alias (`milvus_hybrid_search`) does not leak,
it locks out legitimate traffic — the failure that gets a policy switched off in week one.

`unknown` is a first-class matchable value so a policy states what happens to unclassified tools
instead of leaving it implicit. It must ESCALATE, never allow: classification keys on the tool NAME,
which the agent side controls, so `allow { verb == "unknown" }` is a universal bypass.
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
_T = Path(__file__).resolve().parents[2] / "policies" / "templates" / "read-only-intent-deny-by-default.rego"

_CASES = [
    ("read_search_allowed", "milvus_search", "allow"),
    ("read_query_allowed", "milvus_query", "allow"),
    ("write_blocked", "milvus_insert", "block"),
    ("delete_blocked", "milvus_delete", "block"),
    ("drop_collection_blocked", "milvus_drop_collection", "block"),
    # The alias a tool-name allowlist would have missed — verb gating catches it without enumeration.
    ("unclassified_escalates_not_blocks", "milvus_weird_new_tool", "escalate"),
    # Out of scope: falls through to the platform baseline rather than the default deny.
    ("unscoped_tool_falls_through", "search_kb", "allow"),
    ("unscoped_egress_falls_through", "send_email", "allow"),
]


def _decision(tool: str) -> str:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    payload = {
        "tool_name": tool,
        "tool_params": {},
        "derived": ev._derived_input(SimpleNamespace(tool_name=tool, tool_params={})),
    }
    proc = subprocess.run(
        ["opa", "eval", "--v0-compatible", "-d", str(_T), "-I", "data.norviq.custom.decision"],
        input=json.dumps(payload), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("label,tool,expected", _CASES, ids=[c[0] for c in _CASES])
def test_intent_by_verb(label: str, tool: str, expected: str) -> None:
    assert _decision(tool) == expected, label


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_template_never_allows_unknown() -> None:
    """The bypass this guards: `allow { verb == "unknown" }` permits anything named unrecognisably."""
    src = _T.read_text(encoding="utf-8")
    assert 'default decision = "block"' in src
    # Strip comments first: the template deliberately QUOTES `allow { verb == "unknown" }` in its
    # security note explaining why not to write it, and a naive scan matches that prose instead of a
    # rule. Analyse code only.
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    allow_blocks = [b for b in code.split("decision = ") if b.startswith('"allow"')]
    assert not any('verb == "unknown"' in b for b in allow_blocks), "unknown must never map to allow"
    # ...and it must be handled explicitly rather than falling through to the default.
    assert 'verb == "unknown"' in code, "unknown must be an explicit, matchable branch"
