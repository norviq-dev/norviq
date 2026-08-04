# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The perimeter: a registration-based tool allowlist, which is the only thing that holds against a
deliberately unrecognisable tool name.

The intent template (read-only-intent-deny-by-default.rego) gates on what a call DOES, scoped to a
system by tool-name prefix. That is correct for expressing intent, but it is NOT a perimeter: a tool
named outside the prefix falls through to the baseline ungoverned by it —

    milvus_zzz_obscure -> escalate   (in scope, handled)
    zzz_exfil          -> allow      (out of scope, escapes)

`zzz_exfil` was chosen for that example when the lexicon did not recognise it. It now classifies as
send/high, because "exfil" was added to the egress lexicon. That does not soften the argument — it
sharpens it. The perimeter never depended on the classifier, and a name one lexicon entry away from
the same escape (`xyzzy_plugh`, below) is still trivially available to the agent side.

No lexicon fixes that, because the tool NAME is chosen by the agent side. This template inverts the
question: a tool is permitted because a human listed it, so a novel name FAILS the list rather than
routing around a classifier. `input.derived.verb` is still recorded on denials — `unknown` on a denied
call is what probing with novel names looks like, and it gets its own rule_id so it can be alerted on.
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
_T = Path(__file__).resolve().parents[2] / "policies" / "templates" / "tool-allowlist-perimeter.rego"


def _eval(tool: str) -> dict:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    payload = {
        "tool_name": tool,
        "tool_params": {},
        "derived": ev._derived_input(SimpleNamespace(tool_name=tool, tool_params={})),
    }
    proc = subprocess.run(
        ["opa", "eval", "--v0-compatible", "-d", str(_T), "-I", "data.norviq.custom"],
        input=json.dumps(payload), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


def _derived_verb(tool: str) -> str:
    """The verb on the INPUT document. The policy's output does not echo `derived`, so asserting
    `_eval(t)["derived"]` would raise rather than check — read it from where it is actually set."""
    ev = OPAEvaluator.__new__(OPAEvaluator)
    return ev._derived_input(SimpleNamespace(tool_name=tool, tool_params={})).get("verb", "")


# The exact names that escaped the intent template — the regression this file exists for.
# `xyzzy_plugh` is deliberately unclassifiable and carries the property `zzz_exfil` used to: it is
# the input that proves denial does not require the classifier to have understood anything.
_ESCAPES = ["zzz_exfil", "x1", "do_thing", "vector_purge_all", "milvus_zzz_obscure", "xyzzy_plugh"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("tool", _ESCAPES)
def test_unrecognisable_names_are_denied(tool: str) -> None:
    """Denied for not being LISTED — no classification required, so renaming cannot help."""
    assert _eval(tool)["decision"] == "block", tool


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("tool", ["search_kb", "get_order", "get_customer", "milvus_search", "milvus_query"])
def test_listed_tools_are_allowed(tool: str) -> None:
    assert _eval(tool)["decision"] == "allow", tool


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("tool", ["milvus_delete", "milvus_insert", "send_email", "execute_sql"])
def test_unlisted_but_classified_tools_are_denied(tool: str) -> None:
    """Being classifiable is not permission — only the list grants it."""
    assert _eval(tool)["decision"] == "block", tool


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_unclassified_denial_is_separately_identifiable() -> None:
    """`unknown` on a DENIED call is the probing signal. It must not render identically to an ordinary
    uncovered tool, or it is lost in the noise — the one place where "we could not classify this" is
    itself the interesting fact."""
    # The input must actually BE unclassified, or this asserts nothing about the branch it names.
    # `zzz_exfil` held that property until "exfil" entered the egress lexicon; it now classifies as
    # send, so it moved to the other branch and is asserted there instead.
    assert _derived_verb("xyzzy_plugh") == "unknown"
    assert _eval("xyzzy_plugh")["rule_id"] == "tool_allowlist_perimeter_unclassified"
    # A denied call the classifier DID understand keeps the plain rule_id.
    assert _eval("milvus_delete")["rule_id"] == "tool_allowlist_perimeter"
    assert _eval("zzz_exfil")["rule_id"] == "tool_allowlist_perimeter"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_template_defaults_to_block() -> None:
    """The property the perimeter rests on. A default of allow would make the list decorative."""
    assert 'default decision = "block"' in _T.read_text(encoding="utf-8")
