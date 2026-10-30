# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every Rego generator's EMPTY-input output compiles — on OPA 1.19 and on 1.21+.

OPA 1.21 types a bare `{}`, `set()` or `[]` as a collection with no members, so a lookup into one is
`rego_type_error: undefined ref`. The generators below each produced such a literal from an empty
operator list, and on 1.21 each such module failed to compile, failing every call it governs closed as
`evaluator_error`. norviq/engine/empty_literals.py holds the typed forms that replaced them.

The compile check uses the engine's own pre-push gate — `opa check --v0-compatible` against the shipped
capabilities file, exactly what `opa_client._check_capabilities` runs — with whatever `opa` is on PATH,
so CI checks the pinned binary. The text guard below needs no binary at all, so a machine still
carrying 1.19 (on which every bare literal compiles) cannot pass a regression.

The console's own generators (builder, composer) are checked the same way in
ui/src/lib/emptyLiterals.test.ts; their constants are pinned to these ones here.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.api import baseline, egress_allowlist, mcp_controls
from norviq.api.threat_intent import (
    Intent,
    generate_capability_rego,
    generate_intent_rego,
    generate_remediation_overlay_rego,
    generate_remediation_rego,
)
from norviq.engine.capability import Verb, defense_meta, verb_fragments
from norviq.engine.empty_literals import EMPTY_ARRAY, EMPTY_OBJECT, EMPTY_SET
from norviq.engine.intent.compiler import compile_intent

REPO = Path(__file__).resolve().parents[2]
CAPABILITIES = REPO / "norviq" / "engine" / "opa-capabilities.json"
_OPA = shutil.which("opa")
needs_opa = pytest.mark.skipif(_OPA is None, reason="opa binary required to compile generated rego")


def _capability(frags: bool) -> str:
    meta = defense_meta("postgresql", [Verb.WRITE, Verb.DELETE])
    return generate_capability_rego(
        "postgresql",
        "PostgreSQL",
        "etl-loader",
        meta["verbs"],
        [],
        meta["rule_id"],
        meta["reason"],
        verb_frags=verb_fragments("postgresql", [Verb.WRITE, Verb.DELETE]) if frags else None,
    )


def _intent_compiled(op: str) -> str:
    field = "tool_name" if op == "in" else "data_classes"
    return compile_intent(
        {"name": "empty", "class": "support", "call": [{"id": "r1", "match": {field: {op: []}}}]}
    ).rego


def _baseline(effect: str) -> str:
    return baseline.compile("strict", {cid: effect for cid in baseline.control_ids("strict")})


# Every generator that builds a collection out of operator data, at the input that leaves it empty.
# The two remediation generators have no empty case (they refuse an empty rule list); their smallest
# input is here so the list really is every generator.
GENERATED: dict[str, callable] = {
    "capability: no observed tool": lambda: _capability(frags=True),
    "capability: no observed tool, no verb fragments": lambda: _capability(frags=False),
    "intent allowlist: no tools": lambda: generate_intent_rego("support", [], Intent()),
    "intent allowlist: no tools, every refinement": lambda: generate_intent_rego(
        "support", [], Intent(readonly=True, egress=True, scope=True, rate=True)
    ),
    "intent allowlist: learned verbs for tools outside the (empty) allowlist": lambda: generate_intent_rego(
        "support", [], Intent(readonly=True, egress=True), learned_verbs={"get_x": "read", "post_x": "send"}
    ),
    "mcp registry: empty": lambda: mcp_controls.compile([], []),
    "mcp registry: no writable server": lambda: mcp_controls.compile(["kb"], []),
    "egress allowlist: empty": lambda: egress_allowlist.compile([]),
    "egress allowlist: exact hosts only (no suffix)": lambda: egress_allowlist.compile(["acme.com"]),
    "egress allowlist: suffixes only (no exact host)": lambda: egress_allowlist.compile([".acme.com"]),
    "intent compiler: in []": lambda: _intent_compiled("in"),
    "intent compiler: subsetOf []": lambda: _intent_compiled("subsetOf"),
    "intent compiler: noneOf []": lambda: _intent_compiled("noneOf"),
    "intent compiler: anyOf []": lambda: _intent_compiled("anyOf"),
    "baseline: every control off": lambda: _baseline("off"),
    "baseline: every control monitor": lambda: _baseline("monitor"),
    "remediation: one control": lambda: generate_remediation_rego(
        "owasp", "LLM06", "Excessive agency", "support", ["llm06_excessive_agency"]
    ),
    "remediation overlay: one control": lambda: generate_remediation_overlay_rego(
        "support",
        [
            {
                "framework": "owasp",
                "control_id": "LLM06",
                "control_name": "Excessive agency",
                "rule_ids": ["llm06_excessive_agency"],
            }
        ],
    ),
}

# A bare empty literal on the right of an assignment, or iterated in place. `object.get(x, k, [])` is
# not one of these: its result is typed `any` and both versions accept it.
_BARE_EMPTY = re.compile(r"(?:^|\s)(?::=|=)\s*(?:\{\}|\[\]|set\(\))\s*$|\[\]\[_\]|set\(\)\[_\]|\bset\(\)")


def _opa_check(rego: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego, encoding="utf-8")
        return subprocess.run(
            ["opa", "check", "--v0-compatible", f"--capabilities={CAPABILITIES}", str(path)],
            capture_output=True,
            text=True,
        )


@needs_opa
@pytest.mark.parametrize("name", sorted(GENERATED))
def test_the_empty_input_output_passes_the_engines_pre_push_gate(name: str) -> None:
    proc = _opa_check(GENERATED[name]())
    assert proc.returncode == 0, (
        f"{name}: the module a generator writes for an EMPTY input does not compile on this opa "
        f"({_opa_version()}). Every call it governs would fail closed as evaluator_error.\n"
        f"{proc.stdout}{proc.stderr}"
    )


@pytest.mark.parametrize("name", sorted(GENERATED))
def test_no_generator_writes_a_bare_empty_literal(name: str) -> None:
    """The guard that does not depend on the binary: 1.19 compiles every one of these."""
    offenders = [
        line.strip()
        for line in GENERATED[name]().splitlines()
        if not line.lstrip().startswith("#") and _BARE_EMPTY.search(line)
    ]
    assert not offenders, f"{name} emits a bare empty literal, a type error on OPA 1.21: {offenders}"


@needs_opa
@pytest.mark.parametrize(
    ("typed", "bare", "kind"),
    [(EMPTY_OBJECT, "{}", "is_object"), (EMPTY_SET, "set()", "is_set"), (EMPTY_ARRAY, "[]", "is_array")],
)
def test_a_typed_form_is_the_same_value_and_kind_as_the_literal_it_replaces(typed: str, bare: str, kind: str) -> None:
    """Same value, same kind, and it can be read from — which is the only thing the bare one could not do.

    `{}` is an empty OBJECT, so its replacement must be one too: the evaluator queries the whole package
    document, so a set in its place would change what OPA returns (`[]` instead of `{}`).
    """

    def evaluate(module: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.rego"
            path.write_text(module, encoding="utf-8")
            out = subprocess.run(
                ["opa", "eval", "--v0-compatible", "-d", str(path), "-I", "-f", "json", "data.t"],
                input=json.dumps({"k": "x"}),
                capture_output=True,
                text=True,
                check=True,
            )
            return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]

    # `count` and `is_*` are accepted over a bare literal on both versions, so the bare form is
    # evaluated without a lookup and compared with the typed form's answers.
    shape = "v := {lit}\nn := count(v)\nkind := {kind}(v)\n"
    bare_doc = evaluate("package t\n" + shape.format(lit=bare, kind=kind))
    typed_doc = evaluate(
        "package t\n"
        + shape.format(lit=typed, kind=kind)
        + "hit { v[input.k] }\nmiss { not v[input.k] }\nany_member { v[_] }\n"
    )
    assert {k: typed_doc[k] for k in ("v", "n", "kind")} == bare_doc == {"v": bare_doc["v"], "n": 0, "kind": True}
    # The lookups the bare form cannot compile: nothing is a member, and a negated lookup holds.
    assert "hit" not in typed_doc and "any_member" not in typed_doc and typed_doc["miss"] is True


def test_the_console_uses_the_same_typed_forms() -> None:
    """ui/src/lib/emptyLiterals.ts must emit byte-identical forms, and its never-firing partial-set
    rule must be baseline.py's — two spellings of one idea are how parsers start disagreeing."""
    ts = (REPO / "ui" / "src" / "lib" / "emptyLiterals.ts").read_text(encoding="utf-8")
    consts = dict(re.findall(r"export const (EMPTY_\w+) = '([^']*)';", ts))
    assert consts == {"EMPTY_OBJECT": EMPTY_OBJECT, "EMPTY_SET": EMPTY_SET, "EMPTY_ARRAY": EMPTY_ARRAY}
    template = re.search(r"return `\$\{setName\}(\[id\] \{[^`]*\})`;", ts)
    assert template is not None, "neverFires() no longer has the shape this test reads"
    assert "escalates" + template.group(1) == baseline._NEVER_FIRES.format(set="escalates")


def _opa_version() -> str:
    try:
        return subprocess.run(["opa", "version"], capture_output=True, text=True).stdout.splitlines()[0]
    except (OSError, IndexError):
        return "unknown"
