# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Empty collection literals whose element type OPA's type checker can see.

OPA 1.21.0 changed how the checker types an EMPTY literal. `{}`, `set()` and `[]` are now typed as
collections with no members, so every reference that reads from one is a compile error —
`rego_type_error: undefined ref: ...[_]  want (one of): []` — where 1.19 typed the same literal `any`
and let the lookup evaluate to undefined. Measured with `opa check --v0-compatible` on both binaries:

    names := {}                 names[input.k]          1.19.1 ok   1.21.4 rego_type_error
    names := set()              not names[input.k]      1.19.1 ok   1.21.4 rego_type_error
    xs := []                    endswith(d, xs[_])      1.19.1 ok   1.21.4 rego_type_error
    blocks[id] { id := [][_] }  (the body itself)       1.19.1 ok   1.21.4 rego_type_error
    names := {}                 count(names), x in names            both ok

Several generators build a set or list out of operator data that is legitimately empty — an intent
allowlist with no tools, an MCP namespace with no writable server, an egress allowlist holding only
suffix entries, a builder graph that uses no escalate rule. On 1.21 each of those modules failed to
compile, and a module that does not compile is a fail-closed `evaluator_error` block on every call
it governs.

The replacements are comprehensions that never yield. OPA types a comprehension from its head, so the
element type is visible (string) while the value is exactly the empty collection it replaces — and
the SAME KIND. `{}` is an empty OBJECT in Rego, not an empty set, even where the same generator
writes a set when it has items; it stays an object, so the package document the evaluator queries is
byte-identical to what 1.19 returned. The object maps each key to itself so a lookup yields the key,
which is what a set lookup yields. The placeholder element is `""` rather than a word: 0.2.5's
console parsers collect every non-empty quoted string inside `allow_names := {...}`, so a word there
would show up as an allowlisted tool after a rollback. `:=` inside a comprehension shadows an outer
variable of the same name instead of colliding with it (measured on both binaries), so the forms are
safe to inline into a rule body.

An unused partial set is a separate case with its own established form: `baseline.py`'s
`_NEVER_FIRES` (`<set>[id] { false; id := "__never__" }`), which the console builder now emits too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

EMPTY_OBJECT = '{k: k | k := ""; false}'
EMPTY_SET = '{s | s := ""; false}'
EMPTY_ARRAY = '[s | s := ""; false]'


def braces(rendered: list[str]) -> str:
    """`{<items>}` as the generators always wrote it — a set — or, with no items, the typed form of
    the empty OBJECT `{}` always was. `rendered` holds already-escaped Rego literals."""
    return "{" + ", ".join(rendered) + "}" if rendered else EMPTY_OBJECT


def brackets(rendered: list[str]) -> str:
    """`[<items>]`, or with no items the typed empty array. `rendered` holds already-escaped literals."""
    return "[" + ", ".join(rendered) + "]" if rendered else EMPTY_ARRAY


# --- Policies stored by an older release -----------------------------------------------------------
#
# Every release up to 0.2.5 wrote the bare literals above into Postgres, and those rows are still what
# warm_cache, load_from_db, a peer's upsert event, the embedded engine's reload and a fleet push hand to
# the evaluator. On OPA 1.21 each of them fails to compile. `upgrade_legacy` rewrites, on the way into
# OPA and nowhere else, exactly the lines those generators wrote — each gated on its generator's own
# header or package line — into the forms above, which are the same values. The stored row, the loader's
# copy (which the policies API serves, and whose builder body hash the console checks for hand edits)
# and the version history are untouched, so a rollback to 0.2.5 reads byte-identical rows.
#
# Each line is a whole-line match of what the generator emitted, and nothing looser: a hand-written
# `names := {}`, or a generated line an operator has edited, is not touched and compiles or fails on
# its own merits. Taken from each released tag's own generator output (v0.1.0 .. v0.2.5), not from the
# current source.


@dataclass(frozen=True, slots=True)
class _LegacyShape:
    name: str
    marker: re.Pattern[str]
    line: re.Pattern[str]
    replacement: str


_EOL = r"(?=\r?$)"  # a row saved with CRLF line endings is still the same generated line

LEGACY_SHAPES: tuple[_LegacyShape, ...] = (
    # ui/src/lib/builderCompile.ts, v0.2.0+: a decision set the graph does not use.
    _LegacyShape(
        "builder_unused_decision_set",
        re.compile(r"(?m)^# nrvq-builder-graph/v1: "),
        re.compile(rf"(?m)^(blocks|escalates|audits)\[id\] \{{ id := \[\]\[_\] \}}{_EOL}"),
        r'\1[id] { false; id := "__never__" }',
    ),
    # threat_intent.generate_intent_rego (v0.1.0+) and the builder's allowlist mode (v0.2.0+): an
    # allowlist with no tools. Both write `package norviq.intent.<class>`.
    _LegacyShape(
        "intent_allowlist_empty",
        re.compile(r"(?m)^package norviq\.intent\."),
        re.compile(rf"(?m)^(allow_names|allow_skeletons) := \{{\}}{_EOL}"),
        rf"\1 := {EMPTY_OBJECT}",
    ),
    # threat_intent.generate_capability_rego, v0.1.0+: no tool observed reaching the source yet.
    _LegacyShape(
        "capability_tools_empty",
        re.compile(r"(?m)^package norviq\.remediation\.capability\."),
        re.compile(rf"(?m)^cap_tools := \{{\}}{_EOL}"),
        f"cap_tools := {EMPTY_OBJECT}",
    ),
    # mcp_controls.compile, v0.2.1+: no registered server, or no writable one.
    _LegacyShape(
        "mcp_registry_empty",
        re.compile(r"(?m)^# nrvq-mcp-registry/v1: "),
        re.compile(rf"(?m)^(registered_servers|writable_servers) = \{{\}}{_EOL}"),
        rf"\1 = {EMPTY_OBJECT}",
    ),
    # egress_allowlist.compile, v0.2.0+: no exact host, or no suffix entry.
    _LegacyShape(
        "egress_exact_empty",
        re.compile(r"(?m)^# nrvq-egress-allowlist/v1: "),
        re.compile(rf"(?m)^allowed_exact = \{{\}}{_EOL}"),
        f"allowed_exact = {EMPTY_OBJECT}",
    ),
    _LegacyShape(
        "egress_suffix_empty",
        re.compile(r"(?m)^# nrvq-egress-allowlist/v1: "),
        re.compile(rf"(?m)^allowed_suffix = \[\]{_EOL}"),
        f"allowed_suffix = {EMPTY_ARRAY}",
    ),
    # engine/intent/compiler.py, v0.2.0+: an `in: []` predicate, one labelled entry of `_predicates`
    # (bare, or inside a param_paths derivability guard on the same line).
    _LegacyShape(
        "intent_compiler_in_empty",
        re.compile(r"(?m)^# nrvq:intent-tools "),
        re.compile(r'(?m)^(\t\t"[^"\n]* in \[\]": [^\n]*?count\(\[x \| x := )\[\]\[_\](; x == )'),
        rf"\1{EMPTY_ARRAY}[_]\2",
    ),
    # ui/src/lib/composerRego.ts, v0.1.0+: the keyword box cleared.
    _LegacyShape(
        "composer_keywords_empty",
        re.compile(r"(?m)^# GENERATED by the New Policy composer "),
        re.compile(rf"(?m)^composer_keywords := set\(\){_EOL}"),
        f"composer_keywords := {EMPTY_SET}",
    ),
)


def upgrade_legacy(rego: str) -> tuple[str, tuple[str, ...]]:
    """Rewrite the bare empty literals an older release's generators stored; return the new source and
    the names of the shapes rewritten (empty when nothing matched, and then `rego` is returned as is).

    Idempotent — no replacement matches any pattern — and line-preserving, so an OPA error on the
    result still points at the stored row's line numbers.
    """
    applied: list[str] = []
    for shape in LEGACY_SHAPES:
        if not shape.marker.search(rego):
            continue
        rego, count = shape.line.subn(shape.replacement, rego)
        if count:
            applied.append(shape.name)
    return rego, tuple(applied)
