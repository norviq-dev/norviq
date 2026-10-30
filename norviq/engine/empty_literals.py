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
