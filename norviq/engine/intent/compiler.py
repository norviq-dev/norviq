# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Intent → Rego.

Output constraints, each forced by something already in the system:

* **v0-compatible Rego.** `opa_client` runs `opa run --server --v0-compatible` and `opa check
  --v0-compatible`, so no `if` before a rule body and no `every`.
* **One self-contained module in `package norviq.custom`.** The engine evaluates each policy as a
  single module and this OPA cannot import across packages — the same constraint that forces
  `comprehensive.rego` and `_shared/horizontal.rego` to be two guarded copies.
* **Deterministic.** The same intent must produce byte-identical Rego, so a diff in `policies` means
  a real change rather than dictionary ordering.
* **Fail-closed.** `default decision = "block"`. A rule whose body is undefined does not fire, and
  not firing must mean deny.

Every literal that comes from the intent is emitted through `_lit`, which JSON-encodes it. Rego
string literals are JSON-compatible, so this is also the injection boundary: an operator-supplied
regex or tool name cannot terminate the string and inject Rego.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from norviq.engine.intent.schema import (
    COLLECTION_FIELDS,
    NUMERIC_FIELDS,
    SCALAR_FIELDS,
    TRUST_RANKS,
    IntentError,
    normalize_intent,
)

_HEADER = """# GENERATED FROM AN INTENT — DO NOT EDIT BY HAND.
#
# Regenerate with norviq.engine.intent.compile_intent(). Hand edits are lost on the next compile and,
# worse, make the stored Rego disagree with the intent the console shows the operator.
#
#   intent : {name}
#   class  : {agent_class}
#   planes : {planes}
#
# Positive security: every rule below is an ALLOW. There is no deny list — deny is the absence of a
# match, which is why `default decision` is "block".
#
# nrvq:intent-tools {tools}
#   The tool names this intent can ever admit, as a JSON array, for the console's coverage summary
#   (api/routers/coverage.py `_parse_agent_policy`). A MARKER, never enforcement: the real scoping is
#   the predicates below, and an intent that constrains no tool name emits [] — which honestly means
#   "this intent does not scope by tool name", not "it admits nothing".
package norviq.intent.{token}
"""


def package_token(agent_class: str) -> str:
    """A rego-package-safe token for an agent class ("customer-support" -> "customer_support").

    Deliberately a COPY of `norviq.api.threat_intent.sanitize_class` rather than an import: this is
    engine code and `norviq.api.threat_intent` imports from `norviq.engine`, so importing it back
    would close an api->engine->api cycle. `test_package_token_matches_sanitize_class` pins the two
    together so the copy cannot drift.

    The leading-digit guard is not cosmetic: `package norviq.intent.9lives` is a rego PARSE error,
    which would turn a legally-named agent class into a policy that can never be saved.
    """
    token = re.sub(r"[^a-zA-Z0-9_]", "_", agent_class.strip() or "agent")
    if not re.match(r"[a-zA-Z_]", token):
        token = f"c_{token}"
    return token


# `input.derived` roots that only exist on an engine carrying the MCP-merge scoping primitives.
# A rule referencing one of these MUST also assert the root is published — see _availability_predicates.
_VERSION_GATED_ROOTS = ("param_paths", "destinations", "data_classes", "sql_tables", "param_bytes")


def _gated_roots(predicates: dict) -> set[str]:
    """Which version-gated `input.derived` roots this rule's predicates read."""
    roots: set[str] = set()
    for field in predicates:
        if field.startswith("param_paths."):
            roots.add("param_paths")
        elif field.startswith("destinations."):
            roots.add("destinations")
        elif field in _VERSION_GATED_ROOTS:
            roots.add(field)
    return roots


def _availability_predicates(predicates: dict) -> list[tuple[str, str]]:
    """One predicate per version-gated root the rule reads, asserting the engine publishes it.

    WITHOUT THIS AN INTENT FAILS OPEN, which is the opposite of everything it is for. The collection
    operators compile to counted comprehensions:

        count([x | x := input.derived.data_classes[_]; _in(["secret"], x)]) == 0

    A comprehension whose body is undefined does not become undefined — it yields the EMPTY ARRAY. So
    on an engine that does not publish `data_classes`, `count([]) == 0` is TRUE: `noneOf` and
    `subsetOf` are vacuously satisfied, the rule matches, and the intent ALLOWS the call it was written
    to refuse. Observed on a live cluster, not reasoned about: the same `send_email` to an
    attacker-controlled address carrying an AWS key evaluated `allow` against an engine predating these
    facts and `block` against one carrying them.

    `object.get(input.derived, "<root>", null) != null` is a real boolean either way — false when the
    root is absent, true when present — so the rule simply fails to match on an old engine, which under
    default-deny means block.

    It is a LABELLED predicate rather than a hidden guard so the near-miss explainer names it: the
    operator is told "data_classes is published by this engine" failed, instead of being told nothing
    matched. That is the difference between diagnosing a version skew and disabling the policy.
    """
    return [
        (f"{root} is published by this engine", f'object.get(input.derived, {_lit(root)}, null) != null')
        for root in sorted(_gated_roots(predicates))
    ]


def _scoped_tool_names(norm: dict) -> list[str]:
    """Tool names this intent can admit, for the coverage marker in the header.

    Derived from the SAME normalized predicates the rules compile from, so the marker cannot come to
    describe a policy other than the one emitted. Only `tool_name` equals/`in` narrows the admissible
    set; an intent that scopes by verb or destination instead legitimately yields [] — which the
    console must render as "not scoped by tool name", never as "admits nothing".
    """
    names: set[str] = set()
    for rules in norm["planes"].values():
        for rule in rules:
            spec = rule["predicates"].get("tool_name")
            if isinstance(spec, str):
                names.add(spec)
            elif isinstance(spec, dict):
                if isinstance(spec.get("equals"), str):
                    names.add(spec["equals"])
                for value in spec.get("in") or []:
                    names.add(value)
    return sorted(names)


@dataclass(frozen=True)
class CompiledIntent:
    """The generated module plus the labels the near-miss explainer reports."""

    rego: str
    rule_ids: tuple[str, ...]
    # rule id -> ordered predicate labels, for a caller that wants to explain outside Rego.
    labels: dict


def _lit(value) -> str:
    """A Rego literal. JSON encoding is the injection boundary — see the module docstring."""
    return json.dumps(value, sort_keys=True, separators=(", ", ": "))


def _field_expr(field: str) -> str:
    """The input-document expression for an addressable field."""
    if field.startswith("param_paths."):
        path = field[len("param_paths."):]
        return f"object.get(input.derived.param_paths, {_lit(path)}, \"\")"
    for table in (SCALAR_FIELDS, COLLECTION_FIELDS, NUMERIC_FIELDS):
        if field in table:
            return table[field]
    raise IntentError(f"unknown field {field!r}")  # unreachable: schema validated first


def _predicate(field: str, spec) -> list[tuple[str, str]]:
    """One `field: spec` predicate -> [(label, rego boolean expression)].

    A predicate compiles to an expression that EVALUATES to true/false rather than to a rule body
    that either succeeds or is undefined. That is what makes the near-miss possible: an undefined
    body tells you nothing about which clause failed, a false value names it.
    """
    if field == "trust":
        rank = TRUST_RANKS[spec["atLeast"]]
        ranks = _lit(TRUST_RANKS)
        expr = f'object.get({ranks}, input.trust_category, -1) >= {rank}'
        return [(f"trust >= {spec['atLeast']}", expr)]

    expr_base = _field_expr(field)
    out: list[tuple[str, str]] = []

    if isinstance(spec, str):  # scalar shorthand
        return [(f"{field} == {spec}", f"{expr_base} == {_lit(spec)}")]

    for op, val in sorted(spec.items()):
        if op == "equals":
            out.append((f"{field} == {val}", f"{expr_base} == {_lit(val)}"))
        elif op == "in":
            # A COMPREHENSION, not `list[_] == x`. The bare `[_]` form iterates, so inside the
            # predicate object literal it yields one binding per element — and a complete rule with
            # more than one output is an eval_conflict_error at query time, not a compile error.
            # A single-element list hides it exactly, which is how it survived the first test pass.
            allowed = _lit(sorted(val))
            out.append((f"{field} in {sorted(val)}",
                        f"count([x | x := {allowed}[_]; x == {expr_base}]) > 0"))
        elif op == "matches":
            out.append((f"{field} matches {val}", f"regex.match({_lit(val)}, {expr_base})"))
        elif op == "notMatches":
            out.append((f"{field} !matches {val}", f"not regex.match({_lit(val)}, {expr_base})"))
        elif op == "subsetOf":
            # every element of the collection must be in the allowed set
            allowed = _lit(sorted(val))
            out.append((f"{field} subsetOf {sorted(val)}",
                        f"count([x | x := {expr_base}[_]; not _in({allowed}, x)]) == 0"))
        elif op == "noneOf":
            denied = _lit(sorted(val))
            out.append((f"{field} noneOf {sorted(val)}",
                        f"count([x | x := {expr_base}[_]; _in({denied}, x)]) == 0"))
        elif op == "anyOf":
            wanted = _lit(sorted(val))
            out.append((f"{field} anyOf {sorted(val)}",
                        f"count([x | x := {expr_base}[_]; _in({wanted}, x)]) > 0"))
        elif op == "maxCount":
            out.append((f"count({field}) <= {val}", f"count({expr_base}) <= {_lit(val)}"))
        elif op == "max":
            out.append((f"{field} <= {val}", f"{expr_base} <= {_lit(val)}"))
        elif op == "min":
            out.append((f"{field} >= {val}", f"{expr_base} >= {_lit(val)}"))
        else:  # pragma: no cover - schema validated first
            raise IntentError(f"unknown operator {op!r} on {field!r}")
    return out


def compile_intent(intent: dict) -> CompiledIntent:
    """Compile an intent to a self-contained, v0-compatible Rego module."""
    norm = normalize_intent(intent)
    lines: list[str] = []
    labels: dict[str, list[str]] = {}
    rule_ids: list[str] = []

    lines.append(_HEADER.format(name=norm["name"], agent_class=norm["class"],
                                planes=", ".join(sorted(norm["planes"])),
                                token=package_token(norm["class"]),
                                tools=json.dumps(_scoped_tool_names(norm))))
    lines.append("")
    lines.append('# Deny is the absence of a matching allow rule.')
    lines.append('default decision = "block"')
    lines.append('default rule_id = "intent_no_match"')
    lines.append('default reason = "no intent rule matched this call"')
    lines.append("")
    lines.append("# Membership helper. Inlined because this OPA cannot import across packages.")
    lines.append("_in(haystack, needle) {")
    lines.append("\thaystack[_] == needle")
    lines.append("}")
    lines.append("")

    for plane in sorted(norm["planes"]):
        rules = norm["planes"][plane]
        lines.append(f"# ---- plane: {plane} " + "-" * 60)
        for rule in rules:
            rid = rule["id"]
            rule_ids.append(rid)
            preds: list[tuple[str, str]] = []
            # The plane itself is a predicate, so one module governs all planes and a call on the
            # wrong plane simply fails to match rather than needing a second policy.
            preds.append((f"direction == {plane}",
                          f'object.get(input, "direction", "call") == {_lit(plane)}'))
            for field, spec in sorted(rule["predicates"].items()):
                preds.extend(_predicate(field, spec))
            # Appended AFTER the field predicates so the near-miss explainer reports a genuine
            # scope failure before a version-skew one when both are false.
            preds.extend(_availability_predicates(rule["predicates"]))
            labels[rid] = [label for label, _ in preds]
            lines.append(f"_predicates[{_lit(rid)}] = p {{")
            lines.append("\tp := {")
            for label, expr in preds:
                lines.append(f"\t\t{_lit(label)}: {expr},")
            lines.append("\t}")
            lines.append("}")
            lines.append("")

    lines.append("# Predicates that evaluated false, per rule — the near-miss data.")
    lines.append("_failed[id] = fs {")
    lines.append("\tp := _predicates[id]")
    lines.append("\tfs := sort([k | p[k] == false])")
    lines.append("}")
    lines.append("")
    lines.append("_matched[id] {")
    lines.append("\tcount(_failed[id]) == 0")
    lines.append("}")
    lines.append("")
    lines.append("_any_match {")
    lines.append("\tcount(_matched) > 0")
    lines.append("}")
    lines.append("")
    lines.append("decision = \"allow\" {")
    lines.append("\t_any_match")
    lines.append("}")
    lines.append("")
    # The deny arm, stated as a COMPLETE RULE even though `default decision = "block"` above already
    # produces exactly this value for exactly this case.
    #
    # It is required to SAVE the policy at all. api/routers/policies.py `assert_decision_resolver`
    # admits a module only if it finds a complete `decision = "block"|"escalate" { ... }` rule (or
    # partial sets plus a resolver); a default-only module falls through to its `else` and is rejected
    # 422 "rego_source must include block or escalate decision". Without this, an operator could
    # compile, propose, dry-run and save a DRAFT, then be refused at the one step that starts
    # enforcement — with an error naming rego they never wrote.
    #
    # Fixed here rather than by loosening that validator, because the validator is guarding something
    # real (a `decision` binding that is undefined at runtime silently becomes "allow" in the
    # evaluator) and it is shared by every write path in the product. Widening a security gate to
    # admit one generator is the wrong direction; emitting what the gate asks for is free.
    #
    # Semantically inert: `_any_match` is the same predicate the allow arm keys on, so the two arms
    # are mutually exclusive and can never produce conflicting complete-rule values. When nothing
    # matches, this and the `default` agree on "block".
    lines.append("# Deny, stated explicitly — see the note in compiler.py on why this is not redundant.")
    lines.append("decision = \"block\" {")
    lines.append("\tnot _any_match")
    lines.append("}")
    lines.append("")
    lines.append("# Sorted so a call matching two rules is attributed deterministically.")
    lines.append("rule_id = id {")
    lines.append("\t_any_match")
    lines.append("\tid := sort([i | _matched[i]])[0]")
    lines.append("}")
    lines.append("")
    lines.append('reason = msg {')
    lines.append("\t_any_match")
    lines.append("\tid := sort([i | _matched[i]])[0]")
    lines.append('\tmsg := sprintf("allowed by intent rule %v", [id])')
    lines.append("}")
    lines.append("")
    lines.append("# The near miss. Without it a denial says only \"no rule matched\", which is the")
    lines.append("# absence of a rule — nothing an operator can act on. Naming the closest rule and the")
    lines.append("# clause that failed is the difference between tightening a predicate and switching")
    lines.append("# the policy off.")
    lines.append("_min_failed = n {")
    lines.append("\tnot _any_match")
    lines.append("\tcounts := [c | _predicates[id]; c := count(_failed[id])]")
    lines.append("\tcount(counts) > 0")
    lines.append("\tn := min(counts)")
    lines.append("}")
    lines.append("")
    lines.append("_closest[id] {")
    lines.append("\tcount(_failed[id]) == _min_failed")
    lines.append("}")
    lines.append("")
    lines.append("reason = msg {")
    lines.append("\tnot _any_match")
    lines.append("\tids := sort([i | _closest[i]])")
    lines.append("\tcount(ids) > 0")
    lines.append("\tid := ids[0]")
    lines.append("\ttotal := count(_predicates[id])")
    lines.append("\tmet := total - count(_failed[id])")
    lines.append('\tmsg := sprintf("no intent rule matched; closest %v met %v/%v, failed: %v",')
    lines.append('\t\t[id, met, total, concat(\", \", _failed[id])])')
    lines.append("}")
    lines.append("")

    return CompiledIntent(rego="\n".join(lines), rule_ids=tuple(rule_ids), labels=labels)
