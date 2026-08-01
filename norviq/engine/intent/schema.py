# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Intent schema: validation and normalisation.

Validation is strict and rejects rather than coerces. An intent is a security statement; a typo that
is silently accepted becomes a rule that silently never matches, and under deny-by-default a rule
that never matches is an outage rather than a leak — loud, but still an outage nobody can debug.
Unknown keys are therefore errors, not ignored.
"""

from __future__ import annotations

import re

# Fields an intent rule may address, mapped to the input document path the compiler emits.
# Anything not listed here cannot be scoped on — deliberately, because a policy that reads a field
# the evaluator does not populate is a rule whose body is undefined and which therefore never fires.
SCALAR_FIELDS = {
    "verb": "input.derived.verb",
    "tool_name": "input.tool_name",
    "tool_kind": "input.derived.tool_kind",
    # object.get on input itself first: a call that never went through MCP carries no `input.mcp`,
    # and a bare `input.mcp.server` would make the whole predicate OBJECT undefined — which silently
    # deletes every rule in the module rather than failing one predicate. Fail-closed either way, but
    # the near-miss explainer would have nothing to report.
    "server": 'object.get(object.get(input, "mcp", {}), "server", "")',
    "pin_status": 'object.get(object.get(input, "mcp", {}), "pin_status", "")',
    "scan_severity": 'object.get(object.get(input, "mcp", {}), "scan_severity", "")',
    "sql_normalized": "input.derived.sql_normalized",
    "agent_class": "input.agent.agent_class",
    "namespace": "input.agent.namespace",
}

# Collection fields — operators are set-shaped (subsetOf / noneOf / anyOf / maxCount).
COLLECTION_FIELDS = {
    "data_classes": "input.derived.data_classes",
    "sql_tables": "input.derived.sql_tables",
    "sql_statements": "input.derived.sql_statements",
    "param_values": "input.derived.param_values",
    "destinations.emails": 'object.get(input.derived.destinations, "emails", [])',
    "destinations.urls": 'object.get(input.derived.destinations, "urls", [])',
    "destinations.hosts": 'object.get(input.derived.destinations, "hosts", [])',
    "destinations.schemes": 'object.get(input.derived.destinations, "schemes", [])',
}

NUMERIC_FIELDS = {
    "param_bytes": "input.derived.param_bytes",
    "call_depth": "input.call_depth",
    "trust_score": "input.trust_score",
}

SCALAR_OPS = {"equals", "in", "matches", "notMatches"}
COLLECTION_OPS = {"subsetOf", "noneOf", "anyOf", "maxCount"}
NUMERIC_OPS = {"max", "min"}
# trust is special-cased: an ordered category rather than a raw score, because a policy pinned to a
# score changes meaning when the trust model is retuned.
TRUST_RANKS = {"low": 0, "medium": 1, "high": 2}

PLANES = ("call", "answer", "content")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_PARAM_PATH_RE = re.compile(r"^param_paths\.[\w.\[\]$-]{1,256}$")


class IntentError(ValueError):
    """An intent that cannot be compiled. The message names the offending rule and key."""


def _fail(where: str, msg: str) -> None:
    raise IntentError(f"{where}: {msg}")


def _check_predicate(where: str, field: str, spec: object) -> None:
    """A single `field: spec` predicate."""
    is_param_path = bool(_PARAM_PATH_RE.match(field))
    if field == "trust":
        if not isinstance(spec, dict) or set(spec) != {"atLeast"}:
            _fail(where, "trust takes exactly {atLeast: low|medium|high}")
        if spec["atLeast"] not in TRUST_RANKS:
            _fail(where, f"trust.atLeast must be one of {sorted(TRUST_RANKS)}")
        return
    if field in NUMERIC_FIELDS:
        if not isinstance(spec, dict) or not set(spec) <= NUMERIC_OPS or not spec:
            _fail(where, f"{field} takes {sorted(NUMERIC_OPS)}")
        for op, val in spec.items():
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                _fail(where, f"{field}.{op} must be a number")
        return
    if field in COLLECTION_FIELDS:
        if not isinstance(spec, dict) or not set(spec) <= COLLECTION_OPS or not spec:
            _fail(where, f"{field} takes {sorted(COLLECTION_OPS)}")
        for op, val in spec.items():
            if op == "maxCount":
                if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                    _fail(where, f"{field}.maxCount must be a non-negative integer")
            elif not isinstance(val, list) or not all(isinstance(v, str) for v in val):
                _fail(where, f"{field}.{op} must be a list of strings")
        return
    if field in SCALAR_FIELDS or is_param_path:
        if isinstance(spec, str):
            return  # shorthand for {equals: ...}
        if not isinstance(spec, dict) or not set(spec) <= SCALAR_OPS or not spec:
            _fail(where, f"{field} takes a string or {sorted(SCALAR_OPS)}")
        for op, val in spec.items():
            if op == "in":
                if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
                    _fail(where, f"{field}.in must be a list of strings")
            elif not isinstance(val, str):
                _fail(where, f"{field}.{op} must be a string")
            if op in ("matches", "notMatches"):
                try:
                    re.compile(val)
                except re.error as exc:
                    _fail(where, f"{field}.{op} is not a valid regular expression: {exc}")
        return
    _fail(where, f"unknown field {field!r}; addressable fields are "
                 f"{sorted(set(SCALAR_FIELDS) | set(COLLECTION_FIELDS) | set(NUMERIC_FIELDS) | {'trust'})} "
                 f"or a param_paths.<path>")


def normalize_intent(intent: dict) -> dict:
    """Validate and canonicalise. Returns a new dict; never mutates the caller's."""
    if not isinstance(intent, dict):
        raise IntentError("intent must be an object")
    name = intent.get("name", "")
    if not isinstance(name, str) or not _ID_RE.match(name):
        raise IntentError("intent.name must be lowercase alphanumeric/dash, <= 63 chars")
    agent_class = intent.get("class", "")
    if not isinstance(agent_class, str) or not agent_class:
        raise IntentError("intent.class is required")

    out: dict = {"name": name, "class": agent_class, "planes": {}}
    seen_ids: set[str] = set()
    declared = [p for p in PLANES if p in intent]
    if not declared:
        raise IntentError(f"intent must declare at least one plane: {list(PLANES)}")

    for plane in declared:
        rules = intent[plane]
        if not isinstance(rules, list) or not rules:
            raise IntentError(f"{plane}: must be a non-empty list of allow rules")
        norm_rules = []
        for index, rule in enumerate(rules):
            where = f"{plane}[{index}]"
            if not isinstance(rule, dict):
                _fail(where, "rule must be an object")
            rid = rule.get("id", "")
            if not isinstance(rid, str) or not _ID_RE.match(rid):
                _fail(where, "id is required and must be lowercase alphanumeric/dash")
            # Ids are global, not per-plane: the id lands in the audit row as rule_id, and two rules
            # sharing one would make an allow unattributable to the sentence that permitted it.
            if rid in seen_ids:
                _fail(where, f"duplicate rule id {rid!r}")
            seen_ids.add(rid)
            unknown = set(rule) - {"id", "match", "require", "limit", "respond", "from", "server"}
            if unknown:
                _fail(where, f"unknown keys {sorted(unknown)}")
            predicates: dict = {}
            # `match` and `require` are one conjunction at evaluation time. They are separate keys
            # because they read differently to a human — match selects the call, require states the
            # conditions under which it is permitted — and the near-miss explainer keeps the labels.
            for section in ("match", "require"):
                block = rule.get(section, {})
                if not isinstance(block, dict):
                    _fail(where, f"{section} must be an object")
                for field, spec in block.items():
                    _check_predicate(where, field, spec)
                    if field in predicates:
                        _fail(where, f"field {field!r} set in both match and require")
                    predicates[field] = spec
            # `server` is sugar for match.server, so the common case reads naturally.
            for sugar in ("server", "from"):
                if sugar in rule:
                    if not isinstance(rule[sugar], str):
                        _fail(where, f"{sugar} must be a string")
                    if "server" in predicates:
                        _fail(where, "server given twice")
                    predicates["server"] = rule[sugar]
            if not predicates:
                _fail(where, "a rule with no predicates would allow everything on this plane")
            norm_rules.append({"id": rid, "predicates": predicates})
        out["planes"][plane] = norm_rules
    return out
