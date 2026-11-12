# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Whether a replayed audit row is missing the argument values the real call had, and whether a
refusal of it can be blamed on that.

Both dry runs (/intents/dry-run and /policies/dry-run) rebuild a policy input from an audit row. The row
keeps argument values only when masked parameter capture is on (off by default); otherwise it keeps the
argument NAMES at most. A replay of such a row sees no arguments at all, so any rule over an argument
value is judged against nothing. One predicate, shared, so the two dry runs cannot disagree about which
rows those are.
"""

from __future__ import annotations

from norviq.engine.capability import verb_reads_payload
from norviq.engine.composition import attached_builder_graph
from norviq.engine.intent.compiler import reads_argument_values


def audit_row_lacks_values(params: dict, payload: dict) -> bool:
    """True when the replay of this row may be missing arguments the real call carried.

    A row replayed with recorded values is complete. So is a row that recorded an EMPTY, untruncated
    key set: that call had no arguments, and its empty replay is exact. Every other row without values
    (names only, or nothing recorded about arguments at all) may have carried arguments the replay
    cannot see.
    """
    if params:
        return False
    keys = payload.get("param_keys")
    no_arguments = isinstance(keys, list) and not keys and not payload.get("param_keys_truncated")
    return not no_arguments


def builder_grant_waits_on_values(rego: str, tool_name: str, tool_name_normalized: str = "") -> bool:
    """Whether a Visual Builder allowlist's per-tool grant for this tool reads only argument values.

    The builder's allowlist refuses an allowlisted call as `intent_constraint_violation` when its grant
    (`constraints_ok`) fails. A grant holds argument constraints, which all read `tool_params`, and
    optional scoping facts, which may not: `call_depth`, `direction`, `mcp.*`, `tool_kind` and
    `trust_score` are facts about the call, not its arguments, and `verb` is one only for a tool whose
    verb `classify_tool` takes from the payload. A value-less replay cannot say which line of the grant
    failed, so the refusal can be set aside only when no line could have failed for another reason.

    Read from the graph embedded in the module, and only while the module is attached to it: a
    hand-edited module, or one that is not a builder allowlist, is not described by any graph, and its
    rule ids are not evidence of anything. Answers False whenever it cannot tell, so a refusal it
    cannot explain stays a block. This is the static half; the dry run also re-evaluates the call with
    the grant assumed met, to rule out a refinement that refused it too.
    """
    graph = attached_builder_graph(rego)
    if graph is None or graph.get("mode") != "allowlist":
        return False
    allowlist = graph.get("allowlist")
    raw = allowlist.get("grants") if isinstance(allowlist, dict) else None
    grants = [g for g in raw or [] if isinstance(g, dict) and isinstance(g.get("tool"), str) and g["tool"].strip()]
    if not grants:
        return False
    names = {tool_name.lower(), (tool_name_normalized or tool_name).lower()}
    # A grant matches the raw or the normalized name (builderCompile.ts grantsSection). If neither is
    # found here (a confusable the browser folded differently), every grant could be the one that
    # failed, so every grant is judged.
    applicable = [g for g in grants if g["tool"].strip().lower() in names] or grants

    def fact_reads_values(fact: object) -> bool:
        while isinstance(fact, dict) and fact.get("type") == "not":
            fact = fact.get("inner")
        field = fact.get("field") if isinstance(fact, dict) else None
        if not isinstance(field, str):
            return False
        if field == "verb":
            return verb_reads_payload(tool_name)
        return reads_argument_values(field)

    return all(
        fact_reads_values(fact)
        for grant in applicable
        for fact in (grant.get("facts") if isinstance(grant.get("facts"), list) else [])
    )
