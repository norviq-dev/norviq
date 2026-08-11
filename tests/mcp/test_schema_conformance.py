# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Schema conformance: the shapes that used to switch the whole gate off, and the one it over-blocked.

`mcp_enforce_schema` defaults to True, so an operator who leaves it on believes every call is checked
against the tool's own declaration. Three ordinary, legal declarations made `_schema_violations`
return `[]` for every input — not "this call conformed", but "I checked nothing" wearing the same
spelling. That is the failure this module pins down: a shape the checker cannot fully apply must be
enforced as far as it goes and REPORTED for the rest, never absorbed into an empty list.
"""

from __future__ import annotations

import json

import pytest

from norviq.mcp import protocol as P
from norviq.mcp.firewall import McpFirewall
from norviq.mcp.pins import PinRegistry, MemoryPinStore
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity
from norviq.sdk.core.interceptor import ToolInterceptor


class _StubEvaluator:
    def __init__(self, decision: str = "allow") -> None:
        self.decision = decision
        self.seen: list = []

    async def evaluate(self, event):
        self.seen.append(event)
        return PolicyDecision(decision=self.decision, rule_id="test_rule", reason="test")


class _StubResolver:
    async def resolve(self):
        return AgentIdentity(spiffe_id="spiffe://norviq/ns/agents/sa/default",
                             namespace="agents", agent_class="mcp-agent")


def _firewall(decision: str = "allow"):
    evaluator = _StubEvaluator(decision)
    fw = McpFirewall(
        interceptor=ToolInterceptor(evaluator, _StubResolver()),
        server_id="test-server",
        pins=PinRegistry(store=MemoryPinStore(), mode="tofu"),
    )
    return fw, evaluator


def _msg(payload: dict) -> P.JsonRpcMessage:
    return P.decode(json.dumps(payload).encode())


async def _discovered(schema: dict, decision: str = "allow", name: str = "read_table"):
    fw, evaluator = _firewall(decision)
    await fw.on_client_message(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
    await fw.on_server_message(_msg({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": name, "description": "Reads rows.", "inputSchema": schema}]}}))
    return fw, evaluator


async def _call(fw, arguments: dict, name: str = "read_table", mid: int = 9):
    return await fw.on_client_message(_msg({
        "jsonrpc": "2.0", "id": mid, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}}))


# ── the three shapes that disabled the gate ─────────────────────────────────────────────────────
#
# Each of these returned `[]` for every argument object before the fix, so the smuggled `q` reached
# policy and `required` went unchecked — with the operator's conformance setting ON.

async def test_a_schema_with_no_properties_key_still_enforces_its_own_statements():
    """`required` and `additionalProperties` are statements about the ARGUMENT SET.

    Neither reads `properties`, so neither has any business being skipped when `properties` is
    absent — which is a legal declaration for a tool whose arguments are documented elsewhere.
    """
    fw, evaluator = await _discovered(
        {"type": "object", "required": ["table"], "additionalProperties": False})
    result = await _call(fw, {"q": "smuggled", "table": None})
    assert result.blocked, "an undeclared argument must not reach policy"
    assert "argument 'q' is not declared" in result.reply.decode()
    assert evaluator.seen == []

    # `required` is enforced on the same schema, and the required name is NOT itself reported as
    # undeclared — a schema that demands `table` and refuses it would make the tool uncallable.
    fw2, _ = await _discovered(
        {"type": "object", "required": ["table"], "additionalProperties": False})
    missing = await _call(fw2, {})
    assert missing.blocked
    assert "missing required argument 'table'" in missing.reply.decode()

    fw3, ev3 = await _discovered(
        {"type": "object", "required": ["table"], "additionalProperties": False})
    honest = await _call(fw3, {"table": "users"})
    assert not honest.blocked and len(ev3.seen) == 1


async def test_a_top_level_type_list_containing_object_is_accepted():
    """`["object"]` / `["object","null"]` are legal, and the SAME function already accepts a type
    list at property level. Rejecting one here disabled every check for the tool."""
    schema = {"type": ["object", "null"], "required": ["table"], "additionalProperties": False,
              "properties": {"table": {"type": "string"}}}
    fw, evaluator = await _discovered(schema)
    result = await _call(fw, {"table": "users", "q": "smuggled"})
    assert result.blocked
    assert "argument 'q' is not declared" in result.reply.decode()
    assert evaluator.seen == []

    fw2, ev2 = await _discovered(schema)
    assert not (await _call(fw2, {"table": "users"})).blocked
    assert len(ev2.seen) == 1
    # And it is reported as fully enforceable, because it is.
    assert fw2._catalog["read_table"].schema_enforced is True


async def test_a_non_dict_properties_does_not_abandon_the_argument_set_checks():
    """A `properties` that is not an object declares no usable names. The fail-CLOSED reading is that
    the declared set is empty, not that the server's `additionalProperties: false` evaporates."""
    fw, evaluator = await _discovered(
        {"type": "object", "properties": [{"table": {"type": "string"}}],
         "required": ["table"], "additionalProperties": False})
    result = await _call(fw, {"q": "smuggled", "table": None})
    assert result.blocked
    assert "argument 'q' is not declared" in result.reply.decode()
    assert evaluator.seen == []
    # ...and it is reported as not fully enforceable, since no per-argument type could be read.
    entry = fw._catalog["read_table"]
    assert entry.schema_enforced is False
    assert any("`properties` is not an object" in n for n in entry.schema_notes)


# ── what cannot be enforced is SAID, not swallowed ──────────────────────────────────────────────

@pytest.mark.parametrize("keyword, schema", [
    ("anyOf", {"anyOf": [{"required": ["a"]}, {"required": ["b"]}]}),
    ("oneOf", {"type": "object", "oneOf": [{"required": ["a"]}]}),
    ("allOf", {"type": "object", "properties": {"table": {"type": "string"}},
               "allOf": [{"properties": {"q": {"type": "string"}}}]}),
    ("$ref", {"$ref": "#/$defs/Args"}),
    ("patternProperties", {"type": "object", "properties": {"a": {"type": "string"}},
                           "patternProperties": {"^x-": {"type": "string"}}}),
])
async def test_a_shape_the_subset_checker_cannot_evaluate_is_reported_not_ignored(keyword, schema):
    """Fail closed or fail loud, never fail quiet.

    None of these can be resolved without following references or running server-supplied regexes —
    unbounded work on attacker-controlled input inside a 2s fail-closed evaluation budget. So the
    checker does not attempt them; what it must not do is let "I did not evaluate this" reach the
    operator spelled identically to "this conformed".
    """
    fw, _ = await _discovered(schema)
    entry = fw._catalog["read_table"]
    assert entry.schema_enforced is False
    assert any(keyword in note for note in entry.schema_notes), entry.schema_notes
    # And policy can read it, so a rule may refuse to rely on conformance it did not get.
    ctx = fw._mcp_context("read_table", "tools/call")
    assert ctx["schema_enforced"] is False
    assert ctx["schema_notes"] == entry.schema_notes


async def test_pattern_properties_does_not_switch_off_the_undeclared_argument_refusal():
    """`additionalProperties: false` + `patternProperties` means the legal extras are decided by a
    server-supplied regex. Not running it is the right call; SKIPPING THE WHOLE CHECK is not.

    This assertion was the other way round for one revision, and that was a bypass with a switch on
    it: the schema is authored by the same server the check defends against, so any server could
    disable the undeclared-argument refusal for itself by adding `"patternProperties": {}` — and the
    undeclared argument is the entire residual the check exists to close ("they scope `query` and the
    tool also accepts `q`"). Refusing an argument that a pattern might have legalised costs one call
    on a rare declaration and says why; the other direction costs the control.
    """
    schema = {"type": "object", "properties": {"a": {"type": "string"}},
              "patternProperties": {"^x-": {"type": "string"}}, "additionalProperties": False}
    fw, evaluator = await _discovered(schema)
    result = await _call(fw, {"a": "v", "x-trace": "t"})
    assert result.blocked, "the server declared a closed set; the pattern is not evaluated here"
    assert "argument 'x-trace' is not declared" in result.reply.decode()
    assert evaluator.seen == []
    entry = fw._catalog["read_table"]
    assert entry.schema_closed is True, "the server DID declare a closed set"
    assert entry.schema_enforced is False
    # ...and the refusal's REASON is published, so the operator is not left guessing why a
    # pattern-legal argument bounced.
    assert any("WITHOUT evaluating `patternProperties`" in n for n in entry.schema_notes)


async def test_a_server_cannot_disable_the_undeclared_argument_check_with_its_own_schema():
    """The direct statement of the same thing: an empty `patternProperties` is a no-op in JSON
    Schema, so if adding one changes the verdict, the verdict is the server's to choose."""
    closed = {"type": "object", "properties": {"a": {"type": "string"}},
              "additionalProperties": False}
    with_switch = {**closed, "patternProperties": {}}
    fw, _ = await _discovered(closed)
    assert fw._schema_violations(closed, {"a": "v", "smuggled": "x"})
    assert fw._schema_violations(with_switch, {"a": "v", "smuggled": "x"}), \
        "adding patternProperties must not buy the caller an undeclared argument"


async def test_a_property_level_keyword_the_checker_skips_is_reported_too():
    """`schema_enforced` is a published fact a policy may lean on, so it must not claim more than the
    checker did. The keyword scan looked at TOP-LEVEL keys only, so a schema whose `cmd` is an
    `anyOf` reported `schema_enforced: True` while `_schema_violations` skipped that argument's type
    entirely — the shape defeating the constraint is exactly the case the type check exists for.
    """
    schema = {"type": "object", "additionalProperties": False,
              "properties": {"cmd": {"anyOf": [{"type": "string"}, {"type": "array"}]}}}
    fw, _ = await _discovered(schema)
    entry = fw._catalog["read_table"]
    assert fw._schema_violations(schema, {"cmd": ["a", "b"]}) == [], "the type is genuinely unchecked"
    assert entry.schema_enforced is False, "so it must not be reported as enforced"
    assert any("cmd" in note for note in entry.schema_notes), entry.schema_notes


async def test_the_enforceability_scan_is_bounded_by_the_property_count():
    """The schema is server-authored, so the property count is the server's to choose. Past the cap
    the answer is "I did not look", said out loud."""
    from norviq.mcp.firewall import _MAX_SCHEMA_PROPERTIES

    schema = {"type": "object",
              "properties": {f"p{i}": {"type": "string"} for i in range(_MAX_SCHEMA_PROPERTIES + 10)}}
    fw, _ = await _discovered(schema)
    entry = fw._catalog["read_table"]
    assert entry.schema_enforced is False
    assert any(str(_MAX_SCHEMA_PROPERTIES) in note for note in entry.schema_notes)


async def test_additional_properties_true_is_a_declaration_not_a_checker_limit():
    """`additionalProperties: true` alongside typed `properties` is the server explicitly permitting
    extras. Nothing is broken, so nothing is flagged — but `schema_closed` reports that no
    undeclared-argument refusal is possible for this tool, which no checker can supply on its behalf.
    """
    fw, evaluator = await _discovered(
        {"type": "object", "properties": {"table": {"type": "string"}}, "additionalProperties": True})
    result = await _call(fw, {"table": "users", "extra": "fine"})
    assert not result.blocked and len(evaluator.seen) == 1
    entry = fw._catalog["read_table"]
    assert entry.schema_enforced is True and entry.schema_notes == []
    assert entry.schema_closed is False
    assert fw._mcp_context("read_table", "tools/call")["schema_closed"] is False

    # The typed check still bites — permitting extras is not permitting a wrong shape.
    fw2, _ = await _discovered(
        {"type": "object", "properties": {"table": {"type": "string"}}, "additionalProperties": True})
    assert (await _call(fw2, {"table": ["users"]})).blocked


async def test_a_tool_with_no_schema_reports_no_enforcement_rather_than_success():
    """The observed-only tier: no declaration, so nothing to enforce — and `schema_enforced` says so
    rather than defaulting to the same value a fully-checked tool gets."""
    fw, evaluator = _firewall("allow")
    await fw.on_client_message(_msg({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}))
    await fw.on_server_message(_msg({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "duck_search", "description": "Searches."}]}}))
    assert fw._catalog["duck_search"].schema_enforced is False
    assert fw._mcp_context("duck_search", "tools/call")["schema_enforced"] is False
    assert not (await _call(fw, {"anything": "at all"}, name="duck_search")).blocked


# ── 1.0 is the integer 1 ────────────────────────────────────────────────────────────────────────

async def test_an_integral_float_satisfies_an_integer_declaration():
    """JSON has ONE number type. JSON Schema draft 6+ defines "integer" as any number with a zero
    fractional part, so `10.0` conforms — and which of `10`/`10.0` the peer emitted is a decoder
    detail the caller never chose. `_PendingMap._key` already normalises int/float for exactly this
    reason; the two halves of the file disagreed."""
    schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
    fw, evaluator = await _discovered(schema)
    result = await _call(fw, {"limit": 10.0})
    assert not result.blocked, "10.0 is the integer 10"
    assert len(evaluator.seen) == 1


async def test_a_fractional_number_is_still_not_an_integer():
    schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
    fw, _ = await _discovered(schema)
    result = await _call(fw, {"limit": 10.5})
    assert result.blocked
    assert "must be integer" in result.reply.decode()


@pytest.mark.parametrize("value", [float("inf"), float("nan")])
async def test_a_non_finite_number_is_not_an_integer(value):
    """`Infinity`/`NaN` decode to floats that are not integral, and must not ride the 10.0 relaxation."""
    schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
    fw, _ = await _discovered(schema)
    assert fw._schema_violations(fw._catalog["read_table"].input_schema, {"limit": value})


async def test_true_is_still_not_an_integer():
    """`bool` is an `int` subclass in Python; the relaxation must not reopen that."""
    schema = {"type": "object", "properties": {"limit": {"type": "integer"}}}
    fw, _ = await _discovered(schema)
    assert (await _call(fw, {"limit": True})).blocked
