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

import pytest

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
