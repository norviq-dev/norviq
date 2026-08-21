# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The baseline compiler must change what a control DOES without changing how it DETECTS.

That is the whole safety argument for making presets toggleable, so it is asserted directly rather
than inferred: with every control at `deny` the compiled module carries exactly the preset's own
registration heads, and every line outside the CONTROLS region is byte-identical.

The `off` and `monitor` paths then get their own assertions, including the one that would otherwise
have shipped broken — an all-`monitor` module has no `blocks[...]` heads at all, and a Rego partial
set with zero definitions is UNDEFINED rather than empty, so the module fails to compile with
`var blocks is unsafe`. Since `monitor` is the shipped default for every control, that would have
made the default configuration produce an invalid policy and fail every call closed.
"""

from __future__ import annotations

import pytest

from norviq.api import baseline

PRESET = "strict"


def test_the_preset_region_parses_completely() -> None:
    """Every non-comment line in the CONTROLS region must be a readable head.

    `parse_heads` raises rather than skipping, because a head it cannot read is a control that
    silently disappears from every compiled module — an "off" nobody chose and nobody can see.
    """
    heads = baseline.controls_for(PRESET)
    assert heads, "no control heads found — the region markers are probably misplaced"
    assert len(heads) >= 20, f"expected the preset's ~22 heads, got {len(heads)}"


def test_every_control_has_operator_facing_copy() -> None:
    """A control with no copy still works, but a bare rule_id in the console is not a description."""
    missing = [cid for cid in baseline.control_ids(PRESET) if cid not in baseline._CONTROL_COPY]
    assert not missing, f"controls with no operator copy: {missing}"


def test_all_deny_reproduces_the_presets_own_heads() -> None:
    """Parity: `deny` everywhere registers exactly what the preset registers — with ONE deliberate
    exception, stated here rather than hidden.

    A control the preset authors as `audits[...]` is PROMOTED to `blocks[...]` at deny. Restoring its
    original set instead meant it could never block while the API reported it as enforcing, so the
    exception exists to make the setting honest. Every block/escalate control is still byte-identical,
    which is what the "changing an effect cannot change a detector" argument actually rests on.
    """
    original = {(h.set_name, h.control_id, h.guard) for h in baseline.controls_for(PRESET)}
    audit_authored = {h.control_id for h in baseline.controls_for(PRESET) if h.set_name == "audits"}
    expected = {
        ("blocks" if cid in audit_authored else s, cid, g) for (s, cid, g) in original
    }
    compiled = baseline.compile(PRESET, {cid: "deny" for cid in baseline.control_ids(PRESET)})
    _, region, _ = baseline._split_region(compiled)
    assert {(h.set_name, h.control_id, h.guard) for h in baseline.parse_heads(region)} == expected

    # The guards — the actual detection — are untouched for every control, promoted or not.
    assert {(cid, g) for (_, cid, g) in original} == {
        (h.control_id, h.guard) for h in baseline.parse_heads(region)
    }


def test_everything_outside_the_controls_region_is_untouched() -> None:
    """The detectors are the part that must not move. Compare them literally."""
    src = baseline.preset_source(PRESET)
    before, _, after = baseline._split_region(src)
    for effects in (
        {cid: "deny" for cid in baseline.control_ids(PRESET)},
        {cid: "monitor" for cid in baseline.control_ids(PRESET)},
        {cid: "off" for cid in baseline.control_ids(PRESET)},
    ):
        c_before, _, c_after = baseline._split_region(baseline.compile(PRESET, effects))
        assert c_before == before
        assert c_after == after


def test_monitor_moves_every_head_to_audits() -> None:
    compiled = baseline.compile(PRESET, {cid: "monitor" for cid in baseline.control_ids(PRESET)})
    _, region, _ = baseline._split_region(compiled)
    heads = baseline.parse_heads(region)
    real = [h for h in heads if h.control_id != "__never__"]
    assert real, "monitor produced no heads at all"
    assert {h.set_name for h in real} == {"audits"}


def test_monitor_folds_an_escalate_head_into_audits_too() -> None:
    """llm06 registers BOTH a block and an escalate head. Under monitor both must proceed."""
    sets = {h.set_name for h in baseline.controls_for(PRESET) if h.control_id == "llm06_excessive_agency"}
    assert sets == {"blocks", "escalates"}, "fixture assumption changed — llm06 no longer has both"

    compiled = baseline.compile(PRESET, {"llm06_excessive_agency": "monitor"})
    _, region, _ = baseline._split_region(compiled)
    llm06 = [h for h in baseline.parse_heads(region) if h.control_id == "llm06_excessive_agency"]
    assert len(llm06) == 2
    assert {h.set_name for h in llm06} == {"audits"}


def test_off_removes_the_control_entirely() -> None:
    compiled = baseline.compile(PRESET, {"deny_shell_execution": "off"})
    _, region, _ = baseline._split_region(compiled)
    ids = {h.control_id for h in baseline.parse_heads(region)}
    assert "deny_shell_execution" not in ids
    assert "llm01_prompt_injection" in ids, "turning one control off must not disturb the others"


@pytest.mark.parametrize("effect", ["monitor", "off"])
def test_every_set_is_always_defined(effect: str) -> None:
    """The bug that would have shipped as the DEFAULT.

    A Rego partial set with no definitions is undefined, not empty, so `block_fired { blocks[_] }`
    fails to compile with `rego_unsafe_var_error`. With every control at `monitor` — the shipped
    default — there are no `blocks[...]` heads, so without the never-fires guard the default install
    produces a module that does not compile and every call falls to `evaluator_error`.
    """
    compiled = baseline.compile(PRESET, {cid: effect for cid in baseline.control_ids(PRESET)})
    for set_name in ("blocks", "escalates", "audits"):
        assert f"{set_name}[" in compiled, f"{set_name} has no definition at all — module will not compile"


def test_unknown_control_is_refused_not_ignored() -> None:
    """Silently dropping it would report success for a setting that never took effect."""
    with pytest.raises(ValueError, match="unknown control"):
        baseline.compile(PRESET, {"no_such_control": "deny"})


def test_invalid_effect_is_refused() -> None:
    with pytest.raises(ValueError, match="invalid effect"):
        baseline.compile(PRESET, {"pii_detection": "audit"})  # the rego verb, not a control effect


def test_unknown_preset_raises_rather_than_returning_empty() -> None:
    """An empty module would compile to a policy that allows everything."""
    with pytest.raises(FileNotFoundError):
        baseline.preset_source("no-such-preset")


def test_the_shipped_default_is_now_per_control_and_actually_enforces() -> None:
    """The premise CHANGED, deliberately, and this records what replaced it.

    It used to be "nothing is dropped on a fresh install" — every control at `monitor` — because the
    blast radius was unknown. It is now measured (`norviq/redteam/precision.py`), so a control with no
    measured false positive enforces on evidence instead of shipping inert. A security product whose
    controls all start switched off protects nothing until configured.

    What still protects the customer is narrower and is asserted here plus in
    tests/redteam/test_benign_precision.py::TestShippedDefaultsAreEarned:
      * the GLOBAL fallback stays `monitor`, so a control nobody has measured ships observing;
      * every control that ships `deny` is clean over the benign corpus;
      * a control the preset registers as audit-only never ships `deny`.
    """
    assert baseline.DEFAULT_EFFECT == "monitor", "the fallback for an unmeasured control must stay safe"

    effects = baseline.default_effects(PRESET)
    assert set(effects.values()) == {"deny", "monitor"}, "defaults are per control, not one global"
    assert effects["deny_shell_execution"] == "deny"
    assert effects["scope_violation_dangerous_tool"] == "monitor"

    # And it is not cosmetic: the default configuration must COMPILE blocking heads. Seeding
    # `normalize_effects` from the global left every default enforcing on paper and observing in the
    # module, which is the failure this assertion exists to catch.
    src = baseline.compile(PRESET, effects)
    assert "\nblocks[" in src, "the shipped default produces no blocking head — defaults are inert"


def test_describe_surfaces_the_false_positive_caveats() -> None:
    """An operator promoting a control to deny needs to know what it will cost, at that moment."""
    by_id = {c["id"]: c for c in baseline.describe(PRESET)}
    shell = by_id["deny_shell_execution"]["caveat"]
    assert "1 in 8" in shell
    # ...and it must say that rate is HISTORY. The base64 misfire was fixed by C2-023 and the
    # prose-metacharacter one by exec-name gating, but the caveat kept describing both in the present
    # tense while the control shipped `deny` — so the console warned operators off enforcing a control
    # whose stated cost no longer existed. Asserting the substring alone cannot tell the tenses apart,
    # which is why it passed either way.
    assert "Fixed in 0.2.1" in shell, (
        "the caveat states a false-positive rate that was fixed in 0.2.1; it must say so, or it "
        "reads as a live defect in the console's own UI"
    )
    assert "SSN" in by_id["pii_detection"]["caveat"]
    assert by_id["deny_shell_execution"]["effect"] == "deny"


def test_an_audit_authored_control_can_actually_be_promoted_to_deny() -> None:
    """BUG: `deny` restored the head's ORIGINAL set, so a control the preset authors as an audit went
    straight back into audits[] and could never block — while the API reported it under "enforcing"
    and the console showed effect="deny". Being told twice that a control is enforcing while the call
    proceeds is worse than not offering the setting.

    `scope_violation_dangerous_tool` is the one in the shipped preset; asserted by shape rather than by
    name so a second audit-authored control added later is covered too.
    """
    audit_authored = {h.control_id for h in baseline.controls_for(PRESET) if h.set_name == "audits"}
    assert audit_authored, "fixture assumption changed — no audit-authored control in the preset"

    compiled = baseline.compile(PRESET, {cid: "deny" for cid in baseline.control_ids(PRESET)})
    _, region, _ = baseline._split_region(compiled)
    by_id: dict[str, set[str]] = {}
    for head in baseline.parse_heads(region):
        by_id.setdefault(head.control_id, set()).add(head.set_name)

    for cid in audit_authored:
        assert by_id[cid] == {"blocks"}, f"{cid} at deny is still an audit — it cannot block"


def test_an_audit_authored_control_still_only_records_at_monitor() -> None:
    """The other half: promoting it must be possible, and NOT promoting it must change nothing."""
    audit_authored = {h.control_id for h in baseline.controls_for(PRESET) if h.set_name == "audits"}
    compiled = baseline.compile(PRESET, {cid: "monitor" for cid in baseline.control_ids(PRESET)})
    _, region, _ = baseline._split_region(compiled)
    for head in baseline.parse_heads(region):
        if head.control_id in audit_authored:
            assert head.set_name == "audits"


def test_enforced_as_reports_what_deny_ACTUALLY_does():
    """The console said "call is blocked" under Enforce for every control, and two of them escalate.

    The compiler preserves a head's original severity — a control registered as `escalates[...]` still
    escalates when the operator sets it to `deny`. One sentence for every row made the MCP controls
    that hold a call for a human advertise a hard denial: an operator would either expect an outage
    that never comes, or decline to enforce a control that would not have broken anything.

    Read from the PRESET's own heads rather than a table, for the same reason the shipped-default guard
    is: the author's expressed severity is a signal, and a second copy of it drifts.
    """
    assert baseline.enforced_as("strict", "mcp_definition_drift") == "escalate"
    assert baseline.enforced_as("strict", "mcp_definition_never_scanned") == "escalate"
    assert baseline.enforced_as("strict", "deny_sql_injection") == "block"
    assert baseline.enforced_as("strict", "scope_violation_dangerous_tool") == "audit"


def test_a_control_with_heads_in_two_sets_reports_the_STRONGEST():
    """`llm06_excessive_agency` registers in both `blocks` and `escalates`. Reporting the weaker one
    would understate what enforcing costs, which is the direction that matters."""
    assert baseline.enforced_as("strict", "llm06_excessive_agency") == "block"


def test_the_wire_format_carries_it():
    rows = {r["id"]: r for r in baseline.describe("strict")}
    assert rows["mcp_definition_drift"]["enforced_as"] == "escalate"
    assert all(r["enforced_as"] in ("block", "escalate", "audit") for r in rows.values())
