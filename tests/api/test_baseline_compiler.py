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


def test_the_shipped_default_is_monitor_for_every_control() -> None:
    """Nothing is dropped on a fresh install — the premise of the whole feature."""
    assert baseline.DEFAULT_EFFECT == "monitor"
    assert set(baseline.default_effects(PRESET).values()) == {"monitor"}


def test_describe_surfaces_the_false_positive_caveats() -> None:
    """An operator promoting a control to deny needs to know what it will cost, at that moment."""
    by_id = {c["id"]: c for c in baseline.describe(PRESET)}
    assert "1 in 8" in by_id["deny_shell_execution"]["caveat"]
    assert "SSN" in by_id["pii_detection"]["caveat"]
    assert by_id["deny_shell_execution"]["effect"] == "monitor"


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
