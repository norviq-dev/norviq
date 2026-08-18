# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The benign corpus, and the precision number that decides what ships enforcing.

`ATTACKS` measures recall. Without a precision counterpart, "this control is safe to enforce" was an
opinion — and three separate times it was wrong in production-shaped traffic (BUG-005's date→SSN,
C2-023's base64 shell misfire, F-012 × F-046's pagination cursor). These tests keep the corpus honest
and keep the number from silently meaning nothing.
"""

from __future__ import annotations

import shutil
from collections import Counter

import pytest

from norviq.api import baseline
from norviq.redteam.benign import BENIGN, BenignDefinition, get_benign_by_id, regression_guards
from norviq.redteam.precision import measure

_OPA = shutil.which("opa")
pytestmark = pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the baseline")

#: Controls intended to ship at `deny`. The corpus is what earns a place on this list.
_PROMOTION_CANDIDATES = [
    "deny_shell_execution",
    "deny_sql_injection",
    "deny_sql_multi_statement",
    "ssrf_metadata",
    "dangerous_scheme",
    "cross_tenant_access",
    "pii_detection",
]


class TestTheCorpusIsWellFormed:
    """A corpus that quietly references a control that does not exist measures nothing."""

    def test_it_is_not_empty(self) -> None:
        assert len(BENIGN) >= 20, "a handful of cases cannot support a rate"

    def test_ids_are_unique(self) -> None:
        ids = [c.id for c in BENIGN]
        assert len(ids) == len(set(ids))

    def test_every_named_control_actually_exists(self) -> None:
        """A typo in `at_risk_controls` or `expected_blocked_by` silently disables the check it was
        written to perform — the same class of defect as a control head that fails to parse."""
        known = set(baseline.control_ids("strict"))
        for case in BENIGN:
            named = set(case.at_risk_controls)
            if case.historically_tripped:
                named.add(case.historically_tripped)
            if case.expected_blocked_by:
                named.add(case.expected_blocked_by)
            unknown = named - known
            assert not unknown, f"{case.id} names controls that do not exist: {sorted(unknown)}"

    def test_every_case_explains_itself(self) -> None:
        """The rationale IS the failure message. A case without one is unactionable when it fires."""
        for case in BENIGN:
            assert len(case.rationale) > 40, f"{case.id} needs a real rationale"

    def test_lookup_helpers(self) -> None:
        assert get_benign_by_id("BN-DATE-002") is not None
        assert get_benign_by_id("nope") is None


class TestPrecision:
    def test_no_control_blocks_legitimate_traffic(self) -> None:
        """The headline. Every case is a call a real agent would make.

        A failure here names the case and its rationale, so the finding reads as "a delivery date is
        not a birth date" rather than "some input broke".
        """
        report = measure("strict")
        if report.by_control:
            detail = "\n".join(
                f"  {cid}: {', '.join(e.fired_on)}"
                + "".join(f"\n      {get_benign_by_id(i).rationale}" for i in e.fired_on)
                for cid, e in report.by_control.items()
            )
            pytest.fail(f"controls fired on legitimate traffic:\n{detail}")

    def test_the_promotion_candidates_are_all_clean(self) -> None:
        """The list a shipped default is drawn from. `deny_shell_execution` was ON this list and was
        NOT clean until the bare-metacharacter arm was gated on an exec-shaped tool name — which is
        exactly the check this corpus exists to perform before a control ships enforcing."""
        report = measure("strict")
        clean = report.controls_with_zero_false_positives(_PROMOTION_CANDIDATES)
        assert sorted(clean) == sorted(_PROMOTION_CANDIDATES), (
            f"not promotable: {sorted(set(_PROMOTION_CANDIDATES) - set(clean))}")

    def test_a_by_design_refusal_is_not_counted_as_a_false_positive(self) -> None:
        """`strict` declines `execute_sql` by name however well-formed the query is. Folding that into
        the rate would make the number unactionable — and hide a real false positive behind it."""
        report = measure("strict")
        assert report.expected_refusals >= 1
        assert report.measured == report.total - report.expected_refusals
        assert report.false_positive_rate == 0.0

    def test_a_by_design_refusal_by_the_WRONG_control_still_counts(self) -> None:
        """Attribution matters: if an injection rule catches the parameterised SELECT before
        `strict_default_block` does, the audit log blames the wrong control. Only a block by the
        NAMED control is excused."""
        case = get_benign_by_id("BN-RD-003")
        assert case is not None and case.expected_blocked_by == "strict_default_block"
        impostor = BenignDefinition(
            id=case.id, name=case.name, category=case.category, tool_name=case.tool_name,
            tool_params=case.tool_params, rationale=case.rationale,
            expected_blocked_by="deny_sql_injection",  # not the control that actually refuses it
        )
        report = measure("strict", cases=[impostor])
        assert report.expected_refusals == 0, "a block by another control must not be excused"
        assert report.by_control, "it should be reported as a false positive instead"


class TestTheRegressionGuards:
    """Cases a shipped fix already made safe. A firing here names the fix that regressed."""

    def test_there_are_guards_for_all_three_known_misfires(self) -> None:
        tripped = {c.historically_tripped for c in regression_guards()}
        assert {"pii_detection", "deny_shell_execution", "llm02_data_leakage"} <= tripped

    def test_none_of_them_fire(self) -> None:
        report = measure("strict", cases=regression_guards())
        assert not report.by_control, (
            f"a previously-fixed false positive is back: {report.blocked}")


def test_a_missing_opa_raises_rather_than_reading_as_zero() -> None:
    """The false green this whole module exists to prevent: a precision run that measured nothing
    must not report a clean bill of health."""
    import norviq.redteam.precision as precision

    original = precision.shutil.which
    precision.shutil.which = lambda _name: None
    try:
        with pytest.raises(RuntimeError, match="must not read as 0"):
            precision.measure("strict")
    finally:
        precision.shutil.which = original


# ── the shipped defaults must be justifiable from the two independent signals ──────────────────────

class TestShippedDefaultsAreEarned:
    """A `deny` default is a claim. These are the two things that have to be true for it.

    Both signals are needed and neither is sufficient. Precision says the control does not touch
    legitimate traffic; the preset's own head set says the author meant it to block at all. A control
    can pass one and fail the other.
    """

    def test_every_control_is_exercised_by_at_least_one_case(self) -> None:
        """A control nothing reaches scores clean for want of an input, not on merit.

        Three controls — llm05_supply_chain, chain_depth_limit, scope_violation_dangerous_tool — were
        unexercised by the first version of this corpus and so read as clean. Two of them were not
        reachable at all until the harness carried `call_depth` and `agent_class`.
        """
        exercised: set[str] = set()
        for case in BENIGN:
            exercised.update(case.at_risk_controls)
            if case.expected_blocked_by:
                exercised.add(case.expected_blocked_by)
        missing = set(baseline.control_ids("strict")) - exercised
        assert not missing, f"controls no benign case reaches: {sorted(missing)}"

    def test_nothing_ships_deny_that_the_preset_registers_as_observe_only(self) -> None:
        """The second signal, as a guard rather than reviewer memory.

        `scope_violation_dangerous_tool` registers as `audits[...]` — the preset author made it
        observe-only by construction. Shipping it at `deny` would contradict the source while looking
        like a considered product decision.
        """
        native: dict[str, set[str]] = {}
        for head in baseline.controls_for("strict"):
            native.setdefault(head.control_id, set()).add(head.set_name)

        for cid, sets in native.items():
            if sets == {"audits"}:
                assert baseline.shipped_default(cid) != "deny", (
                    f"{cid} is registered audit-only in the preset but ships at deny")

    def test_every_deny_default_is_clean_over_the_corpus(self) -> None:
        """The first signal. Anything shipping enforcing must have touched nothing legitimate."""
        report = measure("strict")
        enforcing = [c for c in baseline.control_ids("strict")
                     if baseline.shipped_default(c) == "deny"]
        assert enforcing, "if nothing ships enforcing this test is vacuous"
        dirty = [c for c in enforcing if c in report.by_control]
        assert not dirty, f"shipping enforcing despite measured false positives: {dirty}"

    def test_a_control_with_no_considered_default_stays_conservative(self) -> None:
        """Falling back to the global means an unmeasured control ships inert, not enforcing."""
        assert baseline.shipped_default("a_control_nobody_has_measured") == baseline.DEFAULT_EFFECT
        assert baseline.DEFAULT_EFFECT == "monitor"

    def test_default_effects_uses_the_per_control_value(self) -> None:
        effects = baseline.default_effects("strict")
        assert effects["deny_shell_execution"] == "deny"
        assert effects["scope_violation_dangerous_tool"] == "monitor"
        assert len(set(effects.values())) > 1, "a single value means the per-control wiring is not live"

    def test_the_wire_format_carries_the_per_control_default_and_plane(self) -> None:
        """The console renders differs-from-default off this; one global value made the marker lie."""
        rows = {r["id"]: r for r in baseline.describe("strict")}
        assert rows["deny_shell_execution"]["default_effect"] == "deny"
        assert rows["scope_violation_dangerous_tool"]["default_effect"] == "monitor"
        assert all(r["plane"] in ("discovery", "call", "response") for r in rows.values())


class TestControlSurface:
    """`surface` is the axis the console groups on at the top level: WHAT a control governs.

    It is deliberately server-side and NOT derived from an `mcp_` id prefix in the console. The prefix
    is a naming convention nothing enforces, so a future MCP control named without it would land
    silently in the tool group — the one place an operator would never look for it.
    """

    def test_every_control_declares_a_surface(self) -> None:
        rows = baseline.describe("strict")
        assert rows, "no controls described"
        assert all(r["surface"] in ("tool", "mcp") for r in rows)

    def test_the_mcp_controls_are_the_ones_that_read_input_mcp(self) -> None:
        """The grouping must follow what a control actually reads, not what it is called."""
        rows = {r["id"]: r for r in baseline.describe("strict")}
        mcp = {cid for cid, r in rows.items() if r["surface"] == "mcp"}
        assert mcp == {cid for cid in rows if cid.startswith("mcp_")}, (
            "surface and the mcp_ naming convention disagree — one of them is wrong"
        )
        assert len(mcp) >= 5, "the MCP group lost controls"

    def test_both_groups_are_non_empty(self) -> None:
        """A surface with no controls renders as a heading over nothing."""
        rows = baseline.describe("strict")
        by_surface = Counter(r["surface"] for r in rows)
        assert by_surface["tool"] > 0 and by_surface["mcp"] > 0

    def test_an_unknown_control_id_defaults_to_the_tool_surface(self) -> None:
        """Matches the client's `?? "tool"` fallback, so an old payload groups rather than vanishes."""
        assert baseline.surface_of("a_control_nobody_has_measured") == "tool"
