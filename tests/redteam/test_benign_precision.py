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
