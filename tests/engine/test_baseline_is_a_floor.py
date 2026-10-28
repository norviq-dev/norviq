# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The chart's baselines must only tighten, whatever their priority and whatever their mode.

They were base tiers, resolved by priority outright. The chart's baseline is stored at
`<ns>:__baseline__`, priority 1, so any class policy outranked it; harmless while it shipped in `audit`
(an observer cannot win). From 0.2.6 it enforces, and measured on the pre-fix resolver an enforcing
baseline block lost to a class policy at 100 that allowed: writing any policy for a class switched the
baseline off for it. A baseline authored at a high priority (900) failed the other way: its allow beat a
tenant's block.
"""

from __future__ import annotations

from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.decisions import PolicyDecision

EV = OPAEvaluator.__new__(OPAEvaluator)


def _c(key: str, prio: int, decision: str, rule: str, mode: str = "block", overlay: bool = False) -> dict:
    return {"key": key, "priority": prio, "enforcement_mode": mode, "overlay": overlay,
            "decision": PolicyDecision(decision=decision, rule_id=rule)}


def _baseline(decision: str, rule: str, mode: str = "block", key: str = "__cluster__:__baseline__") -> dict:
    return _c(key, 900, decision, rule, mode, overlay=True)  # collected as a floor, as the evaluator now does


def _winner(*cands: dict) -> tuple[str, str]:
    w = EV._resolve_with_packs(list(cands))
    return w["decision"].decision, w["decision"].rule_id


def test_the_charts_baseline_still_blocks_for_a_class_with_its_own_policy() -> None:
    """The case the chart actually hits: baseline at priority 1, a class policy at 100 that allows."""
    floor = _c("agents:__baseline__", 1, "block", "deny_shell_execution", overlay=True)
    assert _winner(floor, _c("agents:support-agent", 100, "allow", "support_default_allow")) == \
        ("block", "deny_shell_execution")


def test_an_enforcing_baseline_allow_does_not_undo_a_tenant_block() -> None:
    assert _winner(_baseline("allow", "default_allow"),
                   _c("agents:support-agent", 100, "block", "support_no_arbitrary_sql")) == \
        ("block", "support_no_arbitrary_sql")


def test_the_namespace_baseline_is_a_floor_too() -> None:
    assert _winner(_baseline("allow", "default_allow", key="agents:__baseline__"),
                   _c("agents:support-agent", 100, "block", "support_no_arbitrary_sql")) == \
        ("block", "support_no_arbitrary_sql")


def test_a_tenant_allow_cannot_loosen_an_enforcing_baseline_block() -> None:
    assert _winner(_baseline("block", "deny_shell_execution"),
                   _c("agents:support-agent", 1000, "allow", "support_default_allow")) == \
        ("block", "deny_shell_execution")


def test_an_audit_baseline_still_only_observes() -> None:
    # 0.2.5 behaviour, kept for operators who opt back: the tenant's block stands...
    assert _winner(_baseline("allow", "default_allow", "audit"),
                   _c("agents:support-agent", 100, "block", "support_no_arbitrary_sql")) == \
        ("block", "support_no_arbitrary_sql")
    # ...and an audit baseline's block is the observation, not an enforcement.
    w = EV._resolve_with_packs([_baseline("block", "deny_shell_execution", "audit"),
                                _c("agents:support-agent", 100, "allow", "support_default_allow")])
    assert w["key"] == "__cluster__:__baseline__" and w["enforcement_mode"] == "audit"


def test_an_audit_baseline_cannot_mask_an_enforcing_guardrail() -> None:
    """Both say block; ranked raw, the audit baseline won on priority and was then softened to a record."""
    w = EV._resolve_with_packs([_baseline("block", "deny_shell_execution", "audit"),
                                _c("agents:__guardrail__", 100, "block", "guardrail_tool_not_allowed", overlay=True),
                                _c("agents:support-agent", 50, "allow", "support_default_allow")])
    assert w["key"] == "agents:__guardrail__" and w["enforcement_mode"] == "block"


def test_with_no_tenant_policy_the_baseline_decides() -> None:
    assert _winner(_baseline("block", "deny_sql_injection")) == ("block", "deny_sql_injection")
    assert _winner(_baseline("allow", "default_allow")) == ("allow", "default_allow")


def test_the_console_labels_the_baselines_as_floors() -> None:
    assert OPAEvaluator._is_overlay("__cluster__:__baseline__")
    assert OPAEvaluator._is_overlay("agents:__baseline__")
    assert not OPAEvaluator._is_overlay("agents:support-agent")
