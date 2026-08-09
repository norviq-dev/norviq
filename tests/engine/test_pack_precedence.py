# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A sector pack is an ADDITIVE-ONLY overlay — it can only TIGHTEN the base decision
(block < escalate < audit < allow), never loosen it, regardless of priority."""

from __future__ import annotations

from types import SimpleNamespace

from norviq.engine.evaluator import OPAEvaluator

# _resolve_with_packs / _resolve_precedence use no instance state; build a bare evaluator.
_ev = OPAEvaluator.__new__(OPAEvaluator)


def _r(key: str, decision: str, priority: int, overlay: bool | None = None) -> dict:
    # _resolve_with_packs now partitions on the "overlay" PROVENANCE flag (set at candidate
    # construction in production), not a key-suffix guess. Default to the key-suffix heuristic here (matches
    # how these fixed overlay names — __pack__/__guardrail__/__pack_override__/__pack_weaken__ — are always
    # tagged in production) so existing key-driven test cases below need no changes; pass `overlay=` explicitly
    # to simulate a real base class whose name happens to collide with a reserved suffix.
    if overlay is None:
        overlay = _ev._is_overlay(key)
    return {"key": key, "decision": SimpleNamespace(decision=decision), "priority": priority, "overlay": overlay}


def _winner(results: list[dict]) -> str:
    return _ev._resolve_with_packs(results)["decision"].decision


def test_pack_allow_never_overrides_specific_block() -> None:
    assert _winner([_r("ns:cs", "block", 700), _r("ns:__pack__", "allow", 800)]) == "block"


def test_pack_block_enforces_over_specific_allow() -> None:
    assert _winner([_r("ns:cs", "allow", 700), _r("ns:__pack__", "block", 800)]) == "block"


def test_pack_block_enforces_over_higher_priority_baseline_allow() -> None:
    # the motivating case: a comprehensive cluster baseline at 900 ALLOWS; the pack at 800 BLOCKS ->
    # the pack still wins because it only tightens (priority is not the mechanism).
    assert _winner([_r("ns:__baseline__", "allow", 900), _r("ns:__pack__", "block", 800)]) == "block"


def test_pack_escalate_does_not_loosen_a_specific_block() -> None:
    # a pack escalate must NOT downgrade a stricter block, even at higher priority.
    assert _winner([_r("ns:cs", "block", 700), _r("ns:__pack__", "escalate", 999)]) == "block"


def test_pack_escalate_tightens_an_allow() -> None:
    assert _winner([_r("ns:cs", "allow", 700), _r("ns:__pack__", "escalate", 800)]) == "escalate"


def test_pack_alone_allow_resolves_to_allow() -> None:
    assert _winner([_r("ns:__pack__", "allow", 800)]) == "allow"


def test_non_pack_precedence_unchanged() -> None:
    # no pack candidate -> ordinary highest-priority precedence is untouched.
    assert _winner([_r("ns:cs", "block", 100), _r("ns:__baseline__", "allow", 900)]) == "allow"


# --- the per-namespace pack override is the SAME tighten-only overlay class ---

def test_pack_override_is_overlay() -> None:
    assert _ev._is_overlay("ns:__pack_override__") is True


def test_override_tightens_an_allow() -> None:
    # an override can make a previously-allowed call BLOCK (the "edit a pack rule -> it blocks as edited" case).
    assert _winner([_r("ns:cs", "allow", 700), _r("ns:__pack_override__", "block", 850)]) == "block"


def test_override_never_weakens_a_pack_block() -> None:
    # ACCEPTANCE: the override must NEVER weaken/remove a pack's block — an override 'allow' cannot beat a pack block.
    assert _winner([_r("ns:__pack__", "block", 800), _r("ns:__pack_override__", "allow", 999)]) == "block"


def test_override_cannot_weaken_a_specific_block() -> None:
    assert _winner([_r("ns:cs", "block", 700), _r("ns:__pack_override__", "allow", 999)]) == "block"


# --- fleet-mgmt: the ADVANCED pack-WEAKEN overlay may relax a pack block, but is still floored by the base ---

def test_weaken_is_overlay() -> None:
    assert _ev._is_overlay("ns:__pack_weaken__") is True


def test_weaken_relaxes_a_pack_block() -> None:
    # the whole point of advanced-weaken: an admin overlay CAN relax a pack's added block (unlike __pack_override__).
    assert _winner([_r("ns:__pack__", "block", 800), _r("ns:__pack_weaken__", "allow", 805)]) == "allow"


def test_weaken_is_floored_by_the_comprehensive_base() -> None:
    # SECURITY ACCEPTANCE: a weaken can never drop BELOW the comprehensive baseline — base block holds.
    assert _winner([_r("ns:cs", "block", 700), _r("ns:__pack__", "block", 800), _r("ns:__pack_weaken__", "allow", 805)]) == "block"
    assert _winner([_r("ns:__baseline__", "block", 900), _r("ns:__pack_weaken__", "allow", 805)]) == "block"


def test_weaken_relaxes_pack_only_when_base_permits() -> None:
    # base ALLOWS + pack BLOCKS + weaken ALLOWS -> the pack restriction is relaxed back to the (permissive) base.
    assert _winner([_r("ns:cs", "allow", 700), _r("ns:__pack__", "block", 800), _r("ns:__pack_weaken__", "allow", 805)]) == "allow"


def test_weaken_can_still_tighten() -> None:
    # a weaken overlay that BLOCKS still tightens an allow (it supersedes the pack overlay but base floor still applies).
    assert _winner([_r("ns:cs", "allow", 700), _r("ns:__pack_weaken__", "block", 805)]) == "block"


# --- the baseline controls tier is a FLOOR ----------------------------------------------------------
#
# Measured on a live cluster before this was changed. `pii_detection` set to Enforce in a namespace,
# one SSN payload, two agent classes:
#
#     r2-support    (has a class policy @100)   allow   cde_default_allow
#     anything-else (no class policy)           block   pii_detection
#
# The controls tier was a BASE tier at priority 2, and base tiers resolve by highest priority
# OUTRIGHT — so a class policy authored at 100 discarded the controls' block entirely. Writing one
# unrelated policy silently switched all fourteen shipped detectors off for that class, while Target
# Settings still read "1 enforcing": true about the control's setting, and false about its reach.
#
# Tagged as an overlay the tier is tighten-only, so priority stops being the mechanism.

def test_controls_block_survives_a_higher_priority_class_policy_allow() -> None:
    # THE regression. Class policy at 100 allows; the controls floor at 2 blocks -> block.
    assert _winner([_r("ns:support", "allow", 100), _r("ns:__controls__", "block", 2, overlay=True)]) == "block"


def test_controls_audit_survives_a_class_policy_allow() -> None:
    # A control on Monitor must keep RECORDING on a class that has its own policy, or the compliance
    # view under-counts precisely the classes an operator has bothered to write policy for. `audit`
    # never interrupts a call, so restoring it costs nothing in availability.
    assert _winner([_r("ns:support", "allow", 100), _r("ns:__controls__", "audit", 2, overlay=True)]) == "audit"


def test_controls_never_weaken_a_stricter_class_policy() -> None:
    # Tighten-only cuts both ways: a control left on Monitor must not downgrade a class policy that
    # blocks. This is the property that makes the floor safe to turn on for existing customers.
    assert _winner([_r("ns:support", "block", 100), _r("ns:__controls__", "audit", 2, overlay=True)]) == "block"
    assert _winner([_r("ns:support", "block", 100), _r("ns:__controls__", "allow", 2, overlay=True)]) == "block"


def test_a_pack_weaken_cannot_relax_the_controls_floor() -> None:
    # __pack_weaken__ exists to dial back a sector pack's own addition. A control the operator
    # explicitly promoted to Enforce is not a pack's addition, and must survive it — the controls key
    # lands in the HARD partition of _resolve_overlay, which has no weaken exception.
    assert _winner([
        _r("ns:support", "allow", 100),
        _r("ns:__controls__", "block", 2, overlay=True),
        _r("ns:__pack_weaken__", "allow", 900),
    ]) == "block"


def test_the_floor_does_not_fire_when_the_control_is_off() -> None:
    # An `off` control emits no head at all, so it contributes no candidate decision. Modelled here as
    # an allow: it must leave the class policy exactly as it was.
    assert _winner([_r("ns:support", "allow", 100), _r("ns:__controls__", "allow", 2, overlay=True)]) == "allow"
