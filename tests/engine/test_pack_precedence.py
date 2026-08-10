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


# --- ties are broken on the EFFECTIVE decision, not the raw one -------------------------------------

def _rm(key: str, decision: str, priority: int, mode: str, overlay: bool) -> dict:
    return {"key": key, "decision": SimpleNamespace(decision=decision), "priority": priority,
            "enforcement_mode": mode, "overlay": overlay}


def test_a_hard_floor_block_beats_an_audit_mode_base_block() -> None:
    """A `block` from an audit-mode policy is softened to `audit` by _apply_policy_mode moments later,
    so it is not really a block. Ranking it as one made two layers look equally strict when only one
    would stop the call — and a tie returns the BASE.

    Caught live the moment the controls tier became a floor: the chart's `__baseline__` (audit mode)
    and the controls floor (block mode) both said block, the tie handed attribution to the baseline,
    and a control set to Enforce came back as `policy_audit_would_block:` for a class that had no
    policy of its own. The floor fixed one hole and a tiebreak quietly opened another.
    """
    winner = _ev._resolve_with_packs([
        _rm("ns:__baseline__", "block", 1, "audit", False),
        _rm("ns:__controls__", "block", 2, "block", True),
    ])
    assert winner["key"] == "ns:__controls__"
    assert winner["enforcement_mode"] == "block"


def test_an_audit_mode_overlay_does_not_steal_a_hard_base_block() -> None:
    # Symmetry: the same reasoning must not let a soft overlay outrank a base that really blocks.
    winner = _ev._resolve_with_packs([
        _rm("ns:support", "block", 100, "block", False),
        _rm("ns:__controls__", "block", 2, "audit", True),
    ])
    assert winner["key"] == "ns:support"


def test_effective_rank_only_softens_block_and_escalate() -> None:
    # An audit-mode policy that decided `allow` is still an allow — softening is not a downgrade of
    # everything, only of the two decisions that would have interrupted the call.
    assert _ev._effective_rank(_rm("k", "allow", 1, "audit", False)) == 3
    assert _ev._effective_rank(_rm("k", "audit", 1, "audit", False)) == 2
    assert _ev._effective_rank(_rm("k", "block", 1, "audit", False)) == 2
    assert _ev._effective_rank(_rm("k", "block", 1, "block", False)) == 0


# --- BUG-014: an audit-mode layer must OBSERVE, never disarm ----------------------------------------
#
# `audit` is the documented safe way to trial a rule. Ranked by priority alongside real decisions, a
# higher-priority audit-mode policy won precedence anyway and `_apply_policy_mode` then softened its
# block to an audit — discarding a lower-priority policy that would actually have blocked. Trialling a
# rule the safe way was what switched enforcement off.
#
# Same shape as the base-vs-floor tie fixed alongside it: the engine reasoned about EFFECTIVE decisions
# in one place and raw decisions in the other.

def test_an_audit_mode_policy_cannot_disarm_a_lower_priority_enforcing_one() -> None:
    winner = _ev._resolve_with_packs([
        _rm("ns:support", "block", 200, "audit", False),      # the trial rule, higher priority
        _rm("ns:__baseline__", "block", 100, "block", False),  # the policy actually enforcing
    ])
    assert winner["key"] == "ns:__baseline__"
    assert winner["enforcement_mode"] == "block"


def test_an_audit_mode_policy_still_tightens_an_allow_to_audit() -> None:
    # Monitor mode's entire purpose: record a call the enforcing layer permits, without interrupting
    # it. `audit` is stricter than `allow`, so the observation survives.
    winner = _ev._resolve_with_packs([
        _rm("ns:support", "block", 200, "audit", False),
        _rm("ns:__baseline__", "allow", 100, "block", False),
    ])
    assert winner["key"] == "ns:support"


def test_priority_still_lets_a_higher_tier_LOOSEN_when_it_is_really_enforcing() -> None:
    # The headline precedence contract, and the reason this is not simply most-restrictive-wins: a
    # per-class allowlist authored at 200 is MEANT to loosen a baseline at 1.
    winner = _ev._resolve_with_packs([
        _rm("ns:support", "allow", 200, "block", False),
        _rm("ns:__baseline__", "block", 1, "block", False),
    ])
    assert winner["key"] == "ns:support"
    assert winner["decision"].decision == "allow"


def test_a_lone_audit_policy_still_produces_its_own_decision() -> None:
    # With nothing enforcing, the observation IS the decision — it is softened downstream by
    # _apply_policy_mode, which is how a would-block gets recorded at all.
    winner = _ev._resolve_with_packs([_rm("ns:support", "block", 200, "audit", False)])
    assert winner["key"] == "ns:support"


def test_two_audit_policies_resolve_between_themselves_by_priority() -> None:
    winner = _ev._resolve_with_packs([
        _rm("ns:low", "block", 10, "audit", False),
        _rm("ns:high", "block", 900, "audit", False),
    ])
    assert winner["key"] == "ns:high"
