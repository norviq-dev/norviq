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


# --- F-54: the per-namespace pack override is the SAME tighten-only overlay class ---

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
