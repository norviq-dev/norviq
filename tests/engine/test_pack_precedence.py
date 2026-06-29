# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F047: a sector pack is an ADDITIVE-ONLY overlay — it can only TIGHTEN the base decision
(block < escalate < audit < allow), never loosen it, regardless of priority (the F-07 trap)."""

from __future__ import annotations

from types import SimpleNamespace

from norviq.engine.evaluator import OPAEvaluator

# _resolve_with_packs / _resolve_precedence use no instance state; build a bare evaluator.
_ev = OPAEvaluator.__new__(OPAEvaluator)


def _r(key: str, decision: str, priority: int) -> dict:
    return {"key": key, "decision": SimpleNamespace(decision=decision), "priority": priority}


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
