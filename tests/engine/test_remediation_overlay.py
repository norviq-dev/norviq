# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Data-loss fix: a compliance-remediation draft ("Generate enforcing policy" for a gap
technique) must be an ADDITIVE, per-class, tighten-only OVERLAY — never a replacement for the class's
existing comprehensive policy. It is applied at the dedicated key ``(ns, "<class>__remediation__")``,
resolved by the evaluator as an overlay candidate (mirrors ``__pack__``/``__guardrail__``), so the base
``(ns, class)`` policy is left byte-identical and still enforcing.

Mirrors ``tests/engine/test_pack_precedence.py`` (resolution-logic unit tests, no I/O) plus
``tests/engine/test_evaluator_unit.py``'s ``_collect_candidates`` fixture pattern (async, fake loader)."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

# _resolve_with_packs / _resolve_precedence / _is_overlay use no instance state; build a bare evaluator.
_ev = OPAEvaluator.__new__(OPAEvaluator)


def _r(key: str, decision: str, priority: int, overlay: bool | None = None) -> dict:
    # _resolve_with_packs now partitions on the "overlay" PROVENANCE flag (set at candidate
    # construction in production), not a key-suffix guess. Default to the key-suffix heuristic here so existing
    # key-driven cases below need no changes; pass `overlay=` explicitly to simulate a real base class whose
    # name happens to collide with the reserved "__remediation__" suffix (this overlay-provenance regression case).
    if overlay is None:
        overlay = _ev._is_overlay(key)
    return {"key": key, "decision": SimpleNamespace(decision=decision), "priority": priority, "overlay": overlay}


def _winner(results: list[dict]) -> str:
    return _ev._resolve_with_packs(results)["decision"].decision


# --- _is_overlay: the per-class remediation overlay key is recognised by its dynamic suffix -------------

def test_remediation_overlay_is_overlay() -> None:
    assert _ev._is_overlay("default:report-gen__remediation__") is True


def test_base_class_is_not_overlay() -> None:
    # sanity: the real class's OWN key (no suffix) must never be misclassified as an overlay.
    assert _ev._is_overlay("default:report-gen") is False


# --- resolution semantics: additive + tighten-only, exactly like __pack__/__guardrail__ -------------------

def test_remediation_overlay_tightens_an_allowing_base() -> None:
    # base class policy allows everything; the remediation overlay adds a block for one control -> BLOCK wins.
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:report-gen__remediation__", "block", 1),
    ]) == "block"


def test_remediation_overlay_cannot_weaken_a_blocking_base() -> None:
    # SECURITY ACCEPTANCE (invariant b): a remediation overlay that tries to ALLOW something the base
    # already BLOCKS must NEVER weaken that decision — the base block holds.
    assert _winner([
        _r("default:report-gen", "block", 700),
        _r("default:report-gen__remediation__", "allow", 999),
    ]) == "block"


def test_remediation_overlay_escalate_tightens_an_allow() -> None:
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:report-gen__remediation__", "escalate", 1),
    ]) == "escalate"


def test_remediation_overlay_alone_resolves_to_its_own_decision() -> None:
    # a brand-new class with only the overlay (no base policy yet) still resolves sanely.
    assert _winner([_r("default:report-gen__remediation__", "block", 1)]) == "block"


def test_two_classes_remediation_overlays_do_not_cross_apply() -> None:
    # a remediation overlay for class A must never affect class B's resolution — they are different keys
    # entirely, so a candidate set for B never includes A's overlay in the first place. Documented here via
    # the key-scoping the evaluator relies on (asserted directly, not through _resolve_with_packs).
    assert _ev._is_overlay("default:report-gen__remediation__") is True
    assert _ev._is_overlay("default:billing-agent__remediation__") is True
    assert "default:report-gen__remediation__" != "default:billing-agent__remediation__"


# --- H6 fix: __pack_weaken__ may relax a PACK'S OWN block, but must NEVER relax a HARD tighten-only overlay
# (__guardrail__ / *__remediation__). Before the fix, _resolve_overlay's weaken exception unconditionally
# returned the weaken candidate whenever ANY __pack_weaken__ existed, discarding every other overlay — including
# a guardrail or remediation block that has nothing to do with the pack the weaken was meant to relax. -------

def test_pack_weaken_cannot_neutralize_a_remediation_block() -> None:
    # base ALLOWS + remediation BLOCKS + an unrelated pack_weaken (default-allow) present -> BLOCK must survive.
    # This is the exact H6 regression: pre-fix this resolved to "allow" (compliance gap silently reopened).
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:report-gen__remediation__", "block", 1),
        _r("default:__pack_weaken__", "allow", 5),
    ]) == "block"


def test_pack_weaken_cannot_neutralize_a_guardrail_block() -> None:
    # same regression, for the F-14 operator guardrail instead of a remediation overlay.
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:__guardrail__", "block", 500),
        _r("default:__pack_weaken__", "allow", 5),
    ]) == "block"


def test_pack_weaken_cannot_neutralize_guardrail_even_at_much_higher_priority() -> None:
    # priority must never let a pack_weaken reach outside the pack family, no matter how it's tuned.
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:__guardrail__", "block", 1),
        _r("default:__pack_weaken__", "allow", 9999),
    ]) == "block"


def test_pack_weaken_still_relaxes_its_own_pack_family() -> None:
    # do-not-over-fix: the LEGITIMATE case (weaken relaxing __pack__'s own block) must still work.
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:__pack__", "block", 800),
        _r("default:__pack_weaken__", "allow", 805),
    ]) == "allow"


def test_pack_weaken_still_relaxes_pack_override_too() -> None:
    # the pack family includes __pack_override__ as well as __pack__ — both may be relaxed by a weaken.
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:__pack__", "block", 800),
        _r("default:__pack_override__", "block", 850),
        _r("default:__pack_weaken__", "allow", 1),
    ]) == "allow"


def test_guardrail_and_remediation_block_combine_most_restrictive_with_pack_family() -> None:
    # a hard overlay block always beats a pack-family allow (weaken relaxed the pack, but the guardrail holds).
    assert _winner([
        _r("default:report-gen", "allow", 700),
        _r("default:__pack__", "block", 800),
        _r("default:__pack_weaken__", "allow", 805),   # legitimately relaxes the pack back to allow
        _r("default:__guardrail__", "block", 500),      # but the guardrail still blocks independently
    ]) == "block"


# --- Overlay-ness comes from provenance, not a key-string suffix. A real agent_class whose OWN name
# happens to end in the reserved "__remediation__" suffix must keep its normal priority-based precedence — its
# base policy must never be misclassified as an overlay and lose to a lower-priority baseline. ------------------

def test_class_named_like_remediation_suffix_keeps_base_precedence() -> None:
    # PROVENANCE regression: a real ServiceAccount happens to be named "billing-agent__remediation__". Its OWN
    # base policy (a high-priority allow) must win over a low-priority cluster baseline block — because it is a
    # BASE candidate (overlay=False), not an overlay, regardless of its key's suffix.
    assert _winner([
        _r("default:billing-agent__remediation__", "allow", 900, overlay=False),  # the class's own base policy
        _r("__cluster__:__baseline__", "block", 100, overlay=False),               # low-priority cluster floor
    ]) == "allow"


def test_class_named_like_remediation_suffix_is_not_treated_as_overlay_by_resolver() -> None:
    # same scenario, but proves it via the overlay/base partition directly: with overlay=False tagged at
    # construction, a real class's own key is placed in the BASE list, not the overlay list, so ordinary
    # highest-priority-wins governs it (not overlay tighten-only semantics).
    winner = _ev._resolve_with_packs([
        _r("default:billing-agent__remediation__", "block", 100, overlay=False),
        _r("default:__pack__", "allow", 999, overlay=True),  # an overlay may not weaken this base's block anyway
    ])
    assert winner["decision"].decision == "block"


# --- _collect_candidates / _collect_candidates_union: the overlay is looked up + appended additively -----

@dataclass
class _LoaderStub:
    _policies: dict[str, dict]

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return self._policies.get(f"{namespace}:{agent_class}")

    async def namespaces_for_class(self, agent_class: str) -> list[str]:
        return sorted({ns for ns, _, ac in (k.partition(":") for k in self._policies) if ac == agent_class})


def _evaluator_with(policies: dict[str, dict]) -> OPAEvaluator:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    ev._loader = _LoaderStub(policies)  # type: ignore[attr-defined]
    return ev


def _event(namespace: str = "default", agent_class: str = "report-gen") -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="delete_record", tool_params={},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{namespace}/sa/{agent_class}", namespace=namespace, agent_class=agent_class,
        ),
        session_id="remediation-overlay-test",
    )


@pytest.mark.asyncio
async def test_collect_candidates_includes_remediation_overlay_when_present() -> None:
    ev = _evaluator_with({
        "default:report-gen": {"rego": "package a", "priority": 700},
        "default:report-gen__remediation__": {"rego": "package b", "priority": 1},
    })
    keys = {c["key"] for c in await ev._collect_candidates(_event())}
    assert "default:report-gen" in keys           # base class untouched, still collected
    assert "default:report-gen__remediation__" in keys  # overlay additively collected


@pytest.mark.asyncio
async def test_collect_candidates_absent_remediation_overlay_costs_nothing() -> None:
    # zero-hot-path-cost invariant: no overlay for this class -> no load_from_db probe, no candidate.
    ev = _evaluator_with({"default:report-gen": {"rego": "package a", "priority": 700}})
    keys = {c["key"] for c in await ev._collect_candidates(_event())}
    assert "default:report-gen__remediation__" not in keys


@pytest.mark.asyncio
async def test_collect_candidates_remediation_overlay_scoped_to_its_own_class() -> None:
    # a remediation overlay for "billing-agent" must never leak into "report-gen"'s candidate set.
    ev = _evaluator_with({
        "default:report-gen": {"rego": "package a", "priority": 700},
        "default:billing-agent__remediation__": {"rego": "package other", "priority": 1},
    })
    keys = {c["key"] for c in await ev._collect_candidates(_event(agent_class="report-gen"))}
    assert "default:billing-agent__remediation__" not in keys


@pytest.mark.asyncio
async def test_collect_candidates_union_includes_remediation_overlay() -> None:
    # the console's namespace="all" picker (_collect_candidates_union) mirrors the same overlay lookup.
    ev = _evaluator_with({
        "prod:report-gen": {"rego": "package a", "priority": 700},
        "prod:report-gen__remediation__": {"rego": "package b", "priority": 1},
    })
    keys = {c["key"] for c in await ev._collect_candidates_union("report-gen")}
    assert "prod:report-gen__remediation__" in keys


# --- End-to-end at the construction layer: _collect_candidates must tag "overlay" by PROVENANCE, so a
# real agent_class literally named "<x>__remediation__" gets its OWN base policy tagged overlay=False, while an
# actual per-class remediation overlay for a DIFFERENT class is tagged overlay=True. -------------------------

@pytest.mark.asyncio
async def test_collect_candidates_tags_overlay_by_provenance_not_key_suffix() -> None:
    # "billing-agent__remediation__" here is a REAL agent_class (collision with the reserved suffix), not an
    # overlay of some "billing-agent" class. Its own base-policy candidate must be tagged overlay=False.
    weird_class = "billing-agent__remediation__"
    ev = _evaluator_with({
        f"default:{weird_class}": {"rego": "package a", "priority": 900},
    })
    candidates = await ev._collect_candidates(_event(agent_class=weird_class))
    own = next(c for c in candidates if c["key"] == f"default:{weird_class}")
    assert own.get("overlay", False) is False  # base policy, never an overlay, regardless of its key's suffix


@pytest.mark.asyncio
async def test_collect_candidates_real_remediation_overlay_is_tagged_overlay_true() -> None:
    ev = _evaluator_with({
        "default:report-gen": {"rego": "package a", "priority": 700},
        "default:report-gen__remediation__": {"rego": "package b", "priority": 1},
    })
    candidates = await ev._collect_candidates(_event(agent_class="report-gen"))
    base = next(c for c in candidates if c["key"] == "default:report-gen")
    overlay = next(c for c in candidates if c["key"] == "default:report-gen__remediation__")
    assert base.get("overlay", False) is False
    assert overlay.get("overlay", False) is True
