# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""P1-2 REGO-CONTRACT-MISMATCH regression (fail-on-bug).

Two real defects, proven live on b227d8c, are fixed here:

- Defect 1 (validation form): `validate_policy_create` rejected the BARE partial-set idiom
  (`blocks[...]`/`escalates[...]`/`audits[...]` with no resolver) with a generic, unhelpful error, so a
  guardrail/pack-style policy could not be authored. It now emits a SPECIFIC, actionable error naming the
  missing resolver — while STILL requiring a decision (a partial-set with no resolver would silently allow).
- Defect 2 (push timeout / silent-allow): the module PUSH shared the tight query timeout, and a
  decision-less module defaulted to ALLOW while a block rule fired. Push now has its own larger timeout, and
  the engine fail-closes (`evaluator_invalid_payload`) when a partial-set rule fired but no `decision` was
  produced — without regressing a complete-rule policy whose condition simply didn't match.

These tests fail on the pre-fix code and pass on the fix.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from norviq.api.routers.policies import PolicyCreate, validate_policy_create
from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator

_RESOLVER = (
    'default decision = "allow"\n'
    'default rule_id = "default_allow"\n'
    'default reason = "Allowed"\n'
    "block_fired { blocks[_] }\n"
    'decision = "block" { block_fired }\n'
    'rule_id = sort([id | blocks[id]])[0] { block_fired }\n'
    'reason = "blocked" { block_fired }\n'
)


def _policy(rego: str) -> PolicyCreate:
    return PolicyCreate(
        namespace="scratch", agent_class="probe", enforcement_mode="block",
        priority=50, policy_name="t", rego_source=rego,
    )


# --- Defect 1: validator contract ----------------------------------------------------------------


def test_bare_partial_set_gets_specific_resolver_error() -> None:
    """A blocks-only rego with no resolver → 422 that NAMES the missing resolver (not the generic message)."""
    bare = 'package norviq.strict\nblocks["g"] { input.tool_name == "x" }\nrule_id = "g"\nreason = "r"\n'
    with pytest.raises(HTTPException) as ei:
        validate_policy_create(_policy(bare))
    assert ei.value.status_code == 422
    detail = ei.value.detail
    assert "partial-set" in detail and "resolver" in detail  # specific, actionable
    assert detail != "rego_source must include block or escalate decision"  # not the old generic message


def test_partial_set_with_resolver_validates() -> None:
    """The canonical pack/comprehensive idiom (partial sets + resolver) is accepted."""
    rego = 'package norviq.strict\nblocks["g"] { input.tool_name == "x" }\n' + _RESOLVER
    validate_policy_create(_policy(rego))  # must not raise


def test_complete_rule_validates() -> None:
    rego = (
        'package norviq.strict\ndefault decision = "allow"\ndefault rule_id = "default_allow"\n'
        'default reason = "ok"\ndecision = "block" { input.tool_name == "x" }\n'
        'rule_id = "cr" { input.tool_name == "x" }\nreason = "b" { input.tool_name == "x" }\n'
    )
    validate_policy_create(_policy(rego))  # must not raise


def test_all_sector_packs_validate() -> None:
    """Every shipped pack's combined rego passes validation (packs need NO rego change)."""
    from norviq.api.packs import combine, load_manifest

    for pid in load_manifest()["packs"]:
        validate_policy_create(_policy(combine([pid])))  # must not raise


# --- Defect 2a: engine fail-closes a decision-less fired result (silent-allow hole) ----------------


def test_fired_partial_set_without_decision_fails_closed() -> None:
    """A block rule fired but the module produced no `decision` → BLOCK, never a silent allow."""
    assert OPAEvaluator._fired_without_decision({"blocks": ["g"], "rule_id": "g"}) is True
    assert OPAEvaluator._fired_without_decision({"escalates": ["e"]}) is True
    assert OPAEvaluator._fired_without_decision({"audits": ["a"]}) is True


def test_complete_rule_no_match_is_not_fail_closed() -> None:
    """A complete-rule policy whose condition didn't match (no partial sets, decision undefined) → allow."""
    assert OPAEvaluator._fired_without_decision({"rule_id": "default_allow"}) is False
    assert OPAEvaluator._fired_without_decision({"blocks": [], "escalates": []}) is False
    assert OPAEvaluator._fired_without_decision({"decision": "allow"}) is False  # decision present wins


# --- Defect 2b: push has its own (larger) timeout, distinct from the hot-path query ---------------


def test_push_timeout_is_larger_than_query_timeout() -> None:
    """The module PUSH must not share the tight query timeout that made cold pushes fail (P1-2)."""
    assert settings.opa_push_timeout_ms > settings.opa_timeout_ms
    assert settings.opa_push_timeout_ms >= 1000


async def test_push_policy_passes_the_push_timeout(monkeypatch) -> None:
    """push_policy sends the push timeout (not opa_timeout_ms) on the PUT request."""
    from norviq.engine.opa_client import OpaClient

    captured: dict = {}

    class _FakeResp:
        status_code = 200
        text = ""

    class _FakeClient:
        async def put(self, url, content=None, headers=None, timeout=None):
            captured["timeout"] = timeout
            return _FakeResp()

    client = OpaClient()
    monkeypatch.setattr(client, "_ensure", lambda: _fake_ensure(_FakeClient()))
    await client.push_policy("mod", "package x\n")
    assert captured["timeout"] == pytest.approx(settings.opa_push_timeout_ms / 1000.0)


async def _fake_ensure(c):
    return c


# --- Defect 2c: override PUT rejects a decision-less overlay at save time (no silent no-op) ---------


def test_override_decisionless_rejected_by_static_guard() -> None:
    """A pack override with partial sets but no resolver is rejected up front (would else silently no-op)."""
    from norviq.api.routers.policies import assert_decision_resolver

    with pytest.raises(HTTPException) as ei:
        assert_decision_resolver('package norviq.pack\nblocks["o"] { input.tool_name == "x" }\n')
    assert ei.value.status_code == 422 and "resolver" in ei.value.detail


def test_override_with_resolver_passes_static_guard() -> None:
    from norviq.api.routers.policies import assert_decision_resolver

    assert_decision_resolver('package norviq.pack\nblocks["o"] { input.tool_name == "x" }\n' + _RESOLVER)


# --- FIX-3 (CRITICAL, silent-allow): a "block" policy whose condition never matches real input ------
#
# `str(result.get("decision", "allow"))` (evaluator.py) defaults to "allow" when a module produces NO
# `decision` binding at all. A complete-rule `decision = "block" { <condition> }` policy with no
# `default decision` produces exactly that when its condition doesn't match: OPA returns an empty
# result for `decision`, and the policy silently evaluates to allow — even though it LOOKS like a block
# policy on review. Every legitimate policy already declares `default decision = "..."`, so requiring it
# at write time makes this failure mode structurally impossible for any admitted policy.


def test_complete_rule_without_default_decision_is_rejected() -> None:
    """A `decision = "block" { <condition> }` rule with NO `default decision` declaration → 422. Without
    this, a condition that never matches real input silently falls back to allow at evaluation time."""
    from norviq.api.routers.policies import assert_decision_resolver

    rego = (
        'package norviq.strict\ndecision = "block" { input.tool_name == "definitely-never-matches" }\n'
        'rule_id = "b" { input.tool_name == "definitely-never-matches" }\n'
        'reason = "r" { input.tool_name == "definitely-never-matches" }\n'
    )
    with pytest.raises(HTTPException) as ei:
        assert_decision_resolver(rego)
    assert ei.value.status_code == 422
    assert "default decision" in ei.value.detail


def test_complete_rule_with_default_decision_allow_is_accepted() -> None:
    """A policy that honestly declares `default decision = "allow"` alongside its block rule passes —
    the author explicitly chose what 'no rule matched' means, so there is no silent fallback."""
    from norviq.api.routers.policies import assert_decision_resolver

    rego = (
        'package norviq.strict\ndefault decision = "allow"\ndefault rule_id = "default_allow"\n'
        'default reason = "ok"\ndecision = "block" { input.tool_name == "x" }\n'
        'rule_id = "b" { input.tool_name == "x" }\nreason = "r" { input.tool_name == "x" }\n'
    )
    assert_decision_resolver(rego)  # must not raise


def test_full_validate_policy_create_rejects_missing_default_decision() -> None:
    """End-to-end through the same entry point create/dry-run/pack-override all share."""
    rego = (
        'package norviq.strict\ndecision = "block" { input.tool_name == "x" }\n'
        'rule_id = "b" { input.tool_name == "x" }\nreason = "r" { input.tool_name == "x" }\n'
    )
    with pytest.raises(HTTPException) as ei:
        validate_policy_create(_policy(rego))
    assert ei.value.status_code == 422
    assert "default decision" in ei.value.detail
