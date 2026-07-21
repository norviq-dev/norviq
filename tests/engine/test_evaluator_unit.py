# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for evaluator regression patterns."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore


@dataclass
class _LoaderStub:
    _policies: dict[str, dict]

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return self._policies.get(f"{namespace}:{agent_class}")


class _CacheStub:
    def __init__(self) -> None:
        self._eval: dict[tuple[str, str, str], object] = {}
        self._trust: dict[str, TrustScore] = {}

    async def get_eval(self, namespace: str, agent_class: str, tool_name: str):
        return self._eval.get((namespace, agent_class, tool_name))

    async def set_eval(self, namespace: str, agent_class: str, tool_name: str, decision) -> None:
        self._eval[(namespace, agent_class, tool_name)] = decision

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        return self._trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        self._trust[spiffe_id] = score

    async def incr_call_count(self, spiffe_id: str, window_s: int = 60) -> int:
        return 1

    async def get_ns_settings(self, namespace: str):
        # No per-namespace posture override in these unit tests → the evaluator falls back to global config.
        return None


def _trust_result() -> TrustResult:
    return TrustResult(
        score=0.9,
        category="high",
        signals={"violation_rate": 0.1},
        weights={"violation_rate": 1.0},
        dominant_signal="violation_rate",
        recommendation="allow",
    )


def _event(tool_name: str = "search_kb", params: dict | None = None) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool_name,
        tool_params=params or {},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/test",
            namespace="default",
            agent_class="test",
        ),
        session_id="unit-test",
    )


@pytest.fixture
def evaluator(monkeypatch: pytest.MonkeyPatch) -> OPAEvaluator:
    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    engine.bind_loader(_LoaderStub({}))

    async def _fake_compute_trust(event: ToolCallEvent, trust: TrustScore, trust_threshold=None) -> TrustResult:
        return _trust_result()

    async def _fake_persist(event: ToolCallEvent, decision, trust: TrustResult) -> None:
        return None

    monkeypatch.setattr(engine, "_compute_trust", _fake_compute_trust)
    monkeypatch.setattr(engine, "_persist_behavior", _fake_persist)
    return engine


@pytest.mark.asyncio
async def test_evaluate_actually_calls_opa(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    rego = (
        'package norviq.strict\n'
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "delete_record" }\n'
        'rule_id = "llm06" { input.tool_name == "delete_record" }\n'
    )
    evaluator._loader._policies["default:test"] = {"rego": rego, "priority": 100}  # type: ignore[attr-defined]
    called = False

    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        nonlocal called
        called = True
        assert opa_input["tool_name"] == "delete_record"
        return {"decision": "block", "rule_id": "llm06", "reason": "blocked by test"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    decision = await evaluator.evaluate(_event(tool_name="delete_record"))
    assert called
    assert decision.decision == "block"
    assert decision.rule_id == "llm06"


@pytest.mark.asyncio
async def test_evaluator_no_regex_default_shortcut(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    rego = (
        'package norviq.strict\n'
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "evil_tool" }\n'
    )
    evaluator._loader._policies["default:test"] = {"rego": rego, "priority": 100}  # type: ignore[attr-defined]

    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        return {"decision": "block", "rule_id": "regex_guard", "reason": "opa"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    decision = await evaluator.evaluate(_event(tool_name="evil_tool"))
    assert decision.decision == "block"


@pytest.mark.asyncio
async def test_provenance_in_rule_id(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        return {"decision": "allow", "rule_id": "default_allow", "reason": "no policy"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    decision = await evaluator.evaluate(_event(tool_name="anything"))
    assert decision.rule_id in {"default_allow", "no_policy"}


@pytest.mark.asyncio
async def test_timeout_fails_closed_not_open(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    rego = 'package norviq.strict\ndefault decision = "allow"\ndecision = "allow" { true }\n'
    evaluator._loader._policies["default:test"] = {"rego": rego, "priority": 100}  # type: ignore[attr-defined]

    async def _slow_single(event: ToolCallEvent, key: str, rego_source: str, trust_result: TrustResult):
        await asyncio.sleep(2.1)
        return None

    monkeypatch.setattr(evaluator, "_evaluate_single", _slow_single)
    decision = await evaluator.evaluate(_event(tool_name="some_tool"))
    assert decision.decision == "block"
    assert "timeout" in decision.rule_id


@pytest.mark.asyncio
async def test_cache_hit_vs_miss_have_same_decision(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        return {"decision": "block", "rule_id": "deny_sql_injection", "reason": "unit"}

    evaluator._loader._policies["default:test"] = {"rego": "package norviq.strict", "priority": 100}  # type: ignore[attr-defined]
    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    event = _event(tool_name="execute_sql", params={"query": "DROP TABLE x"})
    decision_miss = await evaluator.evaluate(event)
    decision_hit = await evaluator.evaluate(event.model_copy(update={"event_id": "evt-2"}))
    assert decision_miss.decision == decision_hit.decision
    assert decision_miss.rule_id == decision_hit.rule_id


@pytest.mark.asyncio
async def test_cache_invalidated_on_policy_change(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        if "block" in rego_source:
            return {"decision": "block", "rule_id": "new_rule", "reason": "updated"}
        return {"decision": "allow", "rule_id": "old_rule", "reason": "old"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    evaluator._loader._policies["default:test"] = {"rego": "allow", "priority": 100}  # type: ignore[attr-defined]
    event = _event(tool_name="delete_record")
    first = await evaluator.evaluate(event)
    assert first.decision == "allow"
    evaluator._loader._policies["default:test"] = {"rego": "block", "priority": 100}  # type: ignore[attr-defined]
    evaluator._cache._eval.clear()  # type: ignore[attr-defined]
    second = await evaluator.evaluate(event.model_copy(update={"event_id": "evt-3"}))
    assert second.decision == "block"


@pytest.mark.asyncio
async def test_evaluator_uses_specific_policy_over_cluster_baseline(
    evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluator._loader._policies["default:test"] = {"rego": "block", "priority": 100}  # type: ignore[attr-defined]
    evaluator._loader._policies["default:__baseline__"] = {"rego": "allow", "priority": 50}  # type: ignore[attr-defined]
    evaluator._loader._policies["__cluster__:__baseline__"] = {"rego": "allow", "priority": 10}  # type: ignore[attr-defined]

    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        if rego_source == "block":
            return {"decision": "block", "rule_id": "specific", "reason": "specific"}
        return {"decision": "allow", "rule_id": "baseline", "reason": "baseline"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    decision = await evaluator.evaluate(_event(tool_name="delete_record"))
    assert decision.decision == "block"
    assert decision.rule_id == "specific"


@pytest.mark.asyncio
async def test_no_policy_path_still_calls_opa_entrypoint(evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        nonlocal called
        called = True
        return {"decision": "allow", "rule_id": "default_allow", "reason": "none"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    decision = await evaluator.evaluate(_event(tool_name="safe_tool"))
    assert called
    assert decision.decision in {"allow", "escalate"}


def test_reload_policy_is_copy_on_write_and_preserves_priority() -> None:
    """reload_policy must use COW (atomic dict swap, no in-place mutation) so a concurrent candidate
    iteration can't see a torn read, and must PRESERVE the existing priority."""
    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    engine.load_policy("default", "svc", "package a\n", priority=800)
    before = engine._policies                       # capture the map identity
    before_entry = engine._policies["default:svc"]  # and the entry object

    engine.reload_policy("default", "svc", "package b\n")  # no explicit priority

    assert engine._policies is not before                  # COW: a NEW map, not mutated in place
    assert engine._policies["default:svc"] is not before_entry
    assert engine._policies["default:svc"]["rego"] == "package b\n"
    assert engine._policies["default:svc"]["priority"] == 800   # preserved, not reset to 100
    # an explicit priority overrides
    engine.reload_policy("default", "svc", "package c\n", priority=250)
    assert engine._policies["default:svc"]["priority"] == 250
    # a fresh key with no prior entry defaults to 100
    engine.reload_policy("default", "new", "package d\n")
    assert engine._policies["default:new"]["priority"] == 100


@pytest.mark.asyncio
async def test_collect_candidates_includes_namespace_and_workload_tiers(evaluator: OPAEvaluator) -> None:
    """The WORKLOAD (deployment:<name>) and NAMESPACE (namespace:<ns>) tiers the catalog advertises are
    now actually COLLECTED for evaluation (they were minted/listed/versioned but never enforced)."""
    loader = evaluator._loader  # type: ignore[attr-defined]
    loader._policies = {
        "default:test": {"rego": "package a", "priority": 100},
        "default:namespace:default": {"rego": "package ns", "priority": 500},
        "default:deployment:checkout": {"rego": "package wl", "priority": 900},
        "prod:deployment:checkout": {"rego": "package other", "priority": 900},  # different ns → must NOT match
    }
    # a caller in `default` running workload `checkout`
    evt = ToolCallEvent(
        tool_name="x", agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/test", namespace="default", agent_class="test", workload="checkout"),
    )
    keys = {c["key"] for c in await evaluator._collect_candidates(evt)}
    assert "default:namespace:default" in keys          # namespace tier collected
    assert "default:deployment:checkout" in keys         # workload tier collected (caller identified its workload)
    assert "prod:deployment:checkout" not in keys        # another namespace's workload policy is not pulled in


@pytest.mark.asyncio
async def test_workload_tier_absent_when_caller_has_no_workload(evaluator: OPAEvaluator) -> None:
    """The workload tier is NEVER guessed — it applies only when the caller identifies its workload."""
    loader = evaluator._loader  # type: ignore[attr-defined]
    loader._policies = {"default:deployment:checkout": {"rego": "package wl", "priority": 900}}
    evt = _event()  # no workload on the identity
    keys = {c["key"] for c in await evaluator._collect_candidates(evt)}
    assert "default:deployment:checkout" not in keys
