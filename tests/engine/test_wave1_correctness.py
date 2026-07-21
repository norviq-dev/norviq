# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Wave-1 console correctness fixes.

The console's global picker sends ``namespace="all"``. Treating it as a literal namespace (which owns no
policy) falls through to ``no_policy_loaded`` even when a policy IS loaded. The resolver instead resolves
the UNION across every namespace that holds a policy for the class, so ``/evaluate`` and
``/policies/effective`` report the real winning rule — while a concrete-namespace evaluation stays byte-identical
(decision parity) and a genuinely-empty case still fails closed.

A TRANSIENT OPA-eval failure (e.g. the server-mode module lazy-load race right after an apply) that falls
straight through to a fail-closed ``evaluator_error`` can record a clean input as an engine error and
mistake it for a policy decision. The evaluator retries once (self-heals a transient error); only a
PERSISTENT engine error stays fail-closed, with a distinct reason and a counted, observable health signal.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore


@dataclass
class _UnionLoaderStub:
    """Loader stub that mirrors the real loader's ``namespaces_for_class`` contract used by the union path."""

    _policies: dict[str, dict]

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return self._policies.get(f"{namespace}:{agent_class}")

    async def namespaces_for_class(self, agent_class: str) -> list[str]:
        found: set[str] = set()
        for key in self._policies:
            ns, _, ac = key.partition(":")
            if ac == agent_class and ns not in ("all", "__cluster__"):
                found.add(ns)
        return sorted(found)


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


def _trust_result() -> TrustResult:
    return TrustResult(
        score=0.9,
        category="high",
        signals={"violation_rate": 0.1},
        weights={"violation_rate": 1.0},
        dominant_signal="violation_rate",
        recommendation="allow",
    )


def _event(namespace: str, agent_class: str = "customer-support",
           tool_name: str = "execute_sql", params: dict | None = None) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool_name,
        tool_params=params or {},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{namespace}/sa/{agent_class}",
            namespace=namespace,
            agent_class=agent_class,
        ),
        session_id="wave1-test",
    )


@pytest.fixture
def evaluator(monkeypatch: pytest.MonkeyPatch) -> OPAEvaluator:
    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    engine.bind_loader(_UnionLoaderStub({}))

    # _compute_trust grew a `trust_threshold` param (per-namespace posture override,
    # None when unset) — evaluate() now always calls it positionally as
    # self._compute_trust(event, trust, posture["trust_threshold"]). A 2-arg stub raises TypeError on that
    # 3rd arg, which evaluate()'s top-level except then reports as the generic "evaluator_fallback" —
    # masking every rule_id these tests actually assert on.
    async def _fake_compute_trust(
        event: ToolCallEvent, trust: TrustScore, trust_threshold: float | None = None
    ) -> TrustResult:
        return _trust_result()

    async def _fake_persist(event: ToolCallEvent, decision, trust: TrustResult) -> None:
        return None

    monkeypatch.setattr(engine, "_compute_trust", _fake_compute_trust)
    monkeypatch.setattr(engine, "_persist_behavior", _fake_persist)
    return engine


# --------------------------------------------------------------------------------------------------
# FIX 1 — namespace=all resolves the real loaded layers (union), never no_policy_loaded when loaded
# --------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_unions_the_real_loaded_layer(evaluator: OPAEvaluator) -> None:
    """namespace=all collects the real loaded layer (default:customer-support), not nothing."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "shell", "priority": 700}  # type: ignore[attr-defined]
    evaluator._loader._policies["__cluster__:__baseline__"] = {"rego": "base", "priority": 100}  # type: ignore[attr-defined]
    candidates = await evaluator._collect_candidates(_event("all"))
    keys = {c["key"] for c in candidates}
    assert "default:customer-support" in keys  # the real class layer is resolved under "all"
    assert "__cluster__:__baseline__" in keys


@pytest.mark.asyncio
async def test_all_yields_same_rule_as_concrete_namespace(
    evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PARITY: the same tool call yields the SAME real rule under all as under the concrete ns (the spec repro)."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "shell", "priority": 700}  # type: ignore[attr-defined]

    async def _fake_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        if rego_source == "shell":
            return {"decision": "block", "rule_id": "deny_shell_execution", "reason": "shell"}
        return {"decision": "allow", "rule_id": "default_allow", "reason": "none"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _fake_opa)
    d_default = await evaluator.evaluate(_event("default", params={"query": "DROP TABLE customers; --"}))
    d_all = await evaluator.evaluate(_event("all", params={"query": "DROP TABLE customers; --"}))
    assert d_default.rule_id == "deny_shell_execution"
    assert d_all.decision == d_default.decision
    assert d_all.rule_id == d_default.rule_id  # NOT no_policy_loaded — the real rule is resolved


@pytest.mark.asyncio
async def test_all_with_nothing_loaded_is_empty_failclosed(evaluator: OPAEvaluator) -> None:
    """Fail-closed: when nothing is loaded anywhere the union is empty (caller denies with no_policy_loaded)."""
    candidates = await evaluator._collect_candidates(_event("all", agent_class="ghost-class"))
    assert candidates == []


@pytest.mark.asyncio
async def test_concrete_namespace_collection_unchanged(evaluator: OPAEvaluator) -> None:
    """PARITY: a concrete-ns collection does NOT take the union branch and is ordered exactly as before."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "r", "priority": 700}  # type: ignore[attr-defined]
    candidates = await evaluator._collect_candidates(_event("default"))
    assert [c["key"] for c in candidates] == ["default:customer-support"]  # class policy first, as before


@pytest.mark.asyncio
async def test_all_unions_across_multiple_namespaces(evaluator: OPAEvaluator) -> None:
    """The union spans EVERY namespace holding the class (not just one)."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "a", "priority": 700}  # type: ignore[attr-defined]
    evaluator._loader._policies["support-bot:customer-support"] = {"rego": "b", "priority": 700}  # type: ignore[attr-defined]
    candidates = await evaluator._collect_candidates(_event("all"))
    keys = {c["key"] for c in candidates}
    assert {"default:customer-support", "support-bot:customer-support"} <= keys


# --------------------------------------------------------------------------------------------------
# FIX 3 — a transient OPA error self-heals; a persistent one fails closed, distinctly + observably
# --------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_transient_opa_error_self_heals(
    evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient OPA failure retries once and succeeds — a clean input NEVER yields evaluator_error."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "r", "priority": 700}  # type: ignore[attr-defined]
    calls = {"n": 0}

    async def _flaky_opa(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("opa module not loaded yet (transient push race)")
        return {"decision": "allow", "rule_id": "default_allow", "reason": "clean"}

    monkeypatch.setattr(evaluator, "_evaluate_opa", _flaky_opa)
    decision = await evaluator.evaluate(_event("default", tool_name="search_kb"))
    assert calls["n"] == 2  # retried once
    assert decision.rule_id != "evaluator_error"
    assert decision.decision == "allow"
    assert evaluator._engine_error_count == 0  # a transient error does NOT inflate the engine-health signal


@pytest.mark.asyncio
async def test_persistent_opa_error_fails_closed_and_is_counted(
    evaluator: OPAEvaluator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A PERSISTENT engine error still fails closed with the DISTINCT reason + a counted, observable signal."""
    evaluator._loader._policies["default:customer-support"] = {"rego": "r", "priority": 700}  # type: ignore[attr-defined]

    async def _always_fail(key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = "") -> dict:
        raise RuntimeError("opa server unreachable")

    monkeypatch.setattr(evaluator, "_evaluate_opa", _always_fail)
    before = evaluator._engine_error_count
    decision = await evaluator.evaluate(_event("default", tool_name="search_kb"))
    assert decision.decision == "block"  # fail-closed preserved
    assert decision.rule_id == "evaluator_error"
    assert "not a policy decision" in decision.reason  # never confused with a real policy block
    assert evaluator._engine_error_count == before + 1  # observable engine-health signal
