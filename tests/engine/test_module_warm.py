# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A slow OPA module compile must cost LATENCY, never a wrong verdict.

Regression for the defect where the first tool call after any policy create/edit was wrongly blocked.
The module push is what makes OPA recompile its store, and it used to run INSIDE the engine's 2s
evaluation budget, so on a CPU-throttled OPA the push alone blew the deadline and the call came back
`evaluator_timeout` — a fail-closed block on traffic the policy actually allowed. Found on AKS, where
the OPA sidecar's 250m CPU limit made it reproduce on 5 of 5 fresh policy keys.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore

_KEY = "default:customer-support"
_REGO = 'package norviq.policy\n\ndefault decision = "allow"\ndefault rule_id = "warm_ok"\ndefault reason = "allowed"\n'

# Longer than the engine's 2.0s evaluation budget: the whole point is that a compile which would have
# blown the deadline no longer decides the verdict.
_SLOW_COMPILE_S = 2.6


@dataclass
class _LoaderStub:
    _policies: dict[str, dict]

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return self._policies.get(f"{namespace}:{agent_class}")


class _CacheStub:
    async def get_eval(self, namespace: str, agent_class: str, tool_name: str):
        return None

    async def set_eval(self, namespace: str, agent_class: str, tool_name: str, decision) -> None:
        return None

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        return None

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        return None

    async def incr_call_count(self, spiffe_id: str, window_s: int = 60) -> int:
        return 1

    async def get_ns_settings(self, namespace: str):
        return None


class _SlowCompileOPA:
    """Stands in for the OPA server: the PUT is slow (recompiling), the query is fast."""

    def __init__(self) -> None:
        self.pushes = 0

    async def push_policy(self, module_id: str, rego: str) -> None:
        self.pushes += 1
        await asyncio.sleep(_SLOW_COMPILE_S)

    async def query(self, package: str, opa_input: dict) -> dict:
        return {"decision": "allow", "rule_id": "warm_ok", "reason": "allowed"}

    async def stop(self) -> None:  # pragma: no cover - parity with the real client
        return None


def _event() -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="search_kb",
        tool_params={"query": "hi"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/customer-support",
            namespace="default",
            agent_class="customer-support",
        ),
        session_id="warm",
    )


@pytest.fixture
def evaluator(monkeypatch: pytest.MonkeyPatch) -> tuple[OPAEvaluator, _SlowCompileOPA]:
    monkeypatch.setattr(settings, "opa_mode", "server")
    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    engine.bind_loader(_LoaderStub({}))
    opa = _SlowCompileOPA()
    engine.opa = opa  # type: ignore[assignment]
    engine.load_policy("default", "customer-support", _REGO)

    async def _fake_compute_trust(event: ToolCallEvent, trust: TrustScore, trust_threshold=None) -> TrustResult:
        return TrustResult(
            score=0.9, category="high", signals={}, weights={}, dominant_signal="", recommendation=""
        )

    async def _fake_persist(event: ToolCallEvent, decision, trust: TrustResult) -> None:
        return None

    monkeypatch.setattr(engine, "_compute_trust", _fake_compute_trust)
    monkeypatch.setattr(engine, "_persist_behavior", _fake_persist)
    return engine, opa


@pytest.mark.asyncio
async def test_slow_compile_does_not_produce_evaluator_timeout(evaluator) -> None:
    """A 2.6s compile — past the 2s evaluation budget — still yields the policy's real decision."""
    engine, opa = evaluator
    decision = await engine.evaluate(_event())
    assert decision.rule_id != "evaluator_timeout", (
        "the module compile was charged to the evaluation deadline again — the first call after a "
        "policy change is being fail-closed blocked on traffic the policy allows"
    )
    assert opa.pushes == 1, f"expected exactly one push from the pre-deadline warm, saw {opa.pushes}"


@pytest.mark.asyncio
async def test_warm_is_idempotent_across_calls(evaluator) -> None:
    """Only the FIRST call pays the compile; an unchanged digest must not re-push (or every call
    would re-pay the recompile and OPA would thrash)."""
    engine, opa = evaluator
    await engine.evaluate(_event())
    await engine.evaluate(_event())
    assert opa.pushes == 1, f"unchanged policy re-pushed {opa.pushes}x — the digest guard is not holding"


@pytest.mark.asyncio
async def test_slow_compile_on_the_candidate_path(evaluator) -> None:
    """Same guarantee on the CANDIDATE path — the one real traffic takes once a policy is loaded.

    The two paths warm at different call sites, so a fix applied to only one of them still leaves
    production exposed; this pins the multi-candidate loop specifically.
    """
    engine, opa = evaluator
    engine.bind_loader(
        _LoaderStub({_KEY: {"rego": _REGO, "priority": 100, "enforcement_mode": "block"}})
    )
    decision = await engine.evaluate(_event())
    assert decision.rule_id != "evaluator_timeout", (
        "candidate-path compile is being charged to the evaluation deadline"
    )
    assert opa.pushes == 1, f"expected exactly one push from the pre-deadline warm, saw {opa.pushes}"


@pytest.mark.asyncio
async def test_warm_failure_still_fails_closed(evaluator, monkeypatch: pytest.MonkeyPatch) -> None:
    """The warm is best-effort, so a push that RAISES must not fail open — the evaluation path still
    owns the verdict and still blocks."""
    engine, opa = evaluator

    async def _boom(module_id: str, rego: str) -> None:
        raise RuntimeError("opa unreachable")

    monkeypatch.setattr(opa, "push_policy", _boom)
    decision = await engine.evaluate(_event())
    assert decision.decision == "block", "a broken OPA must fail closed, never allow"
