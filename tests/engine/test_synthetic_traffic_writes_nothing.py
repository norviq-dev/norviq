# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A fabricated call writes no per-identity state.

A red-team run evaluates as `spiffe://norviq/ns/<ns>/sa/<agent_class>`, and Simulate does the same.
Where the workload's service account is named anything else (the usual `sa/default`) that SVID belongs
to no workload. The evaluator still seeded its `trust:*` key, upserted an agent-registry row at the
default HIGH trust and drew its attack tools into the asset graph, so the Agents roster gained a
phantom agent and the graphs gained edges no agent made. The guards that did exist assumed the SVID was
the real agent's and suppressed only the violation count, the history and the profile.

Driven through `evaluate()` rather than `_persist_behavior` alone, because the trust seed happens
before persistence, on the read.
"""

from __future__ import annotations

import asyncio

import pytest

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore

# Spelled out rather than imported, so a test still runs (and fails on behaviour) against an engine that
# predates the shared set. `test_the_list_here_is_the_shared_set` keeps it equal to that set.
_FABRICATED = ("attack-graph", "policy-tester", "probe", "red-team", "redteam")

_WRITERS = {
    "_safe_set_trust", "_safe_register_agent", "_safe_record_graph", "_safe_record_history", "_safe_update_profile",
}


class _Cache:
    def __init__(self) -> None:
        self.trust: dict[str, TrustScore] = {}

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        return self.trust.get(spiffe_id)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        self.trust[spiffe_id] = score

    async def get_eval(self, *_a):
        return None

    async def set_eval(self, *_a) -> None:
        return None

    async def incr_call_count(self, *_a) -> int:
        return 1

    async def get_ns_settings(self, _ns: str):
        return None


def _engine(monkeypatch: pytest.MonkeyPatch) -> tuple[OPAEvaluator, _Cache, list[str]]:
    cache = _Cache()
    engine = OPAEvaluator(cache)  # type: ignore[arg-type]
    queued: list[str] = []

    def _capture(coro) -> None:
        queued.append(coro.cr_code.co_name)
        coro.close()

    async def _trust(*_a, **_k) -> TrustResult:
        return TrustResult(score=0.9, category="high", signals={}, weights={},
                           dominant_signal="", recommendation="allow")

    async def _no_candidates(*_a, **_k) -> list:
        return []

    async def _opa(*_a, **_k) -> dict:
        return {"decision": "block", "rule_id": "deny_drop_table", "reason": "test"}

    monkeypatch.setattr(engine, "_queue_background", _capture)
    monkeypatch.setattr(engine, "_compute_trust", _trust)
    monkeypatch.setattr(engine, "_collect_candidates", _no_candidates)
    monkeypatch.setattr(engine, "_evaluate_opa", _opa)
    return engine, cache, queued


def _event(framework: str) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="drop_table",
        tool_params={},
        session_id="s",
        framework=framework,
        # The made-up red-team SVID: the namespace's real workload runs as sa/default.
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/my-team/sa/my-agent", namespace="my-team", agent_class="my-agent",
        ),
    )


async def test_a_real_call_does_write_identity_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control arm: the harness sees every writer when the call is real. Without it, the synthetic
    assertions below would pass on an engine that writes nothing for anyone."""
    engine, cache, queued = _engine(monkeypatch)
    decision = await engine.evaluate(_event("sidecar"))
    assert decision.decision == "block"
    assert "spiffe://norviq/ns/my-team/sa/my-agent" in cache.trust
    assert _WRITERS <= set(queued), queued
    await engine.close()


@pytest.mark.parametrize("framework", _FABRICATED)
async def test_a_fabricated_call_registers_no_identity(monkeypatch: pytest.MonkeyPatch, framework: str) -> None:
    engine, cache, queued = _engine(monkeypatch)
    decision = await engine.evaluate(_event(framework))
    # Still evaluated: the red-team result and the Simulate verdict need the decision.
    assert decision.decision == "block" and decision.rule_id == "deny_drop_table"
    assert cache.trust == {}, "a trust:* key lists the made-up SVID on the Agents roster"
    assert not (_WRITERS & set(queued)), queued
    await engine.close()


@pytest.mark.parametrize("framework", _FABRICATED)
async def test_a_fabricated_call_registers_nothing_on_the_fail_closed_path(framework: str) -> None:
    engine = OPAEvaluator(_Cache())  # type: ignore[arg-type]
    queued: list = []

    def _capture(coro) -> None:
        queued.append(coro.cr_code.co_name)
        coro.close()

    engine._queue_background = _capture  # type: ignore[method-assign]
    decision = PolicyDecision(decision="block", rule_id="evaluator_timeout", reason="", event_id="e")
    engine._register_fail_closed(_event(framework), decision)
    assert queued == []
    engine._register_fail_closed(_event("sidecar"), decision)
    assert queued == ["_safe_register_agent"], "control arm: a real call registers"


def test_the_list_here_is_the_shared_set() -> None:
    from norviq.api.synthetic import SYNTHETIC_FRAMEWORKS

    assert set(_FABRICATED) == set(SYNTHETIC_FRAMEWORKS)


_SVID = "spiffe://norviq/ns/my-team/sa/my-agent"


class _WindowCache(_Cache):
    """Records which rate-limit window each call counted against, and can report one as full."""

    def __init__(self, full: str | None = None) -> None:
        super().__init__()
        self.windows: list[str] = []
        self.full = full

    async def incr_call_count(self, key: str, *_a) -> int:
        self.windows.append(key)
        return 10_000 if key == self.full else 1


def _allowing_engine(monkeypatch: pytest.MonkeyPatch, cache: _Cache) -> tuple[OPAEvaluator, list[str]]:
    """The real trust calculation (its store reads stubbed) and an `allow` from the policy, so the call
    reaches the rate limiter and the trust breakdown write."""
    engine = OPAEvaluator(cache)  # type: ignore[arg-type]
    persisted: list[str] = []
    calc = engine._trust_calculator

    async def _value(value):
        return value

    async def _record(spiffe_id: str, _result) -> None:
        persisted.append(spiffe_id)

    monkeypatch.setattr(calc, "_safe_history", lambda *_a: _value([]))
    monkeypatch.setattr(calc, "_history_cached", lambda *_a: _value([]))
    monkeypatch.setattr(calc, "_safe_profile_and_frozen", lambda *_a: _value(({}, False)))
    monkeypatch.setattr(calc, "_profile_cached", lambda *_a: _value({}))
    monkeypatch.setattr(calc, "_safe_frozen_only", lambda *_a: _value(False))
    monkeypatch.setattr(calc, "_safe_override_only", lambda *_a: _value(None))
    monkeypatch.setattr(calc, "_persist", _record)

    def _drop(coro) -> None:
        coro.close()

    async def _no_candidates(*_a, **_k) -> list:
        return []

    async def _opa(*_a, **_k) -> dict:
        return {"decision": "allow", "rule_id": "default_allow", "reason": "test"}

    monkeypatch.setattr(engine, "_queue_background", _drop)
    monkeypatch.setattr(engine, "_collect_candidates", _no_candidates)
    monkeypatch.setattr(engine, "_evaluate_opa", _opa)
    return engine, persisted


@pytest.mark.parametrize("framework", _FABRICATED)
async def test_a_fabricated_call_does_not_use_the_agent_s_rate_limit_window(
    monkeypatch: pytest.MonkeyPatch, framework: str
) -> None:
    """A red-team run or a Simulate uses the real agent's SVID. Counted in `callcount:{svid}`, it used up
    the window the agent's live traffic is throttled on. It counts in its own window instead."""
    cache = _WindowCache()
    engine, _ = _allowing_engine(monkeypatch, cache)
    await engine.evaluate(_event("sidecar"))
    assert cache.windows == [_SVID], "control arm: a real call counts against the agent's window"
    await engine.evaluate(_event(framework))
    assert cache.windows[1:] == [f"synthetic:{_SVID}"]
    await engine.close()


async def test_fabricated_calls_are_still_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    """Their own window, at the same ceiling: a full one still throttles them."""
    cache = _WindowCache(full=f"synthetic:{_SVID}")
    engine, _ = _allowing_engine(monkeypatch, cache)
    assert (await engine.evaluate(_event("redteam"))).rule_id == "rate_limit_exceeded"
    assert (await engine.evaluate(_event("sidecar"))).decision == "allow", "the agent's own window is not full"
    await engine.close()


@pytest.mark.parametrize("framework", _FABRICATED)
async def test_a_fabricated_call_keeps_the_agent_s_trust_breakdown(
    monkeypatch: pytest.MonkeyPatch, framework: str
) -> None:
    """`trustcalc:{svid}` is the signal breakdown the Agents roster shows for the agent. A fabricated call
    under that SVID replaced it with the breakdown of a call the agent never made."""
    engine, persisted = _allowing_engine(monkeypatch, _WindowCache())
    await engine.evaluate(_event("sidecar"))
    await asyncio.sleep(0)
    assert persisted == [_SVID], "control arm: a real call writes the breakdown"
    await engine.evaluate(_event(framework))
    await asyncio.sleep(0)
    assert persisted == [_SVID]
    await engine.close()
