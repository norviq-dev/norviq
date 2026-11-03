# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""One identity rule for minting, deciding and controlling an agent.

POST /keys, the evaluator and the admin trust routes each had their own idea of a valid agent id. The
evaluator took any "spiffe://..." string and POST /keys any up to 512 characters, the bare prefix included,
while PUT /agents/{id}/trust refused the bare prefix and anything over 512 (the registry column). So an
identity could get decisions that no freeze could reach. All three now use
norviq/engine/identity.py::is_controllable_spiffe_id, and the evaluator fails closed on the rest with its
existing invalid_spiffe_identity block.
"""

from __future__ import annotations

import pytest

from norviq.engine.evaluator import InvalidSpiffeIdentity, OPAEvaluator
from norviq.engine.identity import is_controllable_spiffe_id
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from tests.engine.test_evaluator_unit import _CacheStub, _LoaderStub

REFUSED = [
    "spiffe://",
    "spiffe://   ",
    "spiffe://\t",
    "spiffe://" + "a" * 504,
    "not-spiffe",
    "",
    " spiffe://x",
    "spiffe://norviq/ns/x/sa/\ud800",  # a lone surrogate: not UTF-8, so no store (and no URL) can hold it
    "spiffe://norviq/ns/x/sa/a\x00b",  # NUL: Postgres text cannot hold it, so a freeze is never persisted
]
ACCEPTED = [
    "spiffe://acme-agent",
    "spiffe://Acme.com/agent",
    "spiffe://norviq/ns/a/sa/my agent",
    "spiffe://norviq/ns/a/sa/b*?[0]",
    "spiffe://" + "a" * 503,
    "spiffe://" + "\u00e9" * 503,
    "spiffe://norviq/ns/a/sa/\U0001f600",  # a valid non-BMP character
]


@pytest.mark.parametrize("spiffe_id", REFUSED)
def test_the_rule_refuses_what_no_admin_control_can_cover(spiffe_id) -> None:
    assert not is_controllable_spiffe_id(spiffe_id)


@pytest.mark.parametrize("spiffe_id", ACCEPTED)
def test_the_rule_accepts_operator_chosen_ids(spiffe_id) -> None:
    assert is_controllable_spiffe_id(spiffe_id)
    OPAEvaluator(_CacheStub())._validate_spiffe(spiffe_id)  # type: ignore[arg-type]


@pytest.mark.parametrize("spiffe_id", ["spiffe://", "spiffe://   ", "spiffe://" + "a" * 504])
def test_the_evaluator_refuses_an_identity_the_admin_routes_would_422(spiffe_id) -> None:
    """FAIL-ON-BUG: it checked only the prefix, so these got real decisions and could not be frozen."""
    with pytest.raises(InvalidSpiffeIdentity):
        OPAEvaluator(_CacheStub())._validate_spiffe(spiffe_id)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_an_uncontrollable_identity_is_blocked_with_the_existing_invalid_identity_rule() -> None:
    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    engine.bind_loader(_LoaderStub({}))
    event = ToolCallEvent(
        tool_name="search_kb",
        tool_params={},
        agent_identity=AgentIdentity(spiffe_id="spiffe://", namespace="default", agent_class="test"),
        session_id="identity-rule",
    )
    decision = await engine.evaluate(event)
    assert (decision.decision, decision.rule_id) == ("block", "invalid_spiffe_identity")


class _MonitorCache(_CacheStub):
    async def get_ns_settings(self, namespace: str):
        return {"enforcement_mode": "audit"}


@pytest.mark.asyncio
@pytest.mark.parametrize("spiffe_id", ["spiffe://norviq/ns/x/sa/\ud800", "spiffe://norviq/ns/x/sa/a\x00b", "spiffe://"])
@pytest.mark.parametrize("cache", [_CacheStub, _MonitorCache])
async def test_an_id_no_store_can_hold_is_blocked_in_every_posture(spiffe_id, cache) -> None:
    """Review round 8: a lone surrogate passed the rule, then failed later (evaluator_fallback), which a monitor
    namespace softened to allow; it can never be frozen, since neither store nor a URL can hold it. NUL passes
    Redis but not Postgres, so its freeze could never be persisted. Both now block as invalid_spiffe_identity,
    which posture does not soften."""
    engine = OPAEvaluator(cache())  # type: ignore[arg-type]
    engine.bind_loader(_LoaderStub({}))
    event = ToolCallEvent(
        tool_name="search_kb",
        tool_params={},
        agent_identity=AgentIdentity(spiffe_id=spiffe_id, namespace="mon", agent_class="test"),
        session_id="identity-rule",
    )
    decision = await engine.evaluate(event)
    assert (decision.decision, decision.rule_id) == ("block", "invalid_spiffe_identity")


@pytest.mark.asyncio
async def test_the_monitor_stub_does_soften_an_ordinary_block() -> None:
    """Control for the test above: the stub's namespace really is in monitor posture, and an ordinary block
    in it is softened to audit; invalid_spiffe_identity is kept only because it is exempt."""
    from norviq.sdk.core.decisions import PolicyDecision

    engine = OPAEvaluator(_MonitorCache())  # type: ignore[arg-type]
    posture = await engine._resolve_posture("mon")
    assert posture["monitor"] is True
    block = PolicyDecision(decision="block", rule_id="evaluator_fallback", reason="", event_id="e")
    assert engine._apply_posture(block, posture, "e").decision == "audit"


def test_the_bound_is_the_column_width_in_characters() -> None:
    """Review round 7: the bound is the 512-character width of every agent-id column (widening them on every
    API start rebuilt audit_log's indexes under ACCESS EXCLUSIVE). Characters, not bytes, as the columns count."""
    assert is_controllable_spiffe_id("spiffe://" + "a" * 503)  # 512 characters
    assert is_controllable_spiffe_id("spiffe://" + "\u00e9" * 503)  # 512 characters, 1015 bytes
    assert not is_controllable_spiffe_id("spiffe://" + "a" * 504)  # 513


def test_an_uncontrollable_identity_gets_no_registry_row() -> None:
    """Review round 6: the fail-closed path registered ids the admin routes refuse, rows nobody could freeze,
    lift or delete."""
    from norviq.sdk.core.decisions import PolicyDecision

    engine = OPAEvaluator(_CacheStub())  # type: ignore[arg-type]
    queued: list = []

    def _capture(coro):
        queued.append(coro)
        coro.close()

    engine._queue_background = _capture  # type: ignore[method-assign]

    def _event(spiffe_id: str) -> ToolCallEvent:
        return ToolCallEvent(
            tool_name="t",
            tool_params={},
            session_id="s",
            agent_identity=AgentIdentity(spiffe_id=spiffe_id, namespace="d", agent_class="c"),
        )

    decision = PolicyDecision(decision="block", rule_id="invalid_spiffe_identity", reason="", event_id="e")
    engine._register_fail_closed(_event("spiffe://"), decision)
    assert queued == []
    engine._register_fail_closed(_event("spiffe://d/x"), decision)
    assert len(queued) == 1
