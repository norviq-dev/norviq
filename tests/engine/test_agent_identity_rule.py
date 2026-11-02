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

REFUSED = ["spiffe://", "spiffe://   ", "spiffe://\t", "spiffe://" + "a" * 504, "not-spiffe", "", " spiffe://x"]
ACCEPTED = [
    "spiffe://acme-agent",
    "spiffe://Acme.com/agent",
    "spiffe://norviq/ns/a/sa/my agent",
    "spiffe://norviq/ns/a/sa/b*?[0]",
    "spiffe://" + "a" * 503,
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
