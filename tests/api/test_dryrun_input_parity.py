# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Dry-run must replay through the SAME input the evaluator builds, or it lies in both directions.

`_opa_input_from_record` hand-built the OPA input and omitted `derived`, `mcp` and `direction` — three
facts the evaluator publishes and that policies are explicitly encouraged to use (`derived.verb` is how
"block every sink" is written without enumerating tool names). A candidate keyed on any of them saw
them undefined, fired on nothing, and the dry-run reported `would_block: 0`, "safe to deploy", for a
policy that blocks those exact calls in production. Inverted, a security engineer asking "would this
have caught yesterday's exfiltration?" was shown zero and concluded the rule did not work.

The fix is not to copy the missing keys across — that is the second implementation that drifted in the
first place — but to build the input with the evaluator's own `_build_input`.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from norviq.api.routers.policies import _opa_input_from_record
from norviq.engine.evaluator import OPAEvaluator


def _rec(tool="send_email", params=None, mcp=None):
    payload = {"tool_params": params if params is not None else {"to": "attacker@evil.example"}}
    if mcp is not None:
        payload["mcp"] = mcp
    return SimpleNamespace(
        tool_name=tool, payload=payload, agent_id="spiffe://norviq/ns/analytics/sa/agent",
        namespace="analytics", agent_class="support", trust_score=0.9, session_id="s-1",
    )


@pytest.fixture
def evaluator():
    # _build_input / _derived_input are pure over the event; no cache or OPA connection is needed.
    return OPAEvaluator.__new__(OPAEvaluator)


def test_replay_input_carries_the_facts_a_real_evaluation_would(evaluator) -> None:
    doc = _opa_input_from_record(_rec(), evaluator)
    for key in ("derived", "mcp", "direction"):
        assert key in doc, f"{key} missing — a policy keyed on it silently under-fires in dry-run"


def test_derived_verb_is_classified_not_blank(evaluator) -> None:
    """The concrete case: an egress rule written as `derived.verb == "send"` must fire in dry-run."""
    assert _opa_input_from_record(_rec("send_email"), evaluator)["derived"]["verb"] == "send"
    assert _opa_input_from_record(_rec("read_file"), evaluator)["derived"]["verb"] == "read"


def test_mcp_context_survives_the_round_trip(evaluator) -> None:
    doc = _opa_input_from_record(_rec(mcp={"pin_status": "drift", "server": "s1"}), evaluator)
    assert doc["mcp"]["pin_status"] == "drift"
    assert doc["direction"] == "call"


def test_replay_input_matches_the_evaluator_key_for_key(evaluator) -> None:
    """The real invariant: no key the evaluator publishes may be absent from the replay. Compares the
    two documents structurally rather than asserting a hand-written list that can go stale."""
    from norviq.engine.trust import TrustResult
    from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

    rec = _rec()
    live = evaluator._build_input(
        ToolCallEvent(
            tool_name=rec.tool_name, tool_params=rec.payload["tool_params"],
            agent_identity=AgentIdentity(spiffe_id=rec.agent_id, namespace=rec.namespace,
                                         agent_class=rec.agent_class),
            session_id=rec.session_id,
        ),
        TrustResult(score=0.9, category="high", signals={}, weights={},
                    dominant_signal="x", recommendation="y"),
    )
    replay = _opa_input_from_record(rec, evaluator)
    missing = set(live) - set(replay)
    assert not missing, f"replay input is missing evaluator facts: {sorted(missing)}"


def test_no_evaluator_still_returns_a_usable_document() -> None:
    """The fallback path (unit tests without an evaluator) must not explode."""
    doc = _opa_input_from_record(_rec())
    assert doc["tool_name"] == "send_email"
