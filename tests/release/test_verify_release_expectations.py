# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The release gate's enforcement expectations are what this release's engine answers.

scripts/verify_release.py installs the chart into a throwaway cluster and asserts decisions for one
identity. Those expectations live in the script, the defaults in the chart and the engine, and nothing
tied them together: 0.2.6 made the namespace baseline enforce while the gate still asserted
`audit` + `strict_default_block` for execute_sql on a stock install, so the release would have failed its
own gate on correct behaviour (or, with that expectation "fixed" the other way, passed an artifact that
only observes). This runs the gate's probes through the real resolver and the managed OPA with the
chart's baseline stored the way the controller stores it, and the console's controls the way PUT
/baseline/controls compiles them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from norviq.api import baseline
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from tests.engine.test_saved_controls_supersede_the_chart_baseline import _evaluator

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))  # release scripts are not a package; import them by path
import verify_release as vr  # noqa: E402

# The chart's baseline exactly as webhook/controller.go stores it for policyQuotaNamespaces=[TENANT]:
# the strict preset as authored, at baselineFallbackPriority, in the chart's default enforcementMode.
STOCK = {f"{vr.TENANT}:__baseline__": {"rego": baseline.preset_source("strict"), "priority": 1,
                                       "enforcement_mode": "block"}}


def _controls(effects: dict) -> dict:
    """What PUT /baseline/controls stores (baseline_router._write_controls)."""
    return {f"{vr.TENANT}:__controls__": {"rego": baseline.compile("strict", effects), "priority": 2,
                                          "enforcement_mode": "block"}}


async def _decide(policies: dict, tool: str, params: dict) -> tuple[str, str]:
    identity = AgentIdentity(spiffe_id=f"spiffe://norviq/ns/{vr.TENANT}/sa/chatbot", namespace=vr.TENANT,
                             agent_class="chatbot", workload="chatbot")
    ev = _evaluator(policies)
    try:
        decision = await ev.evaluate(ToolCallEvent(tool_name=tool, tool_params=params, session_id="verify",
                                                   agent_identity=identity))
    finally:
        await ev.close()
    return decision.decision, decision.rule_id


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool", "params", "want", "want_rule"), vr.STOCK_PROBES)
async def test_the_gate_expects_what_a_stock_install_answers(tool: str, params: dict, want: str,
                                                             want_rule: str) -> None:
    assert await _decide(STOCK, tool, params) == (want, want_rule)


@pytest.mark.asyncio
async def test_the_gate_expects_what_the_per_control_switch_does() -> None:
    _, params, *_ = next(p for p in vr.STOCK_PROBES if p[0] == "execute_sql")
    for effects, want, want_rule in vr.CONTROL_ROUND_TRIP:
        assert await _decide({**STOCK, **_controls(effects)}, "execute_sql", params) == (want, want_rule), effects


def test_the_round_trip_actually_crosses_an_effect() -> None:
    """Keeps the gate a real check: the switch has to move the decision away from the stock answer and
    back, or a console switch that does nothing would pass it."""
    stock = next((w, r) for t, _, w, r in vr.STOCK_PROBES if t == "execute_sql")
    answers = [(w, r) for _, w, r in vr.CONTROL_ROUND_TRIP]
    assert stock == ("block", "strict_default_block")
    assert any(a != stock for a in answers) and answers[-1] == stock
