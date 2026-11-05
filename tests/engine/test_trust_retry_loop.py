# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A retried refusal must not cost trust on every attempt.

BACKLOG §7.10, measured on kind: an agent retried one refused run_query 12 times, every attempt was a
block, the violation rate crossed the cap's 20% band and trust was capped to 0.30 — so its benign calls
on an unrelated MCP server escalated. Retrying is not misbehaviour, and making an agent retry something
refused is a denial of service anyone can trigger. The same tool with the same parameters now counts
once; different attempts still count every time.
"""

from __future__ import annotations

import asyncio
import time

from norviq.engine.trust.calculator import TrustCalculator
from norviq.engine.trust.signals.base import collapse_repeated_refusals
from norviq.engine.trust.signals.time_decay import TimeDecaySignal
from norviq.engine.trust.signals.violation_rate import ViolationRateSignal

NOW = time.time()


def _entry(decision: str, tool: str, params: str, age_s: float = 0.0) -> dict:
    ts = NOW - age_s
    return {"decision": decision, "tool_name": tool, "param_hash": params, "timestamp_unix": ts,
            "timestamp": __import__("datetime").datetime.fromtimestamp(ts, __import__("datetime").timezone.utc).isoformat()}


def _benign(n: int) -> list[dict]:
    return [_entry("allow", f"tool_{i % 4}", f"p{i}", age_s=600 - i) for i in range(n)]


def _cap(history: list[dict]) -> float:
    calc = TrustCalculator.__new__(TrustCalculator)
    rate = asyncio.run(ViolationRateSignal().compute(None, history, {}))
    return calc._violation_cap({"violation_rate": rate}, len(collapse_repeated_refusals(history)))


def test_a_retry_loop_on_one_refused_call_does_not_reach_the_cap() -> None:
    retries = [_entry("block", "run_query", "sql:select-8812", age_s=30 - i) for i in range(12)]
    history = _benign(14) + retries
    # Uncollapsed, this is 12 of 26 = 46% blocked: over the 20% band, so the cap would be 0.30.
    assert sum(e["decision"] == "block" for e in history) / len(history) > 0.20
    assert asyncio.run(ViolationRateSignal().compute(None, history, {})) > 0.0
    assert _cap(history) > 0.30, "a retry loop alone pushed the agent into the escalation band"


def test_different_refused_calls_still_reach_the_cap() -> None:
    """The fix must not let a real pattern of violations escape: different attempts all count."""
    probes = [_entry("block", "run_query", f"sql:variant-{i}", age_s=30 - i) for i in range(12)]
    history = _benign(14) + probes
    assert asyncio.run(ViolationRateSignal().compute(None, history, {})) == 0.0
    assert _cap(history) == 0.30


def test_different_tools_with_the_same_params_still_count_separately() -> None:
    probes = [_entry("block", f"tool_{i}", "same", age_s=30 - i) for i in range(12)]
    assert _cap(_benign(14) + probes) == 0.30


def test_the_history_unavailable_fallback_still_assumes_the_worst() -> None:
    """The calculator fabricates 20 keyless blocks when it cannot read history. Collapsing them would
    turn "assume the worst" into "one block"."""
    fabricated = [{"decision": "block", "timestamp": "2026-01-01T00:00:00+00:00"}] * 20
    assert len(collapse_repeated_refusals(fabricated)) == 20
    assert asyncio.run(ViolationRateSignal().compute(None, fabricated, {})) == 0.0


def test_retrying_does_not_keep_resetting_the_decay_clock() -> None:
    """First refused 2h ago, retried until now: decay is measured from the first refusal."""
    history = [_entry("block", "run_query", "sql:x", age_s=7200)] + [
        _entry("block", "run_query", "sql:x", age_s=60 - i) for i in range(10)]
    assert asyncio.run(TimeDecaySignal().compute(None, history, {})) == 0.4
    fresh = history + [_entry("block", "send_dm", "to:attacker", age_s=5)]
    assert asyncio.run(TimeDecaySignal().compute(None, fresh, {})) == 0.1, "a NEW refusal must still reset it"


def test_allowed_and_escalated_entries_are_never_collapsed() -> None:
    history = [_entry("allow", "search", "q", age_s=i) for i in range(5)] + [
        _entry("escalate", "create_issue", "t", age_s=i) for i in range(5)]
    assert len(collapse_repeated_refusals(history)) == 10
