# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent nodes must carry the REAL trust score, not `add_agent`'s default.

`record_tool_call` never passed a score, and nothing else ever updated one, so every agent node in
every graph held `add_agent`'s `trust_score: float = 0.8` forever. Nothing crashed — which is why it
survived. What it broke was entirely downstream and entirely silent:

  * the Attack Graph inspector's "Min trust" read 0.80 for every agent, always;
  * the kill-chain severity formula (`threats.py`) is a function of trust, so with trust pinned it
    collapsed to two possible outputs — the Critical and Low severity filter chips could never match
    a single path, and the "Critical paths" stat cell was structurally always 0;
  * `GET /api/v1/graph/critical-paths` always returned `[]`, and `summary.low_trust_agents` always 0.

A feature that always returns empty looks exactly like a feature with nothing to report. These pin the
score end to end so it cannot freeze again.
"""

from __future__ import annotations

from norviq.engine.graph.asset_graph import AssetGraphBuilder


def _props(graph: AssetGraphBuilder, spiffe: str) -> dict:
    return graph.graph.nodes[spiffe]["properties"]


SPIFFE = "spiffe://norviq/ns/analytics/sa/agent"


def test_first_call_records_the_real_score_not_the_default() -> None:
    g = AssetGraphBuilder()
    g.record_tool_call(SPIFFE, "read_file", "allow", "analytics", "scorer", trust_score=0.21)
    assert _props(g, SPIFFE)["trust_score"] == 0.21


def test_score_moves_on_later_calls() -> None:
    """Trust is behavioural — it changes between calls. A node created at 0.9 must not stay there."""
    g = AssetGraphBuilder()
    g.record_tool_call(SPIFFE, "read_file", "allow", "analytics", "scorer", trust_score=0.9)
    g.record_tool_call(SPIFFE, "delete_records", "block", "analytics", "scorer", trust_score=0.15)
    assert _props(g, SPIFFE)["trust_score"] == 0.15


def test_category_is_updated_with_the_score() -> None:
    """The console reads trust_category. Updating the score alone would leave the node contradicting
    itself — a low score still wearing the category it was created with."""
    g = AssetGraphBuilder()
    g.record_tool_call(SPIFFE, "read_file", "allow", "analytics", "scorer", trust_score=0.95)
    high = _props(g, SPIFFE)["trust_category"]
    g.record_tool_call(SPIFFE, "delete_records", "block", "analytics", "scorer", trust_score=0.05)
    low = _props(g, SPIFFE)["trust_category"]
    assert high != low, "category did not follow the score"
    assert low == g._trust_category(0.05)


def test_omitting_the_score_does_not_fabricate_one() -> None:
    """Callers that genuinely have no score (tests, backfills) must leave the node's own value alone
    rather than stamping a made-up number over it."""
    g = AssetGraphBuilder()
    g.record_tool_call(SPIFFE, "read_file", "allow", "analytics", "scorer", trust_score=0.3)
    g.record_tool_call(SPIFFE, "read_file", "allow", "analytics", "scorer")  # no score
    assert _props(g, SPIFFE)["trust_score"] == 0.3


def test_distinct_agents_can_hold_distinct_scores() -> None:
    """The whole point: a graph must be able to contain a spread of trust, which is what every
    trust-derived read (severity, critical paths, low_trust_agents) needs to produce anything."""
    g = AssetGraphBuilder()
    scores = {f"spiffe://norviq/ns/analytics/sa/a{i}": round(0.1 * i, 2) for i in range(1, 6)}
    for spiffe, score in scores.items():
        g.record_tool_call(spiffe, "read_file", "allow", "analytics", "scorer", trust_score=score)
    observed = {s: _props(g, s)["trust_score"] for s in scores}
    assert observed == scores
    assert len(set(observed.values())) == 5, "trust collapsed to a single value again"


def test_evaluator_passes_the_decision_trust_score() -> None:
    """Guard the wiring, not just the sink: `_safe_record_graph` must hand over `decision.trust_score`.
    Without this the builder API stays correct while the only production caller keeps omitting it."""
    import inspect

    from norviq.engine.evaluator import OPAEvaluator

    src = inspect.getsource(OPAEvaluator._safe_record_graph)
    assert "trust_score=decision.trust_score" in src
