# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The eval cache is keyed on (namespace, agent_class, tool+params+depth+workload+mcp) — per CLASS,
not per agent. A policy that reads a per-IDENTITY fact therefore cannot be cached: its decision was
computed for whichever agent called first, and `_handle_cache_hit` re-applies the posture threshold,
the freeze/cap and monitor mode but never re-runs the cached rego. A rule threshold stricter than the
namespace posture — the entire reason to author one — was bypassed for every other agent in the class
until the TTL expired.

`input.trust_score` is authorable from BOTH compilers (the visual builder's `trustBelow`,
ui/src/lib/builderCompile.ts; `trust_score` in norviq/engine/intent/schema.py), so this is reachable
from the product's own policy-authoring surfaces, not just hand-written rego.
"""

from __future__ import annotations

from norviq.engine.evaluator import OPAEvaluator

TRUST_RULE = """
package norviq.custom
deny contains {"rule": "low_trust"} if {
    input.trust_score < 0.7
}
"""

CLASS_ONLY_RULE = """
package norviq.custom
deny contains {"rule": "no_delete"} if {
    input.tool_name == "delete_database"
}
"""


def test_a_policy_reading_trust_score_is_not_cached() -> None:
    """FAIL-ON-BUG: caching this decision serves one agent's verdict to a different-trust agent."""
    assert OPAEvaluator._depends_on_per_identity_facts([{"rego": TRUST_RULE}]) is True


def test_one_trust_rule_among_many_still_blocks_caching() -> None:
    """The guard is over the whole candidate set — a single per-identity rule taints the decision,
    because the resolver may pick it."""
    candidates = [{"rego": CLASS_ONLY_RULE}, {"rego": TRUST_RULE}]
    assert OPAEvaluator._depends_on_per_identity_facts(candidates) is True


def test_trust_category_and_spiffe_id_count_too() -> None:
    """trust_score is not the only per-agent fact a policy can read; a category or a raw SPIFFE id
    partitions agents inside one class just as effectively."""
    assert OPAEvaluator._depends_on_per_identity_facts([{"rego": "x := input.trust_category"}]) is True
    assert OPAEvaluator._depends_on_per_identity_facts([{"rego": "x := input.agent.spiffe_id"}]) is True


def test_a_class_scoped_policy_is_still_cacheable() -> None:
    """The guard must not disable caching wholesale — that would be its own defect. A policy keyed on
    facts the cache key already carries stays cacheable."""
    assert OPAEvaluator._depends_on_per_identity_facts([{"rego": CLASS_ONLY_RULE}]) is False
    assert OPAEvaluator._depends_on_per_identity_facts([]) is False


def test_a_candidate_with_no_rego_is_not_treated_as_trust_dependent() -> None:
    """A missing/empty source must not silently disable the cache for everything."""
    assert OPAEvaluator._depends_on_per_identity_facts([{"rego": None}, {}]) is False


# --- the trust-history param_hash was never a param hash -------------------------------------------


def test_params_digest_actually_tracks_the_params() -> None:
    """`_safe_record_history` used to derive its `param_hash` as `cache_tool.split(":")[-1]`.

    The key is `{tool}:{digest}:d{depth}:w{workload}[:m…]`, so the last segment is the WORKLOAD — a
    value that is constant for an agent. The rolling trust-history signal meant to notice "same tool,
    same arguments, over and over" was comparing a constant, so every call looked like a repeat of the
    last. Indexing from the front is not a fix either: an MCP tool name legitimately contains a colon.
    """
    from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

    def ev(params: dict, tool: str = "search_kb") -> ToolCallEvent:
        return ToolCallEvent(
            tool_name=tool,
            tool_params=params,
            agent_identity=AgentIdentity(
                spiffe_id="spiffe://norviq/ns/default/sa/a", namespace="default", agent_class="c"
            ),
            session_id="s",
        )

    a = OPAEvaluator._params_digest(ev({"query": "refunds"}))
    b = OPAEvaluator._params_digest(ev({"query": "payroll"}))
    assert a != b, "different arguments must produce different param hashes"
    assert a == OPAEvaluator._params_digest(ev({"query": "refunds"})), "same arguments must be stable"
    # Key ordering must not change the fingerprint, or 'same arguments' depends on dict insertion order.
    assert OPAEvaluator._params_digest(ev({"x": 1, "y": 2})) == OPAEvaluator._params_digest(ev({"y": 2, "x": 1}))
    # And it must not vary with the tool name, which is recorded separately.
    assert OPAEvaluator._params_digest(ev({"q": 1}, "a:b")) == OPAEvaluator._params_digest(ev({"q": 1}, "other"))
