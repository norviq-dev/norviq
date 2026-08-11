# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A promoted tool verb must reach ENFORCEMENT, not just the console.

`classify_tool` returns UNKNOWN for a tool whose name it cannot resolve — that is exactly how a tool
enters the promotion queue. An admin then promotes it from observed evidence and the Threats screen
shows it classified. But `input.derived.verb` still read `unknown`, so a verb-gated policy behaved as
if nothing had been promoted: the promotion looked effective and changed nothing.

Verified live on AKS before the fix: promoting zx9_vector_op to delete/critical left
classify_tool("zx9_vector_op") returning `unknown`.

The map is read SYNCHRONOUSLY on the hot path (`_derived_input` runs inside `_build_input`, which
cannot await), so it is warmed out-of-band at startup and re-seeded on promote — the same shape as
`warm_agent_overrides`, which exists for the same reason on the freeze kill-switch.
"""

from __future__ import annotations

from types import SimpleNamespace

from norviq.engine.evaluator import OPAEvaluator


def _ev(overrides: dict | None = None) -> OPAEvaluator:
    ev = OPAEvaluator.__new__(OPAEvaluator)
    if overrides is not None:
        ev._verb_overrides = overrides
    return ev


def _event(tool: str, namespace: str = "chatbot-prod"):
    return SimpleNamespace(
        tool_name=tool,
        tool_params={},
        agent_identity=SimpleNamespace(namespace=namespace, agent_class="cs", spiffe_id="s"),
    )


def test_unpromoted_unclassifiable_tool_is_unknown() -> None:
    """The starting state: the classifier cannot name it, so a deny-by-default policy denies it."""
    assert _ev({})._derived_input(_event("zx9_vector_op"))["verb"] == "unknown"


def test_promoted_verb_reaches_the_policy_input() -> None:
    """The fix: after promotion, a verb-gated policy sees what the admin declared."""
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "delete"})
    assert ev._derived_input(_event("zx9_vector_op"))["verb"] == "delete"


def test_promotion_is_namespace_scoped() -> None:
    """A promotion in one namespace must not silently reclassify the same tool name in another —
    tenants promote independently, and leaking a `read` across would understate a destructive tool."""
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "delete"})
    assert ev._derived_input(_event("zx9_vector_op", "analytics"))["verb"] == "unknown"


def test_promotion_does_not_override_a_confidently_classified_tool() -> None:
    """Only the exact (namespace, tool) pair is overridden; unrelated tools keep classifier results."""
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "read"})
    assert ev._derived_input(_event("milvus_delete"))["verb"] == "delete"


def test_a_promotion_cannot_demote_a_classified_sink() -> None:
    """The promotion may FILL IN an unknown; it may not contradict the classifier.

    One POST — {"ns":"analytics","tool_name":"slack_post_message","verb":"read"} — used to make a
    classified sink stop being a sink. `derived.verb == "read"` satisfies `learned_read` and falsifies
    `is_egress` at the same time, so an AWS key went out through both baseline policies as
    ("allow","default_allow"), and the generated intent policy with readonly+egress ON flipped from
    ("block","intent_refinement_mismatch") to allow. The candidate LISTING only offers tools the
    classifier could not resolve; the write path never re-checked that, so the enforcement point has to.
    """
    ev = _ev({("analytics", "slack_post_message"): "read"})
    derived = ev._derived_input(_event("slack_post_message", "analytics"))
    assert derived["verb"] == "send"


def test_a_promotion_cannot_demote_a_classified_tool_in_any_direction() -> None:
    # Not only egress: an override must never be able to answer "what does this tool do" with less
    # than the classifier already knows, whichever verb it names.
    ev = _ev({("analytics", "milvus_delete"): "read", ("analytics", "milvus_search"): "send"})
    assert ev._derived_input(_event("milvus_delete", "analytics"))["verb"] == "delete"
    assert ev._derived_input(_event("milvus_search", "analytics"))["verb"] == "read"


def test_agent_supplied_params_cannot_cancel_a_promotion() -> None:
    """The other direction of the same invariant, and it was open.

    `classify_tool` falls back to inspecting TOOL_PARAMS when the NAME resolves nothing — and the
    promotion queue only ever offers tools whose name resolves nothing, so that fallback is live for
    every promoted tool. Guarding the override on "the classifier returned unknown" therefore handed
    the agent a cancel button: `zx9_vector_op` promoted to `delete` came back as `read` the moment the
    caller added `{"query": "select 1 from orders"}` to the call, because the payload had classified
    it. One attacker-chosen argument undid an admin decision, in the weakening direction — which is
    the same defect as the demotion the promotion guard was added to stop.
    """
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "delete"})
    event = _event("zx9_vector_op")
    event.tool_params = {"query": "select 1 from orders"}
    assert ev._derived_input(event)["verb"] == "delete"


def test_a_promotion_cannot_bury_what_the_payload_itself_shows() -> None:
    """And symmetrically: when the name says nothing, an admin's `read` must not erase a DROP sitting
    in the arguments. The two readings are of the same call and the more consequential one is
    published, so neither side of the disagreement is a way to weaken the other."""
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "read"})
    event = _event("zx9_vector_op")
    event.tool_params = {"sql": "DROP TABLE users"}
    assert ev._derived_input(event)["verb"] == "delete"


def test_uninitialised_map_degrades_to_classification() -> None:
    """An evaluator whose map was never warmed must fall back, not raise. Degrading to classification is
    the safe direction — the worst case is `unknown`, which deny-by-default denies; raising on the hot
    path would fail every call."""
    ev = OPAEvaluator.__new__(OPAEvaluator)  # no _verb_overrides at all
    assert ev._derived_input(_event("milvus_search"))["verb"] == "read"
    assert ev._derived_input(_event("zx9_vector_op"))["verb"] == "unknown"


def test_event_without_identity_degrades_to_classification() -> None:
    ev = _ev({("chatbot-prod", "zx9_vector_op"): "delete"})
    bare = SimpleNamespace(tool_name="zx9_vector_op", tool_params={})
    assert ev._derived_input(bare)["verb"] == "unknown"


async def test_refresh_replaces_the_map_wholesale() -> None:
    """Swapped whole, never mutated in place: a half-rebuilt map would briefly report the WRONG verb and
    a deny-by-default policy would deny live traffic for the duration."""
    ev = _ev({("ns", "old_tool"): "read"})
    n = await ev.refresh_verb_overrides([
        {"namespace": "ns", "tool_name": "new_tool", "verb": "delete"},
    ])
    assert n == 1
    assert ev._verb_overrides == {("ns", "new_tool"): "delete"}  # the stale entry is gone


async def test_refresh_skips_incomplete_rows() -> None:
    """A row missing any of the three fields cannot key a lookup — dropping it beats inserting a
    half-formed entry that would shadow the classifier with an empty verb."""
    ev = _ev({})
    n = await ev.refresh_verb_overrides([
        {"namespace": "ns", "tool_name": "t", "verb": "delete"},
        {"namespace": "", "tool_name": "t2", "verb": "read"},
        {"namespace": "ns", "tool_name": "", "verb": "read"},
        {"namespace": "ns", "tool_name": "t3", "verb": ""},
    ])
    assert n == 1
