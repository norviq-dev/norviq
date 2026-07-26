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
