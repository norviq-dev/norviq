# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A promotion suggestion must never under-state what a tool can do.

`_top_verb` summarises the observed-verb histogram into the single verb shown to an admin on the
tool-classification screen, and that suggestion is what they promote. It used to rank by FREQUENCY
first, so a tool observed doing 4 reads and 2 deletes was headlined as `read` / risk `low` — and
promoting the suggestion would register a destructive tool as a harmless one, in the exact place a
human is being asked to make a security decision.

Observed live during pre-GA validation: zx9_vector_op, 6 calls, {delete: 2, read: 4} -> "read".

For an authorization decision the question is what a tool CAN do, not what it usually does. One
observed delete makes it a delete tool. The histogram still travels alongside, so nothing is hidden —
the headline just no longer rounds toward safe.
"""

from __future__ import annotations

import pytest

from norviq.api.routers.threats import _top_verb


@pytest.mark.parametrize(
    "verbs,expected",
    [
        # The live case. Frequency-first ranking called this "read".
        ({"read": 4, "delete": 2}, "delete"),
        # Rarity must not launder destructiveness.
        ({"read": 1000, "delete": 1}, "delete"),
        ({"read": 50, "write": 1}, "write"),
        ({"read": 50, "send": 1}, "send"),
        # Ordering across the whole ladder: delete > send > write > read.
        ({"read": 9, "write": 9, "send": 9, "delete": 1}, "delete"),
        ({"read": 9, "write": 9, "send": 1}, "send"),
        ({"read": 9, "write": 1}, "write"),
        # A single-verb histogram is unchanged.
        ({"read": 4}, "read"),
        ({"delete": 2}, "delete"),
    ],
)
def test_most_destructive_observed_verb_wins(verbs: dict, expected: str) -> None:
    assert _top_verb({"verbs": verbs})[0] == expected


def test_count_returned_belongs_to_the_selected_verb() -> None:
    """The count is evidence FOR the suggestion — returning the majority count next to a minority verb
    would overstate how much support the suggestion has."""
    verb, count = _top_verb({"verbs": {"read": 4, "delete": 2}})
    assert (verb, count) == ("delete", 2)


@pytest.mark.parametrize("evidence", [None, {}, {"verbs": {}}, {"verbs": None}])
def test_absent_evidence_yields_no_suggestion(evidence: dict | None) -> None:
    """No observations must produce no suggestion — never a default verb an admin might promote."""
    assert _top_verb(evidence) == (None, 0)


def test_unknown_verb_label_does_not_outrank_a_known_destructive_one() -> None:
    """An unrecognised label ranks lowest (0) rather than crashing or winning by accident."""
    assert _top_verb({"verbs": {"weird_label": 99, "delete": 1}})[0] == "delete"
