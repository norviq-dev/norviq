# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The MCP vector catalog is a claim about coverage, so its integrity is a security property.

Two failure modes these guard against, both of which turn the coverage block from a fact into an alibi:
a vector the suite cannot score but never says why (indistinguishable from someone forgetting to
classify it), and an attack pointing at a vector the suite structurally cannot adjudicate (which would
score a PROXY control red forever, with no operator action that fixes it).
"""

from __future__ import annotations

import re

import pytest

from norviq.redteam.attacks import ATTACKS
from norviq.redteam.vectors import (
    EVALUATE_REACHABLE,
    VECTORS,
    VECTORS_BY_ID,
    McpVector,
    Reachability,
    coverage_denominators,
)

_KEBAB = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def test_every_unmeasurable_vector_states_a_reason() -> None:
    """The contract `_validate()` enforces at import, asserted here so the failure is legible."""
    for v in VECTORS:
        if v.reachability is not Reachability.EVALUATE:
            assert v.reason.strip(), f"{v.id} is {v.reachability.value} and says nothing about why"


def test_validate_rejects_a_silent_unmeasurable_vector() -> None:
    """Proves the import-time guard is load-bearing rather than decorative."""
    import norviq.redteam.vectors as mod

    bad = McpVector("x-silent", VECTORS[0].surface, "t", Reachability.PROXY)
    original = mod.VECTORS
    try:
        mod.VECTORS = (*original, bad)
        with pytest.raises(ValueError, match="states no reason"):
            mod._validate()
    finally:
        mod.VECTORS = original


def test_validate_rejects_a_duplicate_id() -> None:
    """A duplicate would silently MERGE two vectors' scores into one bucket."""
    import norviq.redteam.vectors as mod

    original = mod.VECTORS
    try:
        mod.VECTORS = (*original, original[0])
        with pytest.raises(ValueError, match="duplicate"):
            mod._validate()
    finally:
        mod.VECTORS = original


def test_ids_are_unique_and_kebab() -> None:
    ids = [v.id for v in VECTORS]
    assert len(ids) == len(set(ids))
    for vid in ids:
        assert _KEBAB.match(vid), f"{vid!r} is not kebab-case"


def test_catalog_matches_the_design_document() -> None:
    """The doc is the source of the taxonomy; drift between them means the denominator is wrong.
    Exactly one id is expected to be absent from the doc — the composition vector minted here, which
    had no identifier anywhere (see docs/design/MCP-RED-BLUE-LOOP.md Finding 1)."""
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[2] / "docs/design/MCP-TOOL-ATTACK-SURFACE.md").read_text()
    doc_ids = set(re.findall(r"^\| `([a-z0-9-]+)`", doc, re.M))
    assert doc_ids - set(VECTORS_BY_ID) == set(), "the doc names a vector the catalog does not"
    assert set(VECTORS_BY_ID) - doc_ids == {"base-allowlist-strips-baseline-floor"}


def test_coverage_denominators_partition_the_catalog() -> None:
    d = coverage_denominators()
    assert d["catalogued"] == len(VECTORS)
    assert d["evaluate_reachable"] + d["proxy_only"] + d["out_of_scope"] == d["catalogued"]
    assert d["evaluate_reachable"] == len(EVALUATE_REACHABLE)


def test_the_suite_can_score_something() -> None:
    """A catalog with nothing reachable would render a coverage block over an empty dimension."""
    assert EVALUATE_REACHABLE


def test_every_attack_vector_is_catalogued() -> None:
    """An attack pointing at an id the catalog does not know would vanish from `by_vector`'s title
    lookup and render as a bare slug the operator cannot act on."""
    for attack in ATTACKS:
        vid = getattr(attack, "mcp_vector", "")
        if vid:
            assert vid in VECTORS_BY_ID, f"{attack.id} targets uncatalogued vector {vid!r}"


def test_no_attack_targets_an_unmeasurable_vector() -> None:
    """The load-bearing one. An attack against a PROXY vector scores the wrong layer: the control is
    working, the engine never sees it, and the suite reports red forever with no operator action that
    fixes it."""
    for attack in ATTACKS:
        vid = getattr(attack, "mcp_vector", "")
        if vid:
            assert VECTORS_BY_ID[vid].reachability is Reachability.EVALUATE, (
                f"{attack.id} targets {vid!r}, which is "
                f"{VECTORS_BY_ID[vid].reachability.value} — it cannot be scored by this suite"
            )


def test_mcp_attack_params_are_unique_across_the_corpus() -> None:
    """The eval cache keys on tool+params (+depth, workload, mcp). Two attacks differing ONLY in their
    MCP document used to alias inside the 5s TTL and the second reported the first's decision; that is
    fixed in `_cache_tool_key`, but keeping the payloads distinct means a future regression there
    cannot quietly corrupt this dimension's scores."""
    import json

    seen: dict[str, str] = {}
    for attack in ATTACKS:
        if not getattr(attack, "mcp_vector", ""):
            continue
        key = f"{attack.tool_name}|{json.dumps(attack.tool_params, sort_keys=True)}"
        assert key not in seen, f"{attack.id} shares tool+params with {seen[key]}"
        seen[key] = attack.id
