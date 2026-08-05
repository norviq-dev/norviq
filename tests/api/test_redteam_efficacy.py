# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for the red-team catalog mapping + efficacy roll-up — pure, no DB."""

from __future__ import annotations

from norviq.redteam.vectors import EVALUATE_REACHABLE, VECTORS
from norviq.api.redteam_efficacy import (
    attack_mapping,
    catalog_entry,
    compute_efficacy,
    owasp_control_for_category,
)
from norviq.redteam.attacks import ATTACKS, get_attack_by_id


def test_owasp_control_for_category_only_maps_owasp_categories():
    assert owasp_control_for_category("OWASP_LLM01") == "LLM01:2025"
    assert owasp_control_for_category("OWASP_LLM10") == "LLM10:2025"
    # non-OWASP categories have an ATLAS technique but no OWASP control
    assert owasp_control_for_category("SQL_INJECTION") is None
    assert owasp_control_for_category("CROSS_TENANT") is None


def test_attack_mapping_resolves_display_names():
    sqli = get_attack_by_id("SQL-001")
    m = attack_mapping(sqli)
    assert m["atlas"]["technique_id"] == sqli.mitre_technique
    assert m["atlas"]["technique_name"]  # resolved from the shipped ATLAS mapping (non-empty)
    assert m["owasp"] is None  # SQL injection is not an OWASP LLM category


def test_catalog_entry_carries_both_frameworks_for_owasp_attack():
    pi = get_attack_by_id("PI-001")  # OWASP_LLM01
    entry = catalog_entry(pi)
    assert entry["attack_id"] == "PI-001"
    assert entry["atlas_technique"] == pi.mitre_technique
    assert entry["owasp_control"] == "LLM01:2025"
    assert entry["owasp_control_name"]
    assert entry["expected_decision"] == "block"


def test_every_attack_maps_to_an_atlas_technique():
    for a in ATTACKS:
        entry = catalog_entry(a)
        assert entry["atlas_technique"].startswith("AML.T")
        # OWASP mapping present iff the category is an OWASP LLM category
        is_owasp = a.category.name.startswith("OWASP_LLM")
        assert (entry["owasp_control"] is not None) == is_owasp


def _row(attack_id, agent_class, actual, technique="AML.T0048", tname="T", owasp=None, oname=None, expected="block"):
    return {
        "attack_id": attack_id, "agent_class": agent_class, "namespace": "default",
        "expected": expected, "actual": actual, "passed": actual == expected,
        "atlas_technique": technique, "atlas_technique_name": tname,
        "owasp_control": owasp, "owasp_control_name": oname,
    }


def test_efficacy_caught_vs_got_through():
    rows = [
        _row("A", "billing", "block"),   # caught
        _row("B", "billing", "allow"),   # got through (expected block, allowed)
        _row("C", "billing", "block"),   # caught
    ]
    eff = compute_efficacy(rows)
    assert eff["overall"]["total"] == 3
    assert eff["overall"]["caught"] == 2
    assert eff["overall"]["got_through"] == 1
    assert eff["overall"]["proven_blocking_pct"] == round(2 / 3 * 100, 1)


def test_efficacy_excludes_synthetic_targets():
    rows = [
        _row("A", "billing", "block"),          # real, caught
        _row("B", "scorer", "allow"),           # synthetic class → excluded entirely
        _row("C", "policy-tester", "allow"),    # synthetic class → excluded entirely
    ]
    eff = compute_efficacy(rows)
    assert eff["overall"]["total"] == 1  # only the real billing row counts
    assert eff["overall"]["caught"] == 1
    assert eff["overall"]["got_through"] == 0
    assert eff["excluded_synthetic"] == 2


def test_efficacy_excludes_inapplicable_sector_attacks():
    # A sector-pack attack whose pack isn't enabled (applicable=False) must NOT deflate proven-blocking —
    # a baseline-only namespace with flawless baseline enforcement should read 100%, not a diluted number.
    rows = [
        {**_row("A", "billing", "block"), "applicable": True},   # baseline, caught
        {**_row("B", "billing", "block"), "applicable": True},   # baseline, caught
        {**_row("FIN-001", "billing", "allow"), "applicable": False},  # finance pack NOT enabled → out of scope
    ]
    eff = compute_efficacy(rows)
    assert eff["overall"]["total"] == 2  # the sector row is excluded, not a got-through
    assert eff["overall"]["got_through"] == 0
    assert eff["overall"]["proven_blocking_pct"] == 100.0
    assert eff["sector_not_enabled"] == 1


def test_efficacy_non_block_expected_not_counted_as_miss():
    rows = [
        _row("A", "billing", "allow", expected="allow"),  # runtime/intent control case (expected allow)
        _row("B", "billing", "block"),                    # real block, caught
    ]
    eff = compute_efficacy(rows)
    assert eff["overall"]["total"] == 1  # only the block-expected attack counts toward the ratio
    assert eff["overall"]["got_through"] == 0
    assert eff["non_enforcement"] == 1


def test_efficacy_groups_by_technique_and_owasp():
    rows = [
        _row("A", "billing", "block", technique="AML.T0048", tname="Injection", owasp="LLM01:2025", oname="Prompt Injection"),
        _row("B", "billing", "allow", technique="AML.T0048", tname="Injection", owasp="LLM01:2025", oname="Prompt Injection"),
        _row("C", "billing", "block", technique="AML.T0054", tname="Jailbreak"),
    ]
    eff = compute_efficacy(rows)
    tech = {t["technique_id"]: t for t in eff["by_technique"]}
    assert tech["AML.T0048"]["total"] == 2 and tech["AML.T0048"]["got_through"] == 1
    assert tech["AML.T0054"]["caught"] == 1
    owasp = {o["control_id"]: o for o in eff["by_owasp"]}
    assert owasp["LLM01:2025"]["total"] == 2
    assert owasp["LLM01:2025"]["proven_blocking_pct"] == 50.0


def test_efficacy_empty_is_zero_not_crash():
    eff = compute_efficacy([])
    assert eff["overall"] == {"total": 0, "caught": 0, "got_through": 0, "proven_blocking_pct": 0.0}
    assert eff["by_technique"] == [] and eff["by_owasp"] == []


# --- MCP / tool vector dimension ------------------------------------------------------------------
#
# The third dimension exists so an operator can see MCP coverage next to OWASP. The coverage block
# exists so they can see how much of it the score does NOT cover — a scorecard reading 100% across two
# vectors while thirty are untouched is the failure this product is built to prevent.


def _mcp_row(attack_id, actual, vector, title="t", expected="block", agent_class="billing"):
    r = _row(attack_id, agent_class, actual, expected=expected)
    r["mcp_vector"] = vector
    r["mcp_vector_title"] = title
    return r


def test_efficacy_groups_by_mcp_vector():
    rows = [
        _mcp_row("MCP-01", "block", "mcp-server-identity-unattested", "self-asserted server id"),
        _mcp_row("MCP-02", "allow", "mcp-server-identity-unattested", "self-asserted server id"),
        _mcp_row("MCP-04", "block", "base-allowlist-strips-baseline-floor", "composition"),
    ]
    eff = compute_efficacy(rows)
    by_vec = {v["vector_id"]: v for v in eff["by_vector"]}
    assert by_vec["mcp-server-identity-unattested"]["total"] == 2
    assert by_vec["mcp-server-identity-unattested"]["got_through"] == 1
    assert by_vec["mcp-server-identity-unattested"]["proven_blocking_pct"] == 50.0
    assert by_vec["mcp-server-identity-unattested"]["vector_title"] == "self-asserted server id"
    assert by_vec["base-allowlist-strips-baseline-floor"]["caught"] == 1


def test_rows_with_no_mcp_vector_make_no_unknown_bucket():
    """The 29 attacks predating this dimension exercise NO MCP vector — not an unidentified one.
    Bucketing them as 'unknown' (the way `by_technique` legitimately does for a broken mapping) would
    assert something false and render one row that dominates the table."""
    rows = [_row("A", "billing", "block"), _row("B", "billing", "allow")]
    eff = compute_efficacy(rows)
    assert eff["by_vector"] == []
    assert eff["overall"]["total"] == 2  # still counted everywhere else
    assert eff["vector_coverage"]["exercised"] == 0


def test_vector_coverage_denominators_partition_the_catalog():
    cov = compute_efficacy([])["vector_coverage"]
    assert cov["catalogued"] == len(VECTORS)
    assert cov["evaluate_reachable"] + cov["proxy_only"] + cov["out_of_scope"] == cov["catalogued"]


def test_vector_coverage_counts_distinct_vectors_not_rows():
    """Surface coverage, not attack volume: three attacks on one vector is one vector exercised."""
    rows = [_mcp_row(f"MCP-0{i}", "block", "mcp-server-identity-unattested") for i in range(3)]
    cov = compute_efficacy(rows)["vector_coverage"]
    assert cov["exercised"] == 1


def test_vector_coverage_names_what_was_not_exercised():
    """The honest half. A reachable vector nobody attacked must be listed, not silently absent."""
    rows = [_mcp_row("MCP-01", "block", "mcp-server-identity-unattested")]
    cov = compute_efficacy(rows)["vector_coverage"]
    assert "mcp-server-identity-unattested" not in cov["unexercised_reachable"]
    assert "resources-read-uri-gate" in cov["unexercised_reachable"]
    assert set(cov["unexercised_reachable"]) <= EVALUATE_REACHABLE


def test_vector_coverage_present_on_a_run_with_no_mcp_attacks():
    """Absent would read as 'this build has no MCP dimension'; zero reads as 'nothing was measured'."""
    cov = compute_efficacy([_row("A", "billing", "block")])["vector_coverage"]
    assert cov["exercised"] == 0
    assert sorted(cov["unexercised_reachable"]) == sorted(EVALUATE_REACHABLE)


def test_inapplicable_mcp_attack_is_not_a_miss_and_not_a_bucket():
    """No shipped baseline reads `input.mcp`, so an MCP attack in a namespace without the opt-in
    guardrail can never be blocked. Counting that as got_through would paint every default namespace
    red for a control that was never installed."""
    row = _mcp_row("MCP-01", "allow", "mcp-server-identity-unattested")
    row["applicable"] = False
    eff = compute_efficacy([row])
    assert eff["overall"]["total"] == 0
    assert eff["sector_not_enabled"] == 1
    assert eff["by_vector"] == []
