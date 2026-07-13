# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for the red-team catalog mapping (B1) + efficacy roll-up (B3) — pure, no DB."""

from __future__ import annotations

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
