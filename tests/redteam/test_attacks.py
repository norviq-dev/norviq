# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team attack catalog."""

from norviq.redteam.attacks import ATTACKS, AttackCategory, get_attack_by_id, get_attacks_by_category


def test_attack_catalog_has_25_plus_items() -> None:
    """Ensure catalog size target is met."""
    assert len(ATTACKS) >= 25


def test_get_attacks_by_category_filters() -> None:
    """Return only matching category attacks."""
    attacks = get_attacks_by_category(AttackCategory.SQL_INJECTION)
    assert attacks
    assert all(attack.category == AttackCategory.SQL_INJECTION for attack in attacks)


def test_get_attack_by_id_returns_expected_match() -> None:
    """Resolve known attack ID."""
    attack = get_attack_by_id("PI-001")
    assert attack is not None
    assert attack.id == "PI-001"
