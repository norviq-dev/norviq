# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The confusable skeleton folds homoglyph/zero-width evasion to its ASCII prototype for injection
matching, while leaving genuine non-Latin text intact (matching-only; original preserved for audit)."""

from __future__ import annotations

from norviq.engine.confusables import skeleton
from norviq.engine.evaluator import OPAEvaluator


def test_cyrillic_homoglyph_folds_to_ascii() -> None:
    # The exact repro: Cyrillic і/о/е look-alikes.
    assert "ignore previous" in skeleton("іgnоre prevіоus instructions")


def test_greek_homoglyph_folds() -> None:
    # Greek ο (omicron), ρ (rho), ε look-alikes inside "ignore"/"bypass".
    assert "bypass" in skeleton("byρass")  # rho -> p


def test_zero_width_and_combining_stripped() -> None:
    assert skeleton("ig​no‍re") == "ignore"  # ZWSP/ZWJ removed
    assert skeleton("ignóre") == "ignore"  # combining acute removed


def test_fullwidth_via_nfkc() -> None:
    assert skeleton("ｉｇｎｏｒｅ") == "ignore"


def test_ascii_unchanged_lowercased() -> None:
    assert skeleton("Ignore Previous") == "ignore previous"


def test_genuine_non_latin_preserved() -> None:
    # Real Japanese/Arabic text is not Latin-confusable -> not folded into an injection keyword.
    assert skeleton("注文を検索") == "注文を検索"
    assert "ignore" not in skeleton("مرحبا بالعالم")


def test_normalize_for_match_only_strings() -> None:
    out = OPAEvaluator._normalize_for_match({"q": "іgnоre", "n": 5, "list": ["оr 1=1", 7]})
    assert "ignore" in out["q"]
    assert out["n"] == 5
    assert "or 1=1" in out["list"][0] and out["list"][1] == 7
