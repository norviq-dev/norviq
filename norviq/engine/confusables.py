# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unicode confusable skeleton for injection MATCHING (F-02).

Homoglyph evasion: "іgnоre" (Cyrillic і/о) reads as "ignore" but evades a literal ASCII match. NFKC alone does
NOT fold cross-script look-alikes (Cyrillic о U+043E is not NFKC-equivalent to Latin o). `skeleton()` therefore:
  1. NFKC-normalizes (folds fullwidth, mathematical-alphanumeric, and other compatibility forms),
  2. casefolds,
  3. strips combining marks + zero-width / format / control chars (defeats "i<ZWSP>gnore" and accent stacking),
  4. translates the Latin-confusable letters of the scripts that actually confuse with ASCII (Cyrillic, Greek,
     plus a few others) to their ASCII prototype — a vendored Unicode-TR39-aligned skeleton, broad (whole-alphabet)
     not keyword-specific.

This is MATCHING-only: callers keep the ORIGINAL string for audit/display; only the skeleton feeds pattern matching,
so legitimate non-Latin tool arguments are never altered in stored data and are only "blocked" if their skeleton
genuinely matches an attack pattern (astronomically unlikely for real text).
"""

from __future__ import annotations

import unicodedata

# Latin-confusable letters → ASCII prototype. Lowercase targets (skeleton casefolds first). Whole-alphabet
# coverage for the Latin-confusable scripts, aligned with the Unicode confusables ("MA") data — not cherry-picked.
_RAW_MAP: dict[str, str] = {
    # --- Cyrillic ---
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "d", "е": "e", "ѕ": "s", "з": "3", "и": "u", "і": "i",
    "ї": "i", "й": "u", "к": "k", "л": "n", "м": "m", "н": "h", "о": "o", "п": "n", "р": "p", "с": "c",
    "т": "t", "у": "y", "ф": "o", "х": "x", "ц": "u", "ч": "y", "ш": "w", "ъ": "b", "ы": "bi", "ь": "b",
    "э": "e", "ю": "io", "я": "r", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ѵ": "v",
    "ѡ": "w", "ѹ": "oy", "ғ": "f", "ҽ": "e",
    # --- Greek ---
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z", "η": "n", "θ": "o", "ι": "i", "κ": "k",
    "λ": "a", "μ": "u", "ν": "v", "ξ": "e", "ο": "o", "π": "n", "ρ": "p", "σ": "o", "ς": "c", "τ": "t",
    "υ": "u", "φ": "o", "χ": "x", "ψ": "w", "ω": "w", "ϲ": "c", "ϳ": "j", "ϱ": "p", "ϸ": "p",
    # --- Armenian / Cherokee / other common Latin-confusables ---
    "օ": "o", "ո": "n", "ս": "u", "ց": "g", "ք": "f", "ɡ": "g", "ɩ": "i", "ʟ": "l", "ɑ": "a", "ɛ": "e",
    "ⅰ": "i", "ⅼ": "l", "ⅽ": "c", "ⅾ": "d", "ⅿ": "m", "ⅴ": "v", "ⅹ": "x",
    # --- fullwidth digits/letters are handled by NFKC; a few stray look-alikes ---
    "ø": "o", "ł": "l", "ı": "i", "ɢ": "g", "ɴ": "n", "ʀ": "r", "ʏ": "y", "ѐ": "e",
}

# Build a str.translate table once (codepoint -> str). Multi-char targets (e.g. "bi") are allowed.
_TABLE: dict[int, str] = {ord(k): v for k, v in _RAW_MAP.items() if len(k) == 1}


def _strip_marks(text: str) -> str:
    """Drop combining marks (Mn/Mc/Me) and zero-width / format / control chars (Cf/Cc)."""
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Mn", "Mc", "Me", "Cf", "Cc"):
            continue
        out.append(ch)
    return "".join(out)


def skeleton(text: str) -> str:
    """Return the confusable skeleton of `text` for injection matching (see module docstring).

    NFKD (decompose) folds fullwidth/mathematical/compatibility forms AND separates accents into combining
    marks, which `_strip_marks` then removes (é->e); casefold lowercases; the table folds cross-script
    look-alikes (Cyrillic/Greek/...) to their ASCII prototype.
    """
    if not text:
        return text
    folded = _strip_marks(unicodedata.normalize("NFKD", text))
    return folded.casefold().translate(_TABLE)
