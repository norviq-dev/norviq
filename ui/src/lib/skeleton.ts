// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Client-side (JS-native) mirror of the server's confusable "skeleton" normalization
// (`norviq/engine/confusables.py` `skeleton()`), used by the Intent Allowlist compiler (builderCompile.ts)
// so the allowlist's evasion-normalized match (`allow_skeletons[input.tool_name_normalized]`) is computed
// from the SAME kind of string transform the evaluator applies server-side to produce
// `input.tool_name_normalized` — this file does not need to reproduce the evaluator's own runtime
// computation, only to let the BUILDER preview what a tool name's normalized form looks like.
//
// COVERAGE (what this mirrors): the server's `skeleton()` is `NFKD-normalize -> strip combining marks
// (accents) -> casefold -> translate cross-script confusable letters to their ASCII prototype`. This
// client mirror implements the FIRST THREE steps only, via the JS-native subset the task brief specifies:
//   s.normalize("NFKD").replace(/\p{M}+/gu, "").toLowerCase()
// - `normalize("NFKD")` folds fullwidth/mathematical-alphanumeric/other compatibility forms and
//   decomposes accented letters into base + combining mark (e.g. "é" -> "e" + U+0301).
// - `replace(/\p{M}+/gu, "")` strips those combining marks (Unicode category M = Mn+Mc+Me), so the
//   decomposed accent is dropped, leaving the bare ASCII base letter (e.g. "café" -> "cafe").
// - `.toLowerCase()` folds case. (JS has no native `casefold()`; `toLowerCase()` is the practical
//   subset for the ASCII/Latin-adjacent tool names this feeds — not a full Unicode casefold.)
//
// THE ONE DELIBERATE GAP (not mirrored here): the server's cross-script CONFUSABLES TRANSLATE TABLE —
// the vendored Unicode-TR39-aligned map that folds Cyrillic/Greek/Armenian/etc look-alike letters to
// their ASCII prototype (e.g. Cyrillic "а" U+0430 -> Latin "a"). NFKD does NOT fold this (Cyrillic "а" is
// not NFKD-equivalent to Latin "a" — they are genuinely different codepoints in different scripts), so a
// homoglyph-substituted tool name (e.g. Cyrillic "sеаrch_docs" using Cyrillic е/а) will NOT collapse to
// the same skeleton as the ASCII "search_docs" under this client-side function, even though the server's
// `skeleton()` (and therefore the live `input.tool_name_normalized`) WOULD fold them together. Porting
// that ~80-entry translate table into the browser bundle is a real but bounded productization dependency
// (it's static data, not logic — norviq/engine/confusables.py `_RAW_MAP`), out of scope for this spike.
// Practically: `allow_names` (the plain lower-cased exact match) is this allowlist's PRIMARY defense —
// it needs no confusable folding at all, since it matches the literal (lower-cased) tool name;
// `allow_skeletons` is defense-in-depth against fullwidth/accent/case evasion specifically, not a
// complete mirror of the server's cross-script homoglyph defense.
export function skeleton(text: string): string {
  if (!text) return text;
  return text.normalize("NFKD").replace(/\p{M}+/gu, "").toLowerCase();
}
