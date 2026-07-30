// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// skeleton() mirrors the server confusable-skeleton normalization to the JS-native subset documented in
// skeleton.ts's header: NFKD -> strip combining marks -> lower-case. Covers fullwidth/compat forms,
// accents, and case; does NOT cover the server's cross-script confusables table (see skeleton.ts).
import { describe, it, expect } from "vitest";
import { skeleton } from "./skeleton";

describe("skeleton", () => {
  it("lower-cases a plain ASCII tool name (identity for the already-canonical case)", () => {
    expect(skeleton("search_docs")).toBe("search_docs");
  });

  it("folds an all-uppercase name to lower-case", () => {
    expect(skeleton("SEARCH_DOCS")).toBe("search_docs");
  });

  it("strips accents via NFKD decomposition + combining-mark removal", () => {
    expect(skeleton("café_lookup")).toBe("cafe_lookup");
  });

  it("folds fullwidth characters (NFKD compatibility decomposition) to their ASCII form", () => {
    // U+FF33 U+FF25 U+FF21 U+FF32 U+FF23 U+FF28 = fullwidth "SEARCH"
    const fullwidth = "ＳＥＡＲＣＨ";
    expect(skeleton(fullwidth)).toBe("search");
  });

  it("combines fullwidth + accent + uppercase in one name and maps to the expected ASCII-lower skeleton", () => {
    // Fullwidth "GET" + accented, uppercase "RÉSUMÉ" -> "get_resume"
    const fullwidthGet = "ＧＥＴ"; // GET
    expect(skeleton(`${fullwidthGet}_RÉSUMÉ`)).toBe("get_resume");
  });

  it("does NOT fold cross-script confusables (the documented gap) — Cyrillic look-alikes stay non-Latin", () => {
    // Cyrillic "а" (U+0430) and "е" (U+0435) look like Latin a/e but are different codepoints; NFKD does
    // not unify them with Latin, so this skeleton must NOT equal the plain ASCII "search_docs".
    const cyrillicLookalike = "sеаrch_docs"; // s + Cyrillic е + Cyrillic а + rch_docs
    expect(skeleton(cyrillicLookalike)).not.toBe("search_docs");
  });

  it("returns the empty string unchanged", () => {
    expect(skeleton("")).toBe("");
  });
});
