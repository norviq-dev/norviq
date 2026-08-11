// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * A name in a predicate is not the name it looks like.
 *
 * Found on a live walkthrough: Propose-from-traffic offered a rule reading `calls to send_email`,
 * derived from the observed tool `sеnd_email` whose third character is U+0435 CYRILLIC SMALL LETTER
 * IE. The Tools page flags that tool in red; this page — the one with the Save button — said
 * nothing, and the two names are pixel-identical in the console's font.
 *
 * The consequence is the part that needs stating, not the badge. The generated allowlist matches
 * evasion-normalized (`allow_skeletons[input.tool_name_normalized]`, `norviq/api/threat_intent.py`),
 * and `skeleton()` folds Cyrillic е to Latin e — so saving this rule grants the lookalike AND the
 * real ASCII tool. That is deliberate and right (a homoglyph must not dodge a DENY), but an operator
 * approving a rule is entitled to know their allow just widened to two names.
 *
 * `masked` carries the position rather than the character: printing the codepoint alone tells you
 * something is wrong, printing `s·nd_email` tells you where.
 */

import type { Lookalike } from "../../lib/predicateSentence";

export function LookalikeNote({ lookalikes, "data-testid": testId }: { lookalikes: Lookalike[]; "data-testid"?: string }) {
  if (lookalikes.length === 0) return null;
  return (
    <div
      data-testid={testId ?? "lookalike-note"}
      style={{
        marginTop: 5,
        padding: "7px 9px",
        borderRadius: 8,
        border: "1px solid #ff3b5c30",
        background: "#ff3b5c12",
        fontSize: 12,
        lineHeight: 1.5,
        color: "var(--text-secondary)"
      }}
    >
      <span
        className="pill"
        style={{ background: "#ff3b5c15", color: "#ff3b5c", borderColor: "#ff3b5c30", marginRight: 7 }}
      >
        Lookalike name
      </span>
      {lookalikes.map((l) => (
        <span key={l.value} style={{ display: "block", marginTop: 5 }}>
          <code className="mono" style={{ fontSize: 12 }}>
            {l.masked}
          </code>{" "}
          carries {l.codepoints.join(", ")} where an ASCII letter appears to be.
        </span>
      ))}
      <span style={{ display: "block", marginTop: 5 }}>
        The engine matches this allowlist evasion-normalised, so the rule grants the look-alike{" "}
        <strong>and</strong> the plain-ASCII tool of the same shape. Confirm you meant both before saving.
      </span>
    </div>
  );
}
