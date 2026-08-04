// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The proposed rule card, and specifically the thing a live walkthrough caught it not saying.
 *
 * Propose-from-traffic offered `send-s-nd-email` reading "calls to send_email", derived from the
 * seeded tool whose third character is U+0435 CYRILLIC SMALL LETTER IE. The Tools page flags that
 * tool in red; this card — the one above the Save button — rendered it as an ordinary name, because
 * the two spellings are pixel-identical.
 *
 * The card is where it has to be said, not Tools: an operator who never opens Tools still saves from
 * here, and the generated allowlist matches evasion-normalised, so approving this rule grants both
 * spellings.
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RuleCard } from "./RuleCard";

/** `send_email` with U+0435 for the `e` — written as an escape, since a literal is unreadable. */
const HOMOGLYPH = "s\u0435nd_email";

describe("RuleCard", () => {
  it("states the two questions separately, and calls an empty require what it is", () => {
    render(<RuleCard rule={{ id: "send-send-email", match: { tool_name: "send_email" } }} />);
    expect(screen.getByText("Applies to")).toBeInTheDocument();
    expect(screen.getByText("calls to send_email")).toBeInTheDocument();
    // Not "nothing": an empty ALLOWED IF is a grant, and reads as a missing value otherwise.
    expect(screen.getByText(/this grants the tool outright/)).toBeInTheDocument();
  });

  it("says nothing extra about an ordinary ASCII rule — a warning that always fires is ignored", () => {
    render(<RuleCard rule={{ id: "send-send-email", match: { tool_name: "send_email" } }} />);
    expect(screen.queryByTestId(/lookalike/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Lookalike name/)).not.toBeInTheDocument();
  });

  it("flags a lookalike tool name, showing WHERE the character sits", () => {
    render(<RuleCard rule={{ id: "send-s-nd-email", match: { tool_name: HOMOGLYPH } }} />);
    expect(screen.getByText("Lookalike name")).toBeInTheDocument();
    // The mask, not just the codepoint: "U+0435" says something is wrong, "s·nd_email" says where.
    expect(screen.getByText("s·nd_email")).toBeInTheDocument();
    expect(screen.getByText(/U\+0435/)).toBeInTheDocument();
  });

  it("names the CONSEQUENCE, not just the anomaly — the allow widens to two names", () => {
    // This is the half an operator cannot derive. `allow_skeletons[input.tool_name_normalized]`
    // folds Cyrillic е to Latin e, so saving this rule permits the real ASCII tool as well.
    render(<RuleCard rule={{ id: "send-s-nd-email", match: { tool_name: HOMOGLYPH } }} />);
    expect(screen.getByText(/grants the look-alike/)).toBeInTheDocument();
    expect(screen.getByText(/plain-ASCII tool of the same shape/)).toBeInTheDocument();
  });

  it("attaches the flag to the clause it is about, not to the rule as a whole", () => {
    // A rule can name several tools; a card-level badge cannot say which one is the spoof.
    render(
      <RuleCard rule={{ id: "r", server: "slack", match: { tool_name: HOMOGLYPH } }} />
    );
    const note = screen.getByTestId("rule-r-applies-lookalike");
    expect(note).toHaveTextContent("s·nd_email");
    // The clean `mcp.server == slack` clause in the same band carries no note of its own.
    expect(screen.getAllByTestId(/lookalike/)).toHaveLength(1);
  });

  it("keeps the raw predicate available, verbatim, spoofed character included", () => {
    render(<RuleCard rule={{ id: "r", match: { tool_name: HOMOGLYPH } }} />);
    fireEvent.click(screen.getByTestId("rule-r-raw-toggle"));
    // Never a normalised spelling: `Show raw` is the string an operator greps the engine for.
    expect(screen.getByTestId("rule-r-raw")).toHaveTextContent(`tool_name == ${HOMOGLYPH}`);
  });
});
