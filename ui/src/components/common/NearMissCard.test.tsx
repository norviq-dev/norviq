// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The near miss. Its one non-negotiable property is that the headline and the list agree — "met 3 of
 * 4" beside two clauses is worse than no list at all, because the operator concludes the screen is
 * wrong and stops trusting the rest of it.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { NearMissCard } from "./NearMissCard";

// Exactly what `norviq/engine/intent/dryrun.py` publishes: every clause the closest rule asserts,
// including the two the COMPILER adds rather than the operator.
const DECOMPOSED = {
  index: 5,
  tool_name: "send_email",
  reason:
    "no intent rule matched; closest send-send-email met 3/4, failed: param_paths.to matches ^[^@]+@acme\\.com$",
  closest_rule: "send-send-email",
  met: 3,
  predicates: [
    "direction == call",
    "tool_name == send_email",
    "data_classes is published by this engine",
    "param_paths.to matches ^[^@]+@acme\\.com$"
  ],
  failed: ["param_paths.to matches ^[^@]+@acme\\.com$"]
};

describe("NearMissCard", () => {
  it("renders one clause per predicate, so the headline reconciles", () => {
    render(<NearMissCard call={DECOMPOSED} occurrences={4} />);
    expect(screen.getByTestId("near-miss-summary")).toHaveTextContent("met 3 of 4");
    expect(screen.getAllByTestId("clause-met")).toHaveLength(3);
    expect(screen.getAllByTestId("clause-failed")).toHaveLength(1);
    // 3 + 1 = 4. The arithmetic the heading claims, asserted rather than assumed.
    expect(screen.getAllByTestId(/^clause-/)).toHaveLength(4);
  });

  it("renders the compiler's own clauses and marks them implicit", () => {
    // These are the two that made "met 3 of 4" fail to add up against a list of two. Hiding them
    // does not make them stop applying — it just makes the count wrong.
    render(<NearMissCard call={DECOMPOSED} />);
    expect(screen.getByText(/this engine publishes data_classes/i)).toBeInTheDocument();
    expect(screen.getAllByText(/implicit, applied to every rule/i).length).toBeGreaterThan(0);
  });

  it("puts the failing clause first — it is the one the operator came to act on", () => {
    render(<NearMissCard call={DECOMPOSED} />);
    const clauses = screen.getAllByTestId(/^clause-/);
    expect(clauses[0]).toHaveAttribute("data-testid", "clause-failed");
  });

  it("shows the engine's own words on the failing clause, for searching the rule", () => {
    render(<NearMissCard call={DECOMPOSED} />);
    const failed = screen.getByTestId("clause-failed");
    expect(failed).toHaveTextContent(/the to is an address at acme\.com/i);
    expect(failed).toHaveTextContent("param_paths.to matches");
  });

  it("falls back to the raw sentence when the API could not decompose the reason", () => {
    // Degraded, never self-contradictory: a partial tick-list would show clauses as PASSED that were
    // never evaluated, which is a restriction the operator would believe is in force.
    render(<NearMissCard call={{ index: 1, tool_name: "x", reason: "no intent rule matched this call" }} />);
    expect(screen.queryByTestId("near-miss-summary")).toBeNull();
    expect(screen.queryAllByTestId(/^clause-/)).toHaveLength(0);
    expect(screen.getByText("no intent rule matched this call")).toBeInTheDocument();
  });

  it("does not claim a call count it was not given", () => {
    // Scoped to the exact "<n> calls" shape: the clause "calls to send_email" legitimately contains
    // the word, and a looser matcher would pass or fail for reasons unrelated to the count.
    const { rerender } = render(<NearMissCard call={DECOMPOSED} />);
    expect(screen.queryByText(/^\d+ calls$/)).toBeNull();
    rerender(<NearMissCard call={DECOMPOSED} occurrences={4} />);
    expect(screen.getByText("4 calls")).toBeInTheDocument();
    // A single occurrence is not worth a count — "1 calls" is noise and grammatically wrong.
    rerender(<NearMissCard call={DECOMPOSED} occurrences={1} />);
    expect(screen.queryByText(/^\d+ calls$/)).toBeNull();
  });
});
