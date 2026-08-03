// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Provenance, scopeability, and the reason a control is unavailable.
 *
 * These three are small, but each is the antidote to a specific bug that shipped:
 *  - the builder unioned observed names with capability SUBSTRINGS and treated the union as proof a
 *    tool existed, so it suggested impossible names and suppressed its own warning for them;
 *  - "declared" was conflated with "scopeable", though a pinned tool can lose its schema to an 8 KiB cap;
 *  - disabled buttons carried `title` explanations that `pointer-events: none` made unreachable.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ProvenanceBadge } from "./ProvenanceBadge";
import { ScopeabilityBadge } from "./ScopeabilityBadge";
import { InlineDisabledReason } from "./InlineDisabledReason";

describe("ProvenanceBadge", () => {
  it("distinguishes declared from observed — the distinction the registry exists to preserve", () => {
    const { rerender } = render(<ProvenanceBadge source="mcp_declared" />);
    expect(screen.getByTestId("provenance-mcp_declared")).toHaveTextContent("Declared");
    rerender(<ProvenanceBadge source="observed" />);
    expect(screen.getByTestId("provenance-observed")).toHaveTextContent("Observed");
  });

  it("reads a missing source as Unknown", () => {
    render(<ProvenanceBadge source={null} />);
    expect(screen.getByTestId("provenance-unknown")).toHaveTextContent("Unknown");
  });

  it("renders NOTHING when the registry is unavailable — silence is not an all-clear", () => {
    // The tempting fallback is `Unknown`, and it would be a lie: "we could not check" is not "we
    // checked and found nothing". Callers pair the absent badge with a band saying names are not being
    // checked; a badge here would be a claim the UI has no basis for.
    const { container } = render(<ProvenanceBadge source="mcp_declared" registryNull />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lets registryNull win over every other prop", () => {
    const { container } = render(<ProvenanceBadge source={null} registryNull />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ScopeabilityBadge", () => {
  it("separates 'declared' from 'scopeable' — a pinned tool can still have no schema", () => {
    const { rerender } = render(<ScopeabilityBadge source="mcp_declared" schemaAvailable />);
    expect(screen.getByTestId("scopeability-scopeable")).toHaveTextContent("Scopeable");

    // Same tier, same pin, no schema: the 8 KiB canonical slice put `description` before `inputSchema`
    // alphabetically and evicted it. Real and frequent, not exotic.
    rerender(<ScopeabilityBadge source="mcp_declared" schemaAvailable={false} />);
    expect(screen.getByTestId("scopeability-no-schema")).toHaveTextContent("No schema");
  });

  it("calls an observed tool name-only regardless of the schema flag", () => {
    render(<ScopeabilityBadge source="observed" schemaAvailable={false} />);
    expect(screen.getByTestId("scopeability-name-only")).toHaveTextContent("Name only");
  });

  it("explains itself on hover for the two states an operator will question", () => {
    const { rerender } = render(<ScopeabilityBadge source="mcp_declared" schemaAvailable={false} />);
    expect(screen.getByTestId("scopeability-no-schema")).toHaveAttribute("title", expect.stringMatching(/8 KiB slice/));
    rerender(<ScopeabilityBadge source="observed" schemaAvailable={false} />);
    expect(screen.getByTestId("scopeability-name-only")).toHaveAttribute("title", expect.stringMatching(/whole-call facts/i));
  });
});

describe("InlineDisabledReason", () => {
  it("renders the reason as TEXT, because a disabled button can never show a title", () => {
    // `.btn:disabled { pointer-events: none }` means hover never lands, so a `title` on a disabled
    // control is written, shipped and unreachable. Three surfaces relied on exactly that.
    render(
      <InlineDisabledReason reason="Run a dry-run first — save is blocked until it passes." data-testid="save">
        <button disabled>Save &amp; enforce</button>
      </InlineDisabledReason>
    );
    expect(screen.getByTestId("save-reason")).toHaveTextContent(/Run a dry-run first/);
    expect(screen.getByTestId("save-reason")).toHaveAttribute("role", "status");
  });

  it("renders the control bare when there is nothing to explain", () => {
    render(
      <InlineDisabledReason data-testid="save">
        <button>Save &amp; enforce</button>
      </InlineDisabledReason>
    );
    expect(screen.queryByTestId("save-reason")).not.toBeInTheDocument();
  });

  it("tones a self-clearable blocker differently from a refusal", () => {
    // Two greyed buttons that mean different things must not look identical: "run a dry-run" is
    // actionable by this operator, "this would weaken the policy" is not.
    const { rerender } = render(
      <InlineDisabledReason reason="Dry-run first" tone="escalate" data-testid="a"><button disabled /></InlineDisabledReason>
    );
    const escalate = screen.getByTestId("a-reason").getAttribute("style");
    rerender(
      <InlineDisabledReason reason="Refuses — 2 reasons below" tone="block" data-testid="a"><button disabled /></InlineDisabledReason>
    );
    expect(screen.getByTestId("a-reason").getAttribute("style")).not.toBe(escalate);
  });
});
