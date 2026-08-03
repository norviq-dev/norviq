// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The P1 fix. Its whole reason for existing is that a first-time operator must discover argument
 * scoping WITHOUT being told it exists — so these tests are mostly about what is impossible to miss,
 * not about what is technically present.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ScopeCell } from "./ScopeCell";
import type { BuilderGrantFact, BuilderParamConstraint } from "../../lib/builderGraph";

const ARGS = ["to", "filters.customer"];

function setup(over: Partial<React.ComponentProps<typeof ScopeCell>> = {}) {
  const onToggle = vi.fn();
  render(
    <ScopeCell
      tool="send_dm"
      constraints={[]}
      facts={[]}
      addressableArgs={ARGS}
      totalArgs={4}
      schemaAvailable
      expanded={false}
      onToggle={onToggle}
      {...over}
    />
  );
  return { onToggle };
}

const MATCHES: BuilderParamConstraint = { kind: "matches", field: "to", pattern: "^[^@]+@acme\\.com$" };
const NONE_OF: BuilderGrantFact = { type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] };

describe("ScopeCell", () => {
  it("fills all four slots when nothing is scoped — the state that used to render as a bare chip", () => {
    // An empty cell is what made the old chip readable as "done". Unscoped is not a neutral default;
    // it is the widest grant this policy can make.
    setup();
    expect(screen.getByTestId("scope-cell-send_dm-headline")).toHaveTextContent("Any arguments · unrestricted");
    expect(screen.getByTestId("scope-cell-send_dm-detail")).toHaveTextContent(/2 of its 4 arguments can be narrowed/);
    expect(screen.getByTestId("scope-cell-send_dm-detail")).toHaveTextContent("to");
    expect(screen.getByTestId("scope-cell-send_dm-impact")).toHaveTextContent(
      "Allows every call to send_dm, with any arguments."
    );
    expect(screen.getByTestId("scope-cell-send_dm-cta")).toHaveTextContent("Narrow it");
  });

  it("makes the unscoped CTA the loudest control on the row", () => {
    // The differentiator was previously a 10.5px grey text link. A filled primary is the difference
    // between an operator discovering scoping and finishing the flow without knowing it exists.
    setup();
    expect(screen.getByTestId("scope-cell-send_dm-cta").className).toContain("btn-primary");
  });

  it("recedes to a quiet Edit once the grant has actually been narrowed", () => {
    setup({ constraints: [MATCHES] });
    const cta = screen.getByTestId("scope-cell-send_dm-cta");
    expect(cta).toHaveTextContent("Edit");
    expect(cta.className).toContain("btn-outline");
    expect(cta.className).not.toContain("btn-primary");
  });

  it("says Collapse while the editor is open", () => {
    setup({ constraints: [MATCHES], expanded: true });
    expect(screen.getByTestId("scope-cell-send_dm-cta")).toHaveTextContent("Collapse");
    expect(screen.getByTestId("scope-cell-send_dm-cta")).toHaveAttribute("aria-expanded", "true");
  });

  it("counts constraints AND facts as conditions — they are one idea to an operator", () => {
    // Counting only one store is the defect that has recurred throughout this work: a tool scoped
    // purely by facts previously rendered as unscoped on the very affordance meant to advertise it.
    setup({ constraints: [MATCHES], facts: [NONE_OF] });
    expect(screen.getByTestId("scope-cell-send_dm-headline")).toHaveTextContent("Narrowed · 2 conditions");
    expect(screen.getAllByTestId("scope-cell-send_dm-condition")).toHaveLength(2);
  });

  it("describes each condition in the SAME words the generated rego's header uses", () => {
    // Two renderings of one clause drift, and an operator comparing the rego with the row that
    // produced it cannot then tell whether they are the same restriction.
    setup({ constraints: [MATCHES], facts: [NONE_OF] });
    const chips = screen.getAllByTestId("scope-cell-send_dm-condition").map((c) => c.textContent);
    expect(chips).toContain("to matches /^[^@]+@acme\\.com$/");
    expect(chips).toContain("data_classes excludes {secret}");
  });

  it("states the impact as a policy fact, which is always knowable", () => {
    // `DryRunReplay` carries no per-tool totals, so a call count here would be a lower bound printed
    // as a total. What the grant PERMITS needs no endpoint and is exactly true.
    setup({ constraints: [MATCHES] });
    expect(screen.getByTestId("scope-cell-send_dm-impact")).toHaveTextContent(
      "Allows a call only when its one condition holds."
    );
  });

  it("marks a truncated dry-run sample as a lower bound rather than a total", () => {
    setup({ constraints: [MATCHES], newlyDenied: 4, sampled: true });
    expect(screen.getByTestId("scope-cell-send_dm-impact")).toHaveTextContent("at least 4 replayed calls would now be denied");
  });

  it("says nothing about traffic when no dry run has been done", () => {
    setup({ constraints: [MATCHES] });
    expect(screen.getByTestId("scope-cell-send_dm-impact")).not.toHaveTextContent(/replayed/);
  });

  it("offers the one route that still works when the definition carries no schema", () => {
    // Declared, pinned, and unscopeable — the state the 8 KiB canonical slice creates. Saying
    // "0 arguments" would be false; the arguments exist, we just cannot enumerate them.
    setup({ schemaAvailable: false, addressableArgs: [], totalArgs: 0 });
    expect(screen.getByTestId("scope-cell-send_dm-detail")).toHaveTextContent(
      /No schema — add whole-call conditions, or type a path you know./
    );
    // Still narrowable: whole-call conditions do not need a schema.
    expect(screen.getByTestId("scope-cell-send_dm-cta")).toHaveTextContent("Narrow it");
  });

  it("does not claim an argument can be narrowed when none can be addressed", () => {
    setup({ addressableArgs: [], totalArgs: 3 });
    expect(screen.getByTestId("scope-cell-send_dm-detail")).toHaveTextContent(
      /None of its 3 arguments can be addressed/
    );
  });

  it("hands the click back so the row owns the editor", async () => {
    const { onToggle } = setup();
    await userEvent.click(screen.getByTestId("scope-cell-send_dm-cta"));
    expect(onToggle).toHaveBeenCalledOnce();
  });
});
