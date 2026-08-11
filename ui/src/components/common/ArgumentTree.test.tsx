// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The component the redesign turns on: a tool's arguments, and whether policy can address each one.
 *
 * The schema under test is deliberately the SAME one `scripts/kind-e2e/seed.py` puts on the cluster for
 * `slack/send_dm`, so a unit failure here and an e2e failure there describe the same thing. It exercises
 * all four `schemaPaths()` outcomes at once.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ArgumentTree, toTreeRows } from "./ArgumentTree";
import { schemaPaths } from "../../lib/toolSchema";

/** Byte-for-byte the seeder's `SEND_DM_SCHEMA`. */
const SEND_DM = {
  type: "object",
  required: ["to"],
  properties: {
    to: { type: "string", description: "recipient email" },
    filters: { type: "object", properties: { customer: { type: "string" } } },
    retries: { type: "integer" },
    attachments: { type: "array", items: { type: "string" } }
  }
};

describe("ArgumentTree", () => {
  it("shows every argument, including the ones policy cannot address", () => {
    // Rule 1. Omitting a disabled argument teaches the operator it does not exist — the
    // capability-fragment bug in reverse.
    render(<ArgumentTree schema={SEND_DM} />);
    for (const path of ["to", "filters.customer", "retries", "attachments"]) {
      expect(screen.getByTestId(`argument-row-${path}`), `${path} must be listed`).toBeInTheDocument();
    }
  });

  it("renders the reason verbatim on each unusable argument", () => {
    // Rule 2. Without the note a disabled row is a greyed-out mystery and the product looks broken.
    render(<ArgumentTree schema={SEND_DM} />);
    expect(screen.getByTestId("argument-row-retries")).toHaveTextContent(/only text does/i);
    expect(screen.getByTestId("argument-row-attachments")).toHaveTextContent(/indexed at runtime/i);
  });

  it("marks addressable vs not, and flags required", () => {
    render(<ArgumentTree schema={SEND_DM} />);
    expect(within(screen.getByTestId("argument-row-to")).getByText("Addressable")).toBeInTheDocument();
    expect(within(screen.getByTestId("argument-row-retries")).getByText("Not addressable")).toBeInTheDocument();
    expect(screen.getByTestId("argument-row-to")).toHaveTextContent("*");
  });

  it("synthesises the branch node schemaPaths deliberately omits", () => {
    // `schemaPaths` emits leaves only — pinned by its own tests, because the compiler consumes the same
    // list and an intermediate object is not an addressable path. A tree still needs somewhere to hang
    // `filters.customer`, so the branch is derived here rather than by changing that contract.
    expect(schemaPaths(SEND_DM).map((p) => p.path)).not.toContain("filters");
    render(<ArgumentTree schema={SEND_DM} />);
    const branch = screen.getByTestId("argument-row-filters");
    expect(branch).toBeInTheDocument();
    expect(branch).toHaveAttribute("aria-level", "1");
    expect(screen.getByTestId("argument-row-filters.customer")).toHaveAttribute("aria-level", "2");
  });

  it("puts a branch immediately before its first child, so the tree reads top-down", () => {
    const rows = toTreeRows(schemaPaths(SEND_DM)).map((r) => r.path);
    expect(rows.indexOf("filters")).toBe(rows.indexOf("filters.customer") - 1);
  });

  it("keeps unusable options reachable to a screen reader, with the reason in the accessible name", () => {
    // `aria-disabled`, not `disabled` — a disabled option leaves the accessibility tree entirely, which
    // would hide the very argument the operator is looking for an alternative to.
    render(<ArgumentTree schema={SEND_DM} />);
    const retries = screen.getByTestId("argument-row-retries");
    expect(retries).toHaveAttribute("aria-disabled", "true");
    expect(retries).toHaveAttribute("aria-label", expect.stringMatching(/only text does/i));
  });

  it("picks an addressable argument, and refuses to pick a disabled one", async () => {
    const onPick = vi.fn();
    const user = userEvent.setup();
    render(<ArgumentTree schema={SEND_DM} onPick={onPick} />);

    await user.click(screen.getByTestId("argument-row-to"));
    expect(onPick).toHaveBeenCalledTimes(1);
    expect(onPick.mock.calls[0][0].path).toBe("to");

    await user.click(screen.getByTestId("argument-row-retries"));
    await user.click(screen.getByTestId("argument-row-filters"));
    expect(onPick, "neither a disabled leaf nor a branch is pickable").toHaveBeenCalledTimes(1);
  });

  it("is keyboard reachable — the picker is where the differentiator lives", async () => {
    const onPick = vi.fn();
    const user = userEvent.setup();
    render(<ArgumentTree schema={SEND_DM} onPick={onPick} />);
    screen.getByTestId("argument-row-to").focus();
    await user.keyboard("{Enter}");
    expect(onPick).toHaveBeenCalledTimes(1);
  });

  it("marks an argument already in use and stops it being added twice", async () => {
    const onPick = vi.fn();
    const user = userEvent.setup();
    render(<ArgumentTree schema={SEND_DM} onPick={onPick} used={["to"]} />);
    expect(screen.getByTestId("argument-row-to")).toHaveTextContent("already used");
    await user.click(screen.getByTestId("argument-row-to"));
    expect(onPick).not.toHaveBeenCalled();
  });

  it("renders a property description, and suppresses it when the tool's is withheld", () => {
    // The API nulls the tool-level description when the scanner condemns it, but ships input_schema
    // whole — so the property descriptions carry the same attacker-authored provenance. Honouring the
    // withholding is the renderer's job, and this is that job.
    const { rerender } = render(<ArgumentTree schema={SEND_DM} />);
    expect(screen.getByTestId("argument-row-to")).toHaveTextContent("recipient email");

    rerender(<ArgumentTree schema={SEND_DM} suppressDescriptions />);
    expect(screen.getByTestId("argument-row-to")).not.toHaveTextContent("recipient email");
    // ...but the row itself, its type and its addressability all survive — only the prose is withheld.
    expect(screen.getByTestId("argument-row-to")).toBeInTheDocument();
    expect(within(screen.getByTestId("argument-row-to")).getByText("Addressable")).toBeInTheDocument();
  });

  it("says so plainly when a tool declares no arguments", () => {
    render(<ArgumentTree schema={{ type: "object", properties: {} }} />);
    expect(screen.getByTestId("argument-tree-empty")).toBeInTheDocument();
  });

  it("survives a null or junk schema — this is server-authored text", () => {
    for (const junk of [null, undefined, 42, "nope", []]) {
      expect(() => render(<ArgumentTree schema={junk} />)).not.toThrow();
    }
  });
});
