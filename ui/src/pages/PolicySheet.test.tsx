// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { PolicySheet } from "./PolicyCatalog";

const existing = {
  id: "p1",
  namespace: "default",
  agent_class: "finance-agent",
  target: "finance-agent",
  target_type: "class" as const,
  mode: "audit" as const,
  current_version: 3
};

describe("PolicySheet apply hardening (F-50 / F-51)", () => {
  it("F-50: Apply opens a review/diff step and only fires onApply after Confirm", () => {
    const onApply = vi.fn();
    render(<PolicySheet policy={existing} deployments={[]} onApply={onApply} onClose={() => {}} />);

    // change enforcement audit -> block, then Apply shows the review (no write yet)
    fireEvent.click(screen.getByText("block"));
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(screen.getByTestId("apply-review")).toBeInTheDocument();
    expect(screen.getByText("Review changes before applying")).toBeInTheDocument();
    expect(onApply).not.toHaveBeenCalled(); // still no write

    // Back cancels without a request
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.queryByTestId("apply-review")).not.toBeInTheDocument();
    expect(onApply).not.toHaveBeenCalled();

    // Apply -> Confirm Apply fires the write
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm Apply" }));
    expect(onApply).toHaveBeenCalledTimes(1);
  });

  it("F-50: a brand-new policy shows the 'new policy' review state", () => {
    const draft = { ...existing, current_version: undefined };
    render(<PolicySheet policy={draft} deployments={[]} onApply={vi.fn()} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(screen.getByText(/no existing version to overwrite/i)).toBeInTheDocument();
  });

  it("F-51: dry-run-only disables Apply with an explanatory note (Dry-Run stays)", () => {
    const onApply = vi.fn();
    render(
      <PolicySheet policy={existing} deployments={[]} applyMode="dry_run_only" onApply={onApply} onClose={() => {}} />
    );
    expect(screen.getByText(/dry-run-only/i)).toBeInTheDocument();
    const apply = screen.getByRole("button", { name: "Apply" }) as HTMLButtonElement;
    expect(apply).toBeDisabled();
    expect(screen.getByRole("button", { name: "Dry-Run" })).toBeEnabled();
    fireEvent.click(apply);
    expect(onApply).not.toHaveBeenCalled();
  });
});
