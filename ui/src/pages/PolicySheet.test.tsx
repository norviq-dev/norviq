// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { PolicySheet } from "./PolicyCatalog";

// A small controlled host that mirrors how PolicyCatalog owns `selected.agent_class` and threads
// the typed class back down via onAgentClassChange (the field is controlled by the parent).
function ManualComposerHost({ onApply }: { onApply: (mode: unknown, create?: { rego: string }) => void }) {
  const [policy, setPolicy] = useState<{ target_type: "class"; target: string; agent_class: string; mode: "block" }>({
    target_type: "class",
    target: "",
    agent_class: "",
    mode: "block"
    // no current_version → isNew (a brand-new manual class)
  });
  return (
    <PolicySheet
      policy={policy as never}
      deployments={[]}
      onApply={onApply}
      onClose={() => {}}
      onAgentClassChange={(cls) => setPolicy((p) => ({ ...p, agent_class: cls, target: cls }))}
    />
  );
}

const existing = {
  id: "p1",
  namespace: "default",
  agent_class: "finance-agent",
  target: "finance-agent",
  target_type: "class" as const,
  mode: "audit" as const,
  current_version: 3
};

describe("PolicySheet apply hardening", () => {
  it("Apply opens a review/diff step and only fires onApply after Confirm", () => {
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

  it("a brand-new policy shows the 'new policy' review state", () => {
    const draft = { ...existing, current_version: undefined };
    render(<PolicySheet policy={draft} deployments={[]} onApply={vi.fn()} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(screen.getByText(/no existing version to overwrite/i)).toBeInTheDocument();
  });

  it("the agent-class field is a REAL editable input with a helpful empty-state (no fake dropdown)", () => {
    const draft = { ...existing, agent_class: "", target: "", current_version: undefined };
    render(<PolicySheet policy={draft} deployments={[]} onApply={vi.fn()} onClose={() => {}} />);
    // it's an <input>, not a non-interactive select-trigger div
    const input = screen.getByTestId("composer-agent-class-input");
    expect(input.tagName).toBe("INPUT");
    // with nothing typed and no deployments, the empty-state invites manual entry (does not dead-end)
    expect(screen.getByTestId("composer-no-deployments")).toHaveTextContent(/Type an agent-class name/i);
  });

  it("typing a manual class + Confirm Apply CREATES with a generated enforcing rego for that class", () => {
    const onApply = vi.fn();
    render(<ManualComposerHost onApply={onApply} />);

    const input = screen.getByTestId("composer-agent-class-input") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "manual-only-class" } });
    expect(input.value).toBe("manual-only-class"); // controlled by the parent, reflects the typed value

    // the empty-state now confirms the manual class is authorable without a running deployment
    expect(screen.getByTestId("composer-no-deployments")).toHaveTextContent(/manual-only-class/);

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm Apply" }));

    expect(onApply).toHaveBeenCalledTimes(1);
    const [mode, create] = onApply.mock.calls[0];
    expect(mode).toBe("block");
    // a NEW class carries a generated rego for the create-then-enforce path, scoped to the typed class
    expect(create?.rego).toBeTruthy();
    expect(create.rego).toContain("package norviq.composer.manual_only_class");
    expect(create.rego).toContain('input.agent.agent_class == "manual-only-class"');
    expect(create.rego).toMatch(/decision\s*=\s*"block"\s*\{/);
  });

  it("Confirm Apply is disabled until a class name is entered", () => {
    render(<ManualComposerHost onApply={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    const confirm = screen.getByRole("button", { name: "Confirm Apply" }) as HTMLButtonElement;
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByTestId("composer-agent-class-input"), { target: { value: "svc" } });
    expect(screen.getByRole("button", { name: "Confirm Apply" })).toBeEnabled();
  });

  it("an EXISTING policy re-apply does NOT carry a generated rego (stays on the apply/stamp path)", () => {
    const onApply = vi.fn();
    render(<PolicySheet policy={existing} deployments={[]} onApply={onApply} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm Apply" }));
    expect(onApply).toHaveBeenCalledTimes(1);
    const [, create] = onApply.mock.calls[0];
    expect(create).toBeUndefined();
  });

  it("dry-run-only disables Apply with an explanatory note (Dry-Run stays)", () => {
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
