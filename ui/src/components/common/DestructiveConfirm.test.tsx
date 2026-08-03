// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DestructiveConfirm } from "./DestructiveConfirm";

function setup(over: Partial<React.ComponentProps<typeof DestructiveConfirm>> = {}) {
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <DestructiveConfirm
      title="Forget slack?"
      confirmWord="slack"
      confirmLabel="Forget server"
      onConfirm={onConfirm}
      onCancel={onCancel}
      consequence="the drifted definition would be auto-approved on sight."
      {...over}
    >
      Deletes 3 pins.
    </DestructiveConfirm>
  );
  return { onConfirm, onCancel };
}

describe("DestructiveConfirm", () => {
  it("keeps the action unreachable until the exact word is typed", async () => {
    // The prototype's version was decorative — an input beside an always-live button. A ceremony
    // that never blocks anything teaches operators to click through it.
    const { onConfirm } = setup();
    const submit = screen.getByTestId("destructive-confirm-submit");
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByTestId("destructive-confirm-input"), "sla");
    expect(submit).toBeDisabled();
    await userEvent.type(screen.getByTestId("destructive-confirm-input"), "ck");
    expect(submit).toBeEnabled();
    await userEvent.click(submit);
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("says which of the two blockers is in the way", async () => {
    // "not an admin" and "have not typed it yet" are otherwise the same grey button, and they call
    // for opposite next actions — ask someone else, versus finish typing.
    setup({ allowed: false });
    expect(screen.getByTestId("destructive-confirm-gate-reason")).toHaveTextContent(/Needs admin/i);
    await userEvent.type(screen.getByTestId("destructive-confirm-input"), "slack");
    // Typing does not unlock it for a viewer — the server would refuse anyway.
    expect(screen.getByTestId("destructive-confirm-submit")).toBeDisabled();
    expect(screen.getByTestId("destructive-confirm-gate-reason")).toHaveTextContent(/Needs admin/i);
  });

  it("states the consequence, not just the deletion", () => {
    // The count of deleted rows is not the risk. Re-pinning under `tofu` is.
    setup();
    expect(screen.getByTestId("destructive-confirm-consequence")).toHaveTextContent(/auto-approved on sight/i);
  });

  it("is dismissable from the keyboard", async () => {
    const { onCancel } = setup();
    await userEvent.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it("does not close when the card itself is clicked", async () => {
    // A backdrop handler that does not compare target to currentTarget dismisses on every inner
    // click, so typing the confirm word becomes impossible.
    const { onCancel } = setup();
    await userEvent.click(screen.getByTestId("destructive-confirm-input"));
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("is announced as a modal dialog", () => {
    setup();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleName(/Forget slack/i);
  });
});
