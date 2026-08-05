// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The dialog primitive under both MCP dialogs and every type-to-confirm.
 *
 * These tests pin the things that are security-relevant rather than cosmetic: opening a dialog must
 * not arm a destructive control under the operator's next keypress, `aria-modal="true"` must be true
 * of the tab order, and one Escape must dismiss ONE dialog — the top one — not the stack.
 */

import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Modal } from "./Modal";

describe("Modal", () => {
  it("does not open with the keyboard on a destructive control", async () => {
    // The MCP tool dialog's shape: an approved, non-drifted pin renders no diff toggle and no
    // Approve, so the FIRST button in the card is "Revoke". `querySelector("input, textarea, button")`
    // returns the first node in DOCUMENT ORDER matching ANY branch, so focus landed there and one
    // Space — the natural key for scrolling a dialog that is `max-height: calc(100vh - 48px);
    // overflow-y: auto` — withheld the tool from the model with no confirmation.
    const onRevoke = vi.fn();
    render(
      <Modal title="filesystem / read_file" onClose={() => {}} data-testid="m">
        <p>A definition, several screens of it.</p>
        <button type="button" className="btn btn-destructive" onClick={onRevoke} data-testid="revoke">
          Revoke
        </button>
      </Modal>
    );
    expect(screen.getByTestId("revoke")).not.toHaveFocus();
    // Focus is INSIDE the dialog — moving it in is the part that was right — on the card itself, which
    // announces the dialog to a screen reader and leaves Space as a scroll key.
    expect(screen.getByTestId("m")).toHaveFocus();
    await userEvent.keyboard("[Space]");
    await userEvent.keyboard("{Enter}");
    expect(onRevoke).not.toHaveBeenCalled();
  });

  it("does not open on a checkbox either — Space toggles one", async () => {
    // The same defect one attribute later. `input:not([disabled]):not([type='hidden'])` matches a
    // CHECKBOX, and a focused checkbox is toggled by Space — the key an operator presses to scroll a
    // dialog that is `max-height: calc(100vh - 48px); overflow-y: auto`. "Prefer a text entry,
    // otherwise the card, never a control" has to be true of every input type, not of `type="text"`.
    const onChange = vi.fn();
    render(
      <Modal title="Revoke read_file?" onClose={() => {}} data-testid="m">
        <label>
          <input type="checkbox" data-testid="cb" onChange={onChange} />
          also revoke this tool in every other namespace
        </label>
        <p>Several screens of definition.</p>
      </Modal>
    );
    expect(screen.getByTestId("cb")).not.toHaveFocus();
    expect(screen.getByTestId("m")).toHaveFocus();
    await userEvent.keyboard("[Space]");
    expect((screen.getByTestId("cb") as HTMLInputElement).checked).toBe(false);
    expect(onChange).not.toHaveBeenCalled();
  });

  it("focuses a text entry first, even when a button precedes it", async () => {
    // What the code always CLAIMED ("preferring the first input so a type-to-confirm dialog is
    // immediately usable") and did not do.
    render(
      <Modal title="Forget filesystem?" onClose={() => {}}>
        <button type="button" data-testid="earlier">
          View rego
        </button>
        <input data-testid="confirm-input" />
      </Modal>
    );
    expect(screen.getByTestId("confirm-input")).toHaveFocus();
  });

  it("keeps Tab inside the dialog — aria-modal is a promise about the tab order", async () => {
    render(
      <>
        <button type="button" data-testid="behind">
          Forget filesystem…
        </button>
        <Modal title="filesystem / read_file" onClose={() => {}} data-testid="m">
          <button type="button" data-testid="a">
            first
          </button>
          <button type="button" data-testid="b">
            last
          </button>
        </Modal>
      </>
    );
    const user = userEvent.setup();
    // Shift+Tab as the FIRST keypress, from the card focus lands on when the dialog opens. This is the
    // hop an operator actually makes ("move back within this dialog"), and `contains()` being true of
    // the card itself let it walk out to the page behind the backdrop.
    await user.tab({ shift: true });
    expect(screen.getByTestId("behind")).not.toHaveFocus();
    expect(screen.getByTestId("m").contains(document.activeElement)).toBe(true);
    expect(screen.getByTestId("b")).toHaveFocus(); // wrapped to the last control, not out of the dialog
    await user.tab();
    expect(screen.getByTestId("a")).toHaveFocus();
    await user.tab({ shift: true }); // back off the first control…
    expect(screen.getByTestId("behind")).not.toHaveFocus();
    expect(screen.getByTestId("m").contains(document.activeElement)).toBe(true);
    await user.tab();
    await user.tab();
    await user.tab(); // …and forward off the last one
    expect(screen.getByTestId("behind")).not.toHaveFocus();
    expect(screen.getByTestId("m").contains(document.activeElement)).toBe(true);
  });

  it("closes only the topmost dialog on Escape", async () => {
    // Every Modal registers its own document-level keydown, so one Escape reached them all: backing
    // out of a stacked confirm silently took the definition being reviewed underneath it with it.
    const closeOuter = vi.fn();
    const closeInner = vi.fn();
    render(
      <>
        <Modal title="outer" onClose={closeOuter} data-testid="outer">
          <p>being read</p>
        </Modal>
        <Modal title="inner" onClose={closeInner} data-testid="inner">
          <p>confirm</p>
        </Modal>
      </>
    );
    await userEvent.keyboard("{Escape}");
    expect(closeInner).toHaveBeenCalledTimes(1);
    expect(closeOuter).not.toHaveBeenCalled();
  });

  it("closes the dialog the operator can SEE when one is nested inside the other", async () => {
    // Both backdrops are `z-index: 60` (index.css), so the dialog on top is the one later in document
    // order — and a dialog nested in another's children is later. Mount order is not that: React runs
    // a CHILD's effect before its parent's, so a mount-ordered stack made the covered dialog claim to
    // be topmost. Escape then closed the one the operator could not see and left the one they were
    // answering on screen — a definition under review silently dismissed behind the confirm for it.
    const closeOuter = vi.fn();
    const closeInner = vi.fn();
    render(
      <Modal title="filesystem / read_file" onClose={closeOuter} data-testid="outer">
        <p>being read</p>
        <Modal title="Forget filesystem?" onClose={closeInner} data-testid="inner">
          <p>confirm</p>
        </Modal>
      </Modal>
    );
    await userEvent.keyboard("{Escape}");
    expect(closeInner).toHaveBeenCalledTimes(1);
    expect(closeOuter).not.toHaveBeenCalled();
  });

  it("closes the one underneath once the top one is gone", async () => {
    // The stack must unwind, not deadlock: after the top dialog unmounts the next Escape belongs to
    // the dialog now on top.
    const closeOuter = vi.fn();
    function Stack() {
      const [inner, setInner] = useState(true);
      return (
        <>
          <Modal title="outer" onClose={closeOuter} data-testid="outer">
            <p>being read</p>
          </Modal>
          {inner && (
            <Modal title="inner" onClose={() => setInner(false)} data-testid="inner">
              <p>confirm</p>
            </Modal>
          )}
        </>
      );
    }
    render(<Stack />);
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByTestId("inner")).not.toBeInTheDocument();
    expect(closeOuter).not.toHaveBeenCalled();
    await userEvent.keyboard("{Escape}");
    expect(closeOuter).toHaveBeenCalledTimes(1);
  });

  it("still dismisses from the keyboard and the backdrop, and not from the card", async () => {
    const onClose = vi.fn();
    const { container } = render(
      <Modal title="t" onClose={onClose} data-testid="m">
        <p data-testid="body">body</p>
      </Modal>
    );
    const user = userEvent.setup();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(screen.getByTestId("body"));
    expect(onClose).toHaveBeenCalledTimes(1);
    await user.click(container.querySelector(".modal-backdrop") as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("hands focus back to whatever opened it", async () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" data-testid="opener" onClick={() => setOpen(true)}>
            open
          </button>
          {open && (
            <Modal title="t" onClose={() => setOpen(false)} data-testid="m">
              <p>body</p>
            </Modal>
          )}
        </>
      );
    }
    render(<Host />);
    const user = userEvent.setup();
    await user.click(screen.getByTestId("opener"));
    expect(screen.getByTestId("m")).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.getByTestId("opener")).toHaveFocus();
  });
});
