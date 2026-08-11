// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Roving tabindex: the focus ring and the checked segment must be the SAME segment.
 *
 * The original assertions (written alongside two sibling primitives that never shipped, and removed
 * with them) passed a `vi.fn()` for `onChange`, so `value` never changed and the group never
 * re-rendered — which is exactly why they could not see this. A segmented control is a controlled
 * component; everything about its keyboard behaviour only becomes observable with a wrapper that
 * actually holds the state, so that is what these use.
 *
 * Why it matters more than a stray focus ring: this is the Tools page's observed-window picker. A
 * keyboard operator who arrows to a window and presses Space to confirm was silently put back on the
 * window they arrowed away FROM, and then read the counts under the wrong window.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { SegmentedControl } from "./SegmentedControl";

const OPTS = [
  { value: "block", label: "Block", hex: "#ff3b5c" },
  { value: "escalate", label: "Escalate", hex: "#ffb020" },
  { value: "audit", label: "Audit", hex: "#7c5cfc" }
];

/** Controlled wrapper — without one, `value` never moves and the defect is invisible. */
function Harness({ initial = "block", onPick }: { initial?: string; onPick?: (v: string) => void }) {
  const [value, setValue] = useState(initial);
  return (
    <>
      <SegmentedControl
        options={OPTS}
        value={value}
        onChange={(v) => {
          onPick?.(v);
          setValue(v);
        }}
        ariaLabel="decision"
        data-testid="dec"
      />
      <output data-testid="chosen">{value}</output>
    </>
  );
}

const checked = () =>
  screen
    .getAllByRole("radio")
    .filter((b) => b.getAttribute("aria-checked") === "true")
    .map((b) => b.textContent);

describe("SegmentedControl — focus follows the selection", () => {
  it("moves the focus ring onto the segment the arrow key just selected", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    screen.getByTestId("dec-block").focus();

    await user.keyboard("{ArrowRight}");
    expect(checked()).toEqual(["Escalate"]);
    expect(document.activeElement).toBe(screen.getByTestId("dec-escalate"));
    // The focused element must be the group's single tab stop; the one left behind must not be.
    expect(screen.getByTestId("dec-escalate")).toHaveAttribute("tabindex", "0");
    expect(screen.getByTestId("dec-block")).toHaveAttribute("tabindex", "-1");
  });

  it("does not revert the choice when Space or Enter is pressed to confirm it", async () => {
    // The whole defect: focus stayed on the OLD segment, so the confirming keystroke fired that
    // segment's click handler and put the selection back — with nothing on screen to say so.
    const user = userEvent.setup();
    const onPick = vi.fn();
    render(<Harness onPick={onPick} />);
    screen.getByTestId("dec-block").focus();

    await user.keyboard("{ArrowRight}");
    await user.keyboard("[Space]");
    expect(screen.getByTestId("chosen")).toHaveTextContent("escalate");
    expect(checked()).toEqual(["Escalate"]);

    await user.keyboard("{ArrowRight}");
    await user.keyboard("{Enter}");
    expect(screen.getByTestId("chosen")).toHaveTextContent("audit");
    expect(checked()).toEqual(["Audit"]);
    // Never reported a value the operator had moved away from.
    expect(onPick.mock.calls.map(([v]) => v)).toEqual(["escalate", "escalate", "audit", "audit"]);
  });

  it("keeps focus and selection together across a wrap, in both directions", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    screen.getByTestId("dec-block").focus();

    await user.keyboard("{ArrowLeft}"); // wraps to the last option
    expect(checked()).toEqual(["Audit"]);
    expect(document.activeElement).toBe(screen.getByTestId("dec-audit"));

    await user.keyboard("{ArrowDown}"); // wraps forward to the first
    expect(checked()).toEqual(["Block"]);
    expect(document.activeElement).toBe(screen.getByTestId("dec-block"));
  });

  it("leaves the group as one tab stop, and tabbing out lands nowhere inside it", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button data-testid="before">before</button>
        <Harness />
        <button data-testid="after">after</button>
      </>
    );
    await user.tab(); // before
    await user.tab(); // into the group — the checked segment
    expect(document.activeElement).toBe(screen.getByTestId("dec-block"));
    await user.keyboard("{ArrowRight}");
    await user.tab();
    expect(document.activeElement).toBe(screen.getByTestId("after"));
  });

  it("does not steal focus when the value is driven from elsewhere on the page", async () => {
    // The `contains` guard. A group that grabbed focus on mount or on an unrelated state change would
    // be a worse bug than the one being fixed.
    const user = userEvent.setup();
    function Outside() {
      const [value, setValue] = useState("block");
      return (
        <>
          <button data-testid="outside" onClick={() => setValue("audit")}>
            set audit
          </button>
          <SegmentedControl options={OPTS} value={value} onChange={setValue} ariaLabel="d" data-testid="dec" />
        </>
      );
    }
    render(<Outside />);
    await user.click(screen.getByTestId("outside"));
    expect(checked()).toEqual(["Audit"]);
    expect(document.activeElement).toBe(screen.getByTestId("outside"));
  });

  it("still selects on click, with focus where the operator clicked", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByTestId("dec-audit"));
    expect(checked()).toEqual(["Audit"]);
    expect(document.activeElement).toBe(screen.getByTestId("dec-audit"));
  });
});

/**
 * The one state in which focus and selection CANNOT be made to agree: `value` matches no option.
 *
 * One stale deep link, one renamed option, one owner that normalises a range after the first render, and
 * the roving tabindex gave every segment `tabIndex={-1}` while `move()` bailed on `i < 0`. The result is
 * a control with nothing tinted that Tab skips entirely and arrow keys ignore — silently, with no text
 * anywhere saying the current value is not one of the choices. Making the focus ring follow the checked
 * segment does not reach this: there is no checked segment to follow.
 */
describe("SegmentedControl — when `value` is none of the options", () => {
  it("keeps a tab stop, so the control is still reachable from the keyboard", async () => {
    const user = userEvent.setup();
    render(
      <>
        <button data-testid="before">before</button>
        <SegmentedControl options={OPTS} value="7d-from-an-old-link" onChange={vi.fn()} ariaLabel="d" data-testid="dec" />
      </>
    );
    expect(checked(), "nothing may be claimed as checked").toEqual([]);
    await user.tab();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByTestId("dec-block"));
  });

  it("answers the first arrow key by selecting the first option, instead of doing nothing", async () => {
    const user = userEvent.setup();
    render(<Harness initial="7d-from-an-old-link" />);
    screen.getByTestId("dec-block").focus();

    await user.keyboard("{ArrowRight}");
    expect(screen.getByTestId("chosen")).toHaveTextContent("block");
    expect(checked()).toEqual(["Block"]);
    // And from there the ordinary invariant resumes.
    await user.keyboard("{ArrowRight}");
    expect(checked()).toEqual(["Escalate"]);
    expect(document.activeElement).toBe(screen.getByTestId("dec-escalate"));
  });

  it("moves the tab stop back onto the checked segment the moment there is one", () => {
    const { rerender } = render(
      <SegmentedControl options={OPTS} value="nope" onChange={vi.fn()} ariaLabel="d" data-testid="dec" />
    );
    expect(screen.getByTestId("dec-block")).toHaveAttribute("tabindex", "0");
    rerender(<SegmentedControl options={OPTS} value="audit" onChange={vi.fn()} ariaLabel="d" data-testid="dec" />);
    expect(screen.getByTestId("dec-block")).toHaveAttribute("tabindex", "-1");
    expect(screen.getByTestId("dec-audit")).toHaveAttribute("tabindex", "0");
  });
});

/** Two assertions preserved from the deleted three-primitive test file: the ARIA contract and the tint. */
describe("SegmentedControl — semantics and colour", () => {
  it("is a radiogroup with exactly one checked option", () => {
    render(<SegmentedControl options={OPTS} value="block" onChange={vi.fn()} ariaLabel="decision" data-testid="dec" />);
    expect(screen.getByRole("radiogroup", { name: "decision" })).toBeInTheDocument();
    expect(screen.getByTestId("dec-block")).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("dec-escalate")).toHaveAttribute("aria-checked", "false");
  });

  it("tints the active segment by what it MEANS, not by the brand accent", () => {
    // A selected Block must not look like a selected Audit — the choice is about consequence.
    const { rerender } = render(
      <SegmentedControl options={OPTS} value="block" onChange={vi.fn()} ariaLabel="d" data-testid="dec" />
    );
    const asBlock = screen.getByTestId("dec-block").getAttribute("style");
    rerender(<SegmentedControl options={OPTS} value="audit" onChange={vi.fn()} ariaLabel="d" data-testid="dec" />);
    expect(screen.getByTestId("dec-audit").getAttribute("style")).not.toBe(asBlock);
  });
});
