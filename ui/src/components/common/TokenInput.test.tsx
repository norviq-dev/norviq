// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The three input primitives Phase 1 still owed: token list, segmented choice, stepper.
 *
 * `TokenInput` carries most of these assertions because it replaces a comma-separated text box, and
 * that shape hid real defects: whitespace baked into values, invisible duplicates, and empty elements
 * from a trailing comma. Each is a silent wrong-policy, not a crash.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { TokenInput } from "./TokenInput";
import { SegmentedControl } from "./SegmentedControl";
import { Stepper } from "./Stepper";

/** Controlled wrapper — the component is controlled, so a test needs somewhere to hold the state. */
function Harness({ initial = [] as string[] }) {
  const [values, setValues] = useState<string[]>(initial);
  return (
    <>
      <TokenInput values={values} onChange={setValues} ariaLabel="values" data-testid="tok" placeholder="add a value" />
      <output data-testid="serialised">{JSON.stringify(values)}</output>
    </>
  );
}

describe("TokenInput", () => {
  it("commits on Enter and on comma, because operators paste comma lists out of habit", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const draft = screen.getByTestId("tok-draft");

    await user.type(draft, "secret{Enter}");
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret"]');

    await user.type(draft, "pci,");
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret","pci"]');
  });

  it("splits a pasted comma list into separate tokens", async () => {
    // A paste arrives as ONE change event. Waiting for a keystroke that never comes would leave the
    // whole string as a single value that matches nothing.
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByTestId("tok-draft"));
    await user.paste("secret, pci, pii");
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret","pci","pii"]');
  });

  it("trims whitespace — the defect a comma-split text box bakes into the value", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByTestId("tok-draft"));
    await user.paste("  secret ,  pci  ");
    // Not `[" secret ", "  pci  "]`. A leading space silently stops the policy matching what was meant.
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret","pci"]');
  });

  it("drops empties from a trailing comma", async () => {
    // `"secret,"` used to yield a `""` member: unmatched forever in a noneOf, and a value nobody wrote
    // in a subsetOf.
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByTestId("tok-draft"));
    await user.paste("secret,,");
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret"]');
  });

  it("refuses a duplicate rather than de-duplicating it silently later", async () => {
    const user = userEvent.setup();
    render(<Harness initial={["secret"]} />);
    await user.type(screen.getByTestId("tok-draft"), "secret{Enter}");
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret"]');
  });

  it("commits a typed-but-unconfirmed value on blur", async () => {
    // Losing a restriction because someone clicked Save without pressing Enter is exactly the silent
    // over-permissiveness this whole workstream is about.
    const user = userEvent.setup();
    render(<Harness />);
    await user.type(screen.getByTestId("tok-draft"), "secret");
    await user.tab();
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret"]');
  });

  it("removes a token by its × and by Backspace on an empty draft", async () => {
    const user = userEvent.setup();
    render(<Harness initial={["secret", "pci"]} />);

    await user.click(screen.getByRole("button", { name: "Remove secret" }));
    expect(screen.getByTestId("serialised")).toHaveTextContent('["pci"]');

    await user.click(screen.getByTestId("tok-draft"));
    await user.keyboard("{Backspace}");
    expect(screen.getByTestId("serialised")).toHaveTextContent("[]");
  });

  it("does not eat a Backspace that is editing the draft", async () => {
    const user = userEvent.setup();
    render(<Harness initial={["secret"]} />);
    await user.type(screen.getByTestId("tok-draft"), "pc");
    await user.keyboard("{Backspace}");
    // The draft lost a character; the existing token is untouched.
    expect(screen.getByTestId("serialised")).toHaveTextContent('["secret"]');
    expect(screen.getByTestId("tok-draft")).toHaveValue("p");
  });
});

describe("SegmentedControl", () => {
  const OPTS = [
    { value: "block", label: "Block", hex: "#ff3b5c" },
    { value: "escalate", label: "Escalate", hex: "#ffb020" },
    { value: "audit", label: "Audit", hex: "#7c5cfc" }
  ];

  it("is a radiogroup with exactly one checked option", () => {
    render(<SegmentedControl options={OPTS} value="block" onChange={() => {}} ariaLabel="decision" data-testid="dec" />);
    expect(screen.getByRole("radiogroup", { name: "decision" })).toBeInTheDocument();
    expect(screen.getByTestId("dec-block")).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("dec-escalate")).toHaveAttribute("aria-checked", "false");
  });

  it("moves with arrow keys and takes a single tab stop", async () => {
    // A row of plain buttons would take three tab stops and ignore arrows — not what a keyboard user
    // expects from a segmented control.
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<SegmentedControl options={OPTS} value="block" onChange={onChange} ariaLabel="decision" data-testid="dec" />);
    expect(screen.getByTestId("dec-escalate")).toHaveAttribute("tabindex", "-1");

    screen.getByTestId("dec-block").focus();
    await user.keyboard("{ArrowRight}");
    expect(onChange).toHaveBeenCalledWith("escalate");
  });

  it("wraps at the ends", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(<SegmentedControl options={OPTS} value="block" onChange={onChange} ariaLabel="decision" data-testid="dec" />);
    screen.getByTestId("dec-block").focus();
    await user.keyboard("{ArrowLeft}");
    expect(onChange).toHaveBeenCalledWith("audit");
  });

  it("tints the active segment by what it MEANS, not by the brand accent", async () => {
    // A selected Block must not look like a selected Audit — the choice is about consequence.
    const { rerender } = render(
      <SegmentedControl options={OPTS} value="block" onChange={() => {}} ariaLabel="d" data-testid="dec" />
    );
    const asBlock = screen.getByTestId("dec-block").getAttribute("style");
    rerender(<SegmentedControl options={OPTS} value="audit" onChange={() => {}} ariaLabel="d" data-testid="dec" />);
    expect(screen.getByTestId("dec-audit").getAttribute("style")).not.toBe(asBlock);
  });
});

describe("Stepper", () => {
  const STEPS = [{ label: "Propose" }, { label: "Dry run" }, { label: "Save as draft" }];

  it("marks the current step for assistive tech, and only that one", () => {
    render(<Stepper steps={STEPS} current={1} data-testid="st" />);
    expect(screen.getByTestId("st-step-1")).toHaveAttribute("aria-current", "step");
    expect(screen.getByTestId("st-step-0")).not.toHaveAttribute("aria-current");
    expect(screen.getByTestId("st-step-2")).not.toHaveAttribute("aria-current");
  });

  it("ticks the steps behind you and numbers the ones ahead", () => {
    // The number is only useful while the step is still ahead — once done, the tick says more.
    render(<Stepper steps={STEPS} current={1} data-testid="st" />);
    expect(screen.getByTestId("st-step-0").querySelector("svg")).toBeTruthy();
    expect(screen.getByTestId("st-step-2")).toHaveTextContent("3");
  });

  it("renders the reassurance both surfaces need in the same place", () => {
    render(<Stepper steps={STEPS} current={0} hint="Nothing is enforced until you save." data-testid="st" />);
    expect(screen.getByTestId("st")).toHaveTextContent("Nothing is enforced until you save.");
  });
});
