// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// REACHABILITY, not behaviour. Every other builder spec picks an option it already knows exists
// (`selectOption("keyword")`) and drives the flow behind it — so a control that is MISSING from the
// dropdown is invisible to all of them.
//
// That is not hypothetical. `scalarFact` was added to CONDITION_TYPES, the unit test asserting that
// constant passed, tsc/eslint/build passed, 191 browser tests passed — and the option was still absent
// from the only control an operator can reach, because the dropdown renders from a SECOND list
// (CONDITION_TYPE_GROUPS) whose element type checks membership but not coverage. It was caught by a
// human opening the console.
//
// So this spec asserts the OFFER: every condition type the product claims to support must be present
// in the live dropdown, and picking the engine-facts one must produce a usable editor rather than a
// dead row. A test that only ever selects options it hard-codes cannot notice an absent one.

import { test, expect, waitForApp } from "./fixtures";

test.describe("Visual Builder — every condition type is reachable", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/policies/catalog");
    await waitForApp(page);
    await page.getByRole("button", { name: "Visual Builder" }).click();
    await expect(page.getByTestId("builder-agent-class")).toBeVisible({ timeout: 20_000 });
    await page.getByTestId("builder-agent-class").fill("reachability-probe");
    await page.getByTestId("builder-mode-rules").click();
    await page.getByTestId("builder-add-rule").click();
    await page.getByTestId("builder-add-condition-0-0").click();
  });

  test("the condition dropdown offers every supported type, including the engine facts", async ({ page }) => {
    const select = page.getByTestId("builder-cond-0-0-0-type");
    await expect(select).toBeVisible();

    const values = await select.locator("option").evaluateAll((os) =>
      os.map((o) => (o as HTMLOptionElement).value)
    );

    // The six that always existed, plus scalarFact — the one that shipped unreachable.
    for (const t of ["detector", "keyword", "paramRegex", "toolIn", "sourceVerb", "trustBelow", "scalarFact"]) {
      expect(values, `condition type "${t}" is not offered in the live dropdown`).toContain(t);
    }

    // Every option must sit inside a labelled optgroup — an ungrouped option is how a type ends up
    // rendered but unfindable, which is the same failure one step later.
    const grouped = await select.locator("optgroup option").count();
    expect(grouped).toBe(values.length);
  });

  test("picking the engine-fact type yields a working editor, not a dead row", async ({ page }) => {
    await page.getByTestId("builder-cond-0-0-0-type").selectOption("scalarFact");

    const field = page.getByTestId("builder-cond-0-0-0-fact-field");
    await expect(field, "the scalarFact row must render a field picker").toBeVisible();

    const fields = await field.locator("option").evaluateAll((os) =>
      os.map((o) => (o as HTMLOptionElement).value)
    );
    for (const f of ["mcp.pin_status", "mcp.scan_severity", "mcp.server", "direction", "verb"]) {
      expect(fields, `engine fact "${f}" is not offered`).toContain(f);
    }
  });

  test("a closed vocabulary is a picker, never a free-text box", async ({ page }) => {
    // factOpsFor already withheld the regex ops for these fields; the VALUE stayed free text, so
    // `drifted` for `drift` compiled, validated and then matched nothing for ever. A rule that
    // silently never fires is indistinguishable from one that fires and finds nothing.
    await page.getByTestId("builder-cond-0-0-0-type").selectOption("scalarFact");
    await page.getByTestId("builder-cond-0-0-0-fact-field").selectOption("mcp.pin_status");

    await expect(page.getByTestId("builder-cond-0-0-0-fact-enum")).toBeVisible();
    await expect(page.getByTestId("builder-cond-0-0-0-fact-value")).toHaveCount(0);

    const vals = await page
      .getByTestId("builder-cond-0-0-0-fact-enum")
      .locator("option")
      .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
    // Transcribed from norviq/mcp/pins.py's PIN_* constants plus the "unknown" an unscanned tool reports.
    expect(vals).toEqual(expect.arrayContaining(["pinned", "drift", "quarantined", "unknown"]));

    // And the ops must be the cheap set-membership pair, not the regex ops.
    const ops = await page
      .getByTestId("builder-cond-0-0-0-fact-op")
      .locator("option")
      .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
    expect(ops.sort()).toEqual(["equals", "in"]);
  });

  test("the guardrail shape compiles — block when the MCP pin drifted", async ({ page }) => {
    await page.getByTestId("builder-rule-reason-0").fill("mcp tool definition drifted since approval");
    await page.getByTestId("builder-cond-0-0-0-type").selectOption("scalarFact");
    await page.getByTestId("builder-cond-0-0-0-fact-field").selectOption("mcp.pin_status");
    await page.getByTestId("builder-cond-0-0-0-fact-enum").selectOption("drift");

    // The live rego pane is the product's own proof that the graph compiles. The nested object.get form
    // matters: a bare input.mcp.pin_status makes the WHOLE rule body undefined when a call carries no
    // MCP context, rather than making one predicate false.
    // No dedicated testid for the rego text; `builder-editor-container` is the pane that holds it.
    const rego = page.getByTestId("builder-editor-container");
    await expect(rego).toContainText("pin_status", { timeout: 20_000 });
    await expect(rego).toContainText("drift");
  });
});
