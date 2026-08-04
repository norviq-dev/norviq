// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The P1 acceptance criterion, in a browser, against the real app and a real seeded cluster.
//
// The handoff states it as an outcome rather than a feature: "a first-time operator must discover
// argument scoping WITHOUT being told it exists". A unit test can prove a ScopeCell renders four
// slots; only this can prove those slots are what an operator meets when they allow a tool.
//
// The seeder puts `send_dm` on the cluster with a schema whose four arguments cover all four
// addressability outcomes, so the detail slot here is computed from a real registry response rather
// than from a fixture I wrote.
//
// Prerequisites (see scripts/e2e.sh):
//   kubectl -n norviq port-forward svc/norviq-ui 3400:80
//   .venv/bin/python scripts/kind-e2e/seed.py
//   an admin JWT in $NRVQ_TOKEN_FILE

import { expect, test } from "./fixtures";

/**
 * Add a condition through the ConditionPicker.
 *
 * Replaces `selectOption` on the two `<select>`s this used to drive. The picker is the affordance now
 * because a select cannot show a disabled option's REASON — the non-addressable arguments carried
 * theirs in a `title` on a disabled `<option>`, which no browser renders.
 *
 * Tolerates an already-open picker: some tests add two conditions in a row.
 */
async function pickCondition(page: import("@playwright/test").Page, id: string): Promise<void> {
  const open = page.getByTestId("builder-condition-picker-open");
  if (await open.isVisible().catch(() => false)) await open.click();
  await page.getByTestId(`builder-condition-picker-option-${id}`).click();
}

/** Open the builder and allow one tool — the shortest path to the row this spec is about. */
async function allowTool(page: import("@playwright/test").Page, tool: string) {
  await page.goto("/policies/catalog?ns=analytics");
  await page.getByRole("button", { name: "Visual Builder" }).click();
  await expect(page.getByTestId("builder-agent-class")).toBeVisible({ timeout: 20_000 });
  await page.getByTestId("builder-agent-class").fill("support-agent");
  // Allowlist mode is where a grant exists at all; Tighten-only has no allowed-tool list.
  const allowlist = page.getByTestId("builder-mode-allowlist");
  if (await allowlist.count()) await allowlist.click();
  await page.getByTestId("builder-allowlist-tool-input").fill(tool);
  await page.getByTestId("builder-allowlist-tool-add").click();
  await expect(page.getByTestId(`builder-allowlist-tool-row-${tool}`)).toBeVisible();
}

test("allowing a tool immediately says the grant is unrestricted, and offers the way to narrow it", async ({
  page,
  recorder
}) => {
  // The whole P1. This used to be a chip with a 10.5px grey `+ scope` link — the product's
  // differentiator rendered as the least prominent thing on screen.
  await allowTool(page, "send_dm");

  await expect(page.getByTestId("builder-scope-cell-send_dm-headline")).toHaveText("Any arguments · unrestricted");
  await expect(page.getByTestId("builder-scope-cell-send_dm-impact")).toContainText(
    "Allows every call to send_dm, with any arguments."
  );
  const cta = page.getByTestId("builder-scope-cell-send_dm-cta");
  await expect(cta).toHaveText(/Narrow it/);
  // Loud, not a text link: the affordance has to be found without being told it exists.
  await expect(cta).toHaveClass(/btn-primary/);

  recorder.expectNoApiFailures();
  recorder.expectNoConsoleErrors();
});

test("the detail slot names the tool's real narrowable arguments, from the registry", async ({ page }) => {
  // Computed from the live `/api/v1/tools` response — `send_dm` declares four arguments of which two
  // are addressable. A fixture could not prove the endpoint really produces that shape.
  await allowTool(page, "send_dm");
  const detail = page.getByTestId("builder-scope-cell-send_dm-detail");
  await expect(detail).toContainText(/of its 4 arguments can be narrowed/);
  await expect(detail).toContainText("to");
});

test("the standing banner counts what is still wide open", async ({ page }) => {
  // "I allowed six tools" has to become "I have narrowed two of six" somewhere that cannot be
  // scrolled past, or an unscoped grant reads as a finished one.
  await allowTool(page, "send_dm");
  const banner = page.getByTestId("builder-unscoped-banner");
  await expect(banner).toBeVisible();
  await expect(banner).toContainText(/1 of 1 allowed tool is unscoped/);
  await expect(banner).toContainText(/A name is what your framework already grants/);

  // And it is a route into the work, not just a scold.
  await page.getByTestId("builder-unscoped-banner-cta").click();
  await expect(page.getByTestId("builder-grant-editor-send_dm")).toBeVisible();
});

test("narrowing a tool flips the row from loud to quiet, and the banner clears", async ({ page }) => {
  await allowTool(page, "send_dm");
  await page.getByTestId("builder-scope-cell-send_dm-cta").click();
  await expect(page.getByTestId("builder-grant-editor-send_dm")).toBeVisible();

  // Add one whole-call condition — the route that works whether or not a schema is available.
  await pickCondition(page, "data_classes");
  await page.getByTestId("builder-fact-value-send_dm-0").fill("secret");

  await expect(page.getByTestId("builder-scope-cell-send_dm-headline")).toContainText("Narrowed · 1 condition");
  await expect(page.getByTestId("builder-scope-cell-send_dm-impact")).toContainText(
    "Allows a call only when its one condition holds."
  );
  // The CTA recedes once there is nothing urgent left on this row.
  await expect(page.getByTestId("builder-scope-cell-send_dm-cta")).toHaveClass(/btn-outline/);
  await expect(page.getByTestId("builder-unscoped-banner")).toHaveCount(0);
});

test("a condition authored on the row reaches the policy the builder is about to save", async ({ page }) => {
  await allowTool(page, "send_dm");
  await page.getByTestId("builder-scope-cell-send_dm-cta").click();
  await pickCondition(page, "data_classes");
  await page.getByTestId("builder-fact-value-send_dm-0").fill("secret");

  // The row states the clause in the compiler's own words.
  await expect(page.getByTestId("builder-scope-cell-send_dm-condition").first()).toHaveText(
    "data_classes excludes {secret}"
  );

  // OPEN THE REGO DRAWER FIRST. It is a 46px rail by default — the compiled policy is reference, and
  // a permanently-open pane was taking the width the allowed-tool row needs — so the editor is not
  // mounted until someone asks for it. Driving the rail is what a user does to read the rego, and it
  // is what this assertion depends on, so the spec should do it rather than assume a pane that is no
  // longer there by default.
  await page.getByTestId("builder-editor-expand-toggle").click();

  // And the live preview is compiling THIS class's intent-allowlist module — scoped to the sheet,
  // because the Policy Catalog behind it has its own Monaco showing the strict preset, and an
  // unscoped locator asserts green against the wrong document entirely.
  //
  // That the chip and the module's header use the SAME words is a structural guarantee rather than a
  // coincidence — both call the exported `describeFact` — and is asserted in ScopeCell.test.tsx.
  // It is not re-asserted here: Monaco virtualises its viewport and the summary line sits below the
  // fold of a long generated header, so a DOM read would be testing scroll position, not vocabulary.
  const lines = page.getByTestId("builder-sheet").locator(".monaco-editor .view-lines").first();
  await expect(lines).toBeVisible();
  await expect
    .poll(async () => (await lines.innerText()).replace(/\u00a0/g, " "), { timeout: 15_000 })
    .toContain("package norviq.intent.support_agent");
});

test("the mode fork states the inversion, not just the two definitions", async ({ page }) => {
  // The two modes do not merely differ in emphasis — an identical clause is a precondition for
  // ALLOWING in one and a trigger for BLOCKING in the other. An operator switching mode with
  // conditions already authored keeps every clause and reverses every outcome, which is the most
  // expensive mistake this screen can produce and the one it never mentioned.
  await page.goto("/policies/catalog?ns=analytics");
  await page.getByRole("button", { name: "Visual Builder" }).click();
  await expect(page.getByTestId("builder-agent-class")).toBeVisible({ timeout: 20_000 });

  const fork = page.getByTestId("builder-mode-fork");
  await expect(fork).toContainText("The two modes invert what a condition means");
  await expect(fork).toContainText("allow only if it carries no secret");
  await expect(fork).toContainText("block when it carries no secret");

  // ...and it names the consequence of the mode currently selected, which is the actionable half.
  await page.getByTestId("builder-mode-rules").click();
  await expect(fork).toContainText(/a mistake is SILENT/);
  await page.getByTestId("builder-mode-allowlist").click();
  await expect(fork).toContainText(/a mistake is LOUD/);
});

test("the budget hint follows the encoding, not the label", async ({ page }) => {
  // `hostIn` reads like set membership and emits an anchored `regex.match`; `destinations.hosts
  // anyOf` reads like a pattern and compiles to a free set comprehension. Both directions are
  // counter-intuitive, and the server caps a policy at 25 regex ops.
  await allowTool(page, "send_dm");
  await page.getByTestId("builder-scope-cell-send_dm-cta").click();

  await pickCondition(page, "hostIn");
  await expect(page.getByTestId("builder-constraint-cost-send_dm-0")).toContainText("1 regex op");

  await pickCondition(page, "destinations.hosts");
  await expect(page.getByTestId("builder-fact-cost-send_dm-0")).toContainText("free");
});

test("the scope panel groups clauses by what they address", async ({ page }) => {
  // Per-argument constraints and whole-call facts read identically and behave differently: one fails
  // when the caller simply omits the argument, the other is derived from the call as a whole.
  await allowTool(page, "send_dm");
  await page.getByTestId("builder-scope-cell-send_dm-cta").click();
  const editor = page.getByTestId("builder-grant-editor-send_dm");

  await pickCondition(page, "required");
  await expect(editor.getByText("Argument", { exact: true })).toBeVisible();
  await expect(editor).toContainText(/A call that omits it fails this line/);

  await pickCondition(page, "data_classes");
  await expect(editor.getByText("Whole call", { exact: true })).toBeVisible();
  await expect(editor).toContainText(/derived about the call, not one named argument/);
});
