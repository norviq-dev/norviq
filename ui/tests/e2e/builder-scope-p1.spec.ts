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
  await page.getByTestId("builder-fact-add-kind").selectOption("data_classes");
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
  await page.getByTestId("builder-fact-add-kind").selectOption("data_classes");
  await page.getByTestId("builder-fact-value-send_dm-0").fill("secret");

  // The row states the clause in the compiler's own words.
  await expect(page.getByTestId("builder-scope-cell-send_dm-condition").first()).toHaveText(
    "data_classes excludes {secret}"
  );

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
