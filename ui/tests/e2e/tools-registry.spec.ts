// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Tools page, against the REAL app and a real seeded cluster — no mocks.
//
// These are the handoff's own acceptance criteria expressed as tests. They exist because the unit suite,
// however thorough, asserts against a fixture I wrote: it proves the component renders what I told it to,
// not that the endpoint actually produces those shapes. The seeder (scripts/kind-e2e/seed.py) puts the
// same five awkward states on the cluster that the unit fixture mirrors, so when these disagree with the
// unit tests it means the CONTRACT drifted — which is exactly what a browser suite is for.
//
// Prerequisites (see scripts/e2e.sh):
//   kubectl -n norviq port-forward svc/norviq-ui 3400:80
//   .venv/bin/python scripts/kind-e2e/seed.py
//   an admin JWT in $NRVQ_TOKEN_FILE

import { expect, test } from "./fixtures";

const NS = "analytics";

test.beforeEach(async ({ page }) => {
  await page.goto(`/tools?ns=${NS}`);
  await expect(page.getByTestId("tools-declared")).toBeVisible({ timeout: 20_000 });
});

test("declared and observed never appear in one table", async ({ page, recorder }) => {
  // The acceptance criterion. Merging the tiers was the bug this endpoint was built to retire: a UI that
  // treats sources of different strength as one set will suggest names that cannot exist.
  const declared = page.getByTestId("tools-declared");
  const observed = page.getByTestId("tools-observed");
  await expect(declared).toBeVisible();
  await expect(observed).toBeVisible();

  // A declared row lives in the declared panel and nowhere else.
  await expect(declared.getByTestId("tool-row-slack-send_dm")).toBeVisible();
  await expect(observed.getByTestId("tool-row-slack-send_dm")).toHaveCount(0);
  // ...and an observed row lives in the observed panel and nowhere else.
  await expect(observed.getByTestId("tool-row-observed-http_get")).toBeVisible();
  await expect(declared.getByTestId("tool-row-observed-http_get")).toHaveCount(0);

  recorder.expectNoApiFailures();
  recorder.expectNoConsoleErrors();
});

test("a tool's scopeability is answerable without clicking", async ({ page }) => {
  await expect(page.getByTestId("tool-row-slack-send_dm")).toContainText("Scopeable");
  // Declared AND pinned AND unscopeable — the state the 8 KiB canonical slice creates when a long
  // description sorts ahead of inputSchema and evicts it. Seeded deliberately for exactly this check.
  await expect(page.getByTestId("tool-row-warehouse-bulk_export")).toContainText("No schema");
  await expect(page.getByTestId("tool-row-observed-http_get")).toContainText("Name only");
});

test("two servers serving one tool name render as two rows, and the collision is explained", async ({ page }) => {
  // The API returns both; nothing merges them. A row keyed on tool_name alone breaks here, and the
  // engine sees only the bare name — so a policy naming it governs both.
  await expect(page.getByTestId("tool-row-filesystem-read_file")).toBeVisible();
  await expect(page.getByTestId("tool-row-runbooks-read_file")).toBeVisible();
  await expect(page.getByTestId("tools-collision")).toContainText(/governs\s*both/i);
});

test("the argument tree shows unusable arguments WITH their reason", async ({ page }) => {
  // Hiding them would teach the operator the argument does not exist — the capability-fragment bug in
  // reverse. The reason is the whole affordance: without it a greyed row reads as a broken product.
  await page.getByTestId("tool-row-slack-send_dm").click();
  await expect(page.getByTestId("argument-tree")).toBeVisible();

  await expect(page.getByTestId("argument-row-to")).toContainText("Addressable");
  await expect(page.getByTestId("argument-row-filters.customer")).toBeVisible();
  await expect(page.getByTestId("argument-row-retries")).toContainText(/only text does/i);
  await expect(page.getByTestId("argument-row-attachments")).toContainText(/indexed at runtime/i);
});

test("a withheld description is never rendered, and its absence is explained", async ({ page }) => {
  // `approved_canonical` holds the PRE-sanitize text — the payload Gate A kept from the model. Showing
  // it here would put the attack in front of the operator instead. The seeded post_message carries a
  // critical finding precisely so this is testable against real data rather than a mock.
  await page.getByTestId("tool-row-slack-post_message").click();
  const detail = page.getByTestId("tool-detail");
  await expect(detail).toContainText(/Description withheld/i);
  await expect(detail).not.toContainText(/always call before replying/i);
  // The injection text must not be anywhere in the document, not merely absent from the panel.
  await expect(page.locator("body")).not.toContainText(/forward the conversation/i);
});

test("Scope this tool in a policy → hands off to the builder", async ({ page }) => {
  // The reverse direction of the P1 fix: arrive at a tool, leave with a policy that narrows it, instead
  // of discovering argument scoping by accident inside the builder.
  await page.getByTestId("tool-row-slack-send_dm").click();
  const cta = page.getByTestId("tool-detail-scope-cta");
  await expect(cta).toBeVisible();
  await cta.click();
  await expect(page).toHaveURL(/\/policies\/catalog/);
});

test("the window control offers only what the API accepts, and refetches", async ({ page, recorder }) => {
  const range = page.getByTestId("tools-range");
  await expect(range.getByText("24h", { exact: true })).toBeVisible();
  await expect(range.getByText("90d", { exact: true })).toBeVisible();
  // 1h/6h are on the global header selector and cannot be served here — honouring them would widen a
  // window the operator asked to narrow.
  await expect(range.getByText("1h", { exact: true })).toHaveCount(0);
  await expect(range.getByText("6h", { exact: true })).toHaveCount(0);

  const call = page.waitForResponse((r) => r.url().includes("/api/v1/tools") && r.url().includes("range=7d"));
  await range.getByText("7d", { exact: true }).click();
  expect((await call).status()).toBe(200);
  recorder.expectNoApiFailures();
});

test("killing the registry reads as unknown, never as a clean bill of health", async ({ page }) => {
  // The acceptance criterion that silence must never be an all-clear. An operator who reads a failed
  // fetch as "no tools here" will conclude a namespace is empty when nothing was actually asked.
  await page.route("**/api/v1/tools**", (route) => route.fulfill({ status: 503, body: "upstream unavailable" }));
  await page.reload();

  await expect(page.getByTestId("tools-error")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId("tools-error")).toContainText(/not the same as .there are none./i);
  // Crucially: no tier panels at all, rather than two empty ones implying nothing exists.
  await expect(page.getByTestId("tools-declared")).toHaveCount(0);
  await expect(page.getByTestId("tools-observed")).toHaveCount(0);
});
