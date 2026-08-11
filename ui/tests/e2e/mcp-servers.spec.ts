// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// MCP Servers, against the REAL app and a real seeded cluster — no mocks.
//
// The unit suite proves the component renders what a fixture told it to. These prove the API actually
// produces those shapes: that `pins/observe` really leaves a drifted row when a server changes its
// definition, that `findings[].evidence` really survives the round trip, and that the composite key
// the endpoint returns really is what the table needs.
//
// Prerequisites (see scripts/e2e.sh):
//   kubectl -n norviq port-forward svc/norviq-ui 3400:80
//   .venv/bin/python scripts/kind-e2e/seed.py     ← seeds the drift these tests need
//   an admin JWT in $NRVQ_TOKEN_FILE

import { expect, test } from "./fixtures";

test.beforeEach(async ({ page }) => {
  await page.goto("/mcp");
  await expect(page.getByTestId("mcp-totals")).toBeVisible({ timeout: 20_000 });
});

test("two servers serving one tool name are two rows with distinct keys", async ({ page, recorder }) => {
  // `rowKey="tool_name"` gave React duplicate keys here, and made selection unreachable.
  await expect(page.locator('tr[data-row-key="analytics/filesystem/read_file"]')).toBeVisible();
  await expect(page.locator('tr[data-row-key="analytics/runbooks/read_file"]')).toBeVisible();
  await expect(page.getByTestId("mcp-collision")).toContainText(/governs both/i);
  recorder.expectNoApiFailures();
  recorder.expectNoConsoleErrors();
});

test("clicking a pin highlights the row it opened", async ({ page }) => {
  // The old `selectedKey` was `server/tool` compared against `row.tool_name` — never equal, so the
  // highlight was code that could not run.
  const row = page.locator('tr[data-row-key="analytics/runbooks/read_file"]');
  await row.click();
  await expect(row).toHaveClass(/selected/);
  await expect(page.locator('tr[data-row-key="analytics/filesystem/read_file"]')).not.toHaveClass(/selected/);
});

test("a drifted definition shows WHAT changed, not two documents", async ({ page }) => {
  // The seeder re-serves slack/post_message with an instruction smuggled into the `channel`
  // argument's description — a PINNED field, so the digest genuinely moves. If the API did not
  // really record a drift, this fails, which is the point of running it against the cluster.
  await page.locator('tr[data-row-key="analytics/slack/post_message"]').click();
  const detail = page.getByTestId("mcp-detail");
  await expect(detail).toBeVisible();
  await expect(detail).toContainText(/DIFFERS from the one approved/i);

  await expect(page.getByTestId("diff-added-count")).not.toHaveText("0 added");
  await expect(page.getByTestId("diff-add").filter({ hasText: "ignore prior instructions" })).toBeVisible();
  // Full documents are one click away, not the default — the default is the answer.
  await expect(page.getByTestId("approved-definition")).toHaveCount(0);
  await page.getByTestId("diff-toggle-full").click();
  await expect(page.getByTestId("approved-definition")).toBeVisible();
});

test("the scanner's evidence is quoted, framed, and inert", async ({ page }) => {
  // `findings[].evidence` reached the API and was rendered nowhere, so the rule name had to be
  // taken on faith. Here the operator reads the sentence they are being asked to judge.
  await page.locator('tr[data-row-key="analytics/slack/post_message"]').click();
  const quote = page.getByTestId("mcp-evidence-mcp_a_instruction_override-quote");
  await expect(quote).toBeVisible();
  await expect(quote).toContainText(/ignore prior instructions/i);
  await expect(page.getByText(/attacker-authored/i)).toBeVisible();
  await expect(page.getByText(/Stripped before the model saw it/i)).toBeVisible();
});

test("forgetting a server is gated on typing its name and states the tofu consequence", async ({ page }) => {
  await page.locator('tr[data-row-key="analytics/warehouse"]').click();
  await page.getByTestId("mcp-forget-open").click();

  const submit = page.getByTestId("mcp-forget-submit");
  await expect(submit).toBeDisabled();
  await expect(page.getByTestId("mcp-forget-consequence")).toContainText(/auto-approved on sight/i);
  await page.getByTestId("mcp-forget-input").fill("wrong");
  await expect(submit).toBeDisabled();
  // Deliberately NOT confirmed: this spec proves the gate, and destroying a seeded server would
  // make every later spec order-dependent.
  await page.getByTestId("mcp-forget-cancel").click();
  await expect(page.getByTestId("mcp-forget")).toHaveCount(0);
});

test("a failed pin read never reads as 'no drift'", async ({ page }) => {
  await page.route("**/api/v1/mcp/pins**", (route) => route.fulfill({ status: 503, body: "pin store unreachable" }));
  await page.reload();
  const err = page.getByTestId("mcp-error");
  await expect(err).toBeVisible({ timeout: 20_000 });
  await expect(err).toContainText(/Not the same as .no drift./i);
  await expect(err).toContainText(/enforcement is unaffected/i);
});

test("cross-links to the surface that says what a tool can DO", async ({ page }) => {
  await page.getByTestId("mcp-to-tools").click();
  await expect(page).toHaveURL(/\/tools/);
  await expect(page.getByTestId("tools-declared")).toBeVisible({ timeout: 20_000 });
});
