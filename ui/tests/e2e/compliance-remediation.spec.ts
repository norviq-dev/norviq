// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Batch B (COMP-GEN-01) — REAL form login, REAL controls + backend. Proves the Compliance detail view's
// MULTI-SELECT + agent-class picker drives the real control-specific batch-generation endpoint:
//   • checking a GAP control reveals the batch bar (count),
//   • the class-scope picker + "Generate for selected" fire ONE POST /compliance/{fw}/generate-batch
//     carrying every checked control + the chosen class_mode, and
//   • the console reports the outcome (a rollup toast).
// (The control-specific rego, the two-controls-differ fix, the apply→/evaluate block, and tighten-only are
// proven live at the backend + opa level in tests/api/test_compliance_remediation.py + the closeout evidence.
// In the seeded default namespace every live GAP is a no-runtime-rule control, so the batch correctly reports
// escalations — this spec asserts the UI→backend wiring + the real request body, which is the UI deliverable.)
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

test.use({ storageState: { cookies: [], origins: [] } });

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

async function openOwaspGaps(page: Page): Promise<void> {
  await page.goto("/compliance");
  await page.waitForLoadState("networkidle");
  // Open the OWASP framework's coverage detail (second card), jumping to its gaps.
  const openButtons = page.getByText("Open coverage detail →");
  await expect(openButtons.first()).toBeVisible({ timeout: 20000 });
  await openButtons.nth(1).click();
  await page.waitForLoadState("networkidle");
}

test("COMP-GEN-01: multi-select + class picker fires one control-specific generate-batch with the checked controls", async ({ page }) => {
  await realLogin(page);
  await openOwaspGaps(page);

  // Find the GAP-row checkboxes (only gap controls are generatable → only they carry a checkbox).
  const checkboxes = page.locator('[data-testid^="gap-select-"]');
  const n = await checkboxes.count();
  test.skip(n === 0, "No GAP controls in the served OWASP coverage — nothing to multi-select. BEST-EFFORT.");

  // No batch bar until at least one is checked.
  await expect(page.getByTestId("gap-batch-bar")).toHaveCount(0);

  // Check up to two gaps and capture their technique ids from the testid suffix.
  const pick = Math.min(n, 2);
  const chosenIds: string[] = [];
  for (let i = 0; i < pick; i++) {
    const cb = checkboxes.nth(i);
    const tid = (await cb.getAttribute("data-testid"))!.replace("gap-select-", "");
    chosenIds.push(tid);
    await cb.check();
  }
  await expect(page.getByTestId("gap-batch-bar")).toBeVisible();
  await expect(page.getByTestId("gap-batch-count")).toHaveText(`${pick} selected`);

  // Choose a class scope ("all affected classes") — the picker drives the batch's class_mode.
  await page.getByTestId("gap-batch-classmode").selectOption("all");

  // "Generate for selected" → exactly ONE POST /compliance/owasp/generate-batch with the checked controls.
  const batchReq = page.waitForRequest(
    (r) => r.url().includes("/api/v1/compliance/owasp/generate-batch") && r.method() === "POST"
  );
  await page.getByTestId("gap-batch-generate").click();
  const req = await batchReq;
  const body = req.postDataJSON() as { technique_ids?: string[]; class_mode?: string };
  expect(body.class_mode).toBe("all");
  expect([...(body.technique_ids ?? [])].sort()).toEqual([...chosenIds].sort());

  // The console reports the outcome (a rollup toast) and clears the selection bar.
  await expect(page.getByText(/pending in Policies|draft|escalat|no affected class/i).first()).toBeVisible({ timeout: 15000 });
  await expect(page.getByTestId("gap-batch-bar")).toHaveCount(0);
});
