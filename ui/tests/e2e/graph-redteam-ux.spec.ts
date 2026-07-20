// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// REAL form login, REAL controls + backend.
// Proves three Attack-Graph / Red-Team UX changes drive their actual on-screen + backend effect (a 200
// is NOT a pass):
//   • The per-attack results table collapses the separate ATLAS + OWASP columns into a
//     single "Frameworks" column of mapped chips (scales to N frameworks). The separate columns are GONE.
//   • The what-if "Draft blocking policy" button was a FABRICATED local-only "✓ Draft
//     created" (no POST, no id). It now POSTs a real dry-run draft (/threats/intent-draft) and the
//     confirmation becomes a LIVE deep-link into /policies/catalog?intent_draft=<id> where the draft row
//     is actually visible (dry-run, non-enforcing).
//   • The ranked path list / inspector sit BELOW the KPI/severity divider (a small top
//     offset), asserted geometrically against the stat strip.
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

// ── Frameworks column ────────────────────────────────────────────────────────────────────────────
test("the per-attack results collapse ATLAS+OWASP into a single Frameworks column of chips", async ({ page }) => {
  await realLogin(page);
  await page.goto("/redteam");
  await page.waitForLoadState("networkidle");

  // The seeded cluster carries a prior run → the results table renders on load. If the empty state is
  // shown instead, run the suite once so the table (and its headers) appear.
  if (await page.getByTestId("redteam-empty").count()) {
    await page.getByTestId("redteam-run").click();
    await expect(page.getByTestId("redteam-attacks")).toBeVisible({ timeout: 120000 });
  }
  const table = page.getByTestId("redteam-attacks").locator("table.tbl");
  await expect(table).toBeVisible({ timeout: 20000 });

  // The collapse: exactly ONE "Frameworks" column header, and NO standalone ATLAS / OWASP column headers.
  await expect(table.getByRole("columnheader", { name: "Frameworks" })).toHaveCount(1);
  await expect(table.getByRole("columnheader", { name: "ATLAS", exact: true })).toHaveCount(0);
  await expect(table.getByRole("columnheader", { name: "OWASP", exact: true })).toHaveCount(0);

  // The mapping still renders — as chips inside the single Frameworks cell (≥1 row, ≥1 ATLAS chip).
  await expect(table.getByTestId("redteam-frameworks").first()).toBeVisible();
  await expect(table.getByTestId("fw-chip-atlas").first()).toBeVisible();
});

// ── Draft blocking policy ────────────────────────────────────────────────────────────────────────
test("the what-if 'Draft blocking policy' POSTs a real dry-run draft and deep-links to it (no fabrication)", async ({ page }) => {
  await realLogin(page);
  await page.goto("/threats/graph");
  await page.waitForLoadState("networkidle");
  await expect(page.getByTestId("attack-graph-canvas")).toBeVisible({ timeout: 20000 });

  const rows = page.locator('button[aria-pressed]').filter({ hasText: "→" });
  const n = await rows.count();
  test.skip(n === 0, "No attack paths in the served namespace — cannot drive the draft flow. BEST-EFFORT.");

  // Select rows until one exposes a togglable (non-blocked) hop → the inspector's what-if toggle.
  const inspector = page.getByRole("complementary", { name: "Attack path inspector" });
  const limit = Math.min(n, 10);
  let armed = false;
  for (let i = 0; i < limit; i++) {
    await rows.nth(i).click();
    const toggle = inspector.getByRole("button", { name: /Block this step \(what-if\)/ }).first();
    if (await toggle.count()) { await toggle.click(); armed = true; break; }
  }
  test.skip(!armed, "No path with a togglable hop in the top rows — cannot arm a what-if. BEST-EFFORT.");

  // The draft button appears only once a what-if is active. First click = a REAL POST /threats/intent-draft.
  const draftBtn = inspector.getByTestId("ag-draft-button");
  await expect(draftBtn).toBeVisible();
  await expect(draftBtn).toHaveText(/Draft blocking policy/);
  const draftReq = page.waitForRequest((r) => r.url().includes("/api/v1/threats/intent-draft") && r.method() === "POST");
  const draftResp = page.waitForResponse((r) => r.url().includes("/api/v1/threats/intent-draft") && r.request().method() === "POST");
  await draftBtn.click();
  const req = await draftReq;
  // The POST carries the selected path's ns/cls + a readonly (tighten-only) intent + the path id (pre-fix: no POST).
  const body = req.postDataJSON() as { ns?: string; cls?: string; path_ids?: string[]; intent?: Record<string, boolean> };
  expect(typeof body.ns).toBe("string");
  expect(typeof body.cls).toBe("string");
  expect(Array.isArray(body.path_ids)).toBe(true);
  expect(body.path_ids?.length).toBeGreaterThanOrEqual(1);
  expect(body.intent).toMatchObject({ readonly: true });
  const resp = await draftResp;
  expect(resp.status()).toBeLessThan(300);
  const draftId = ((await resp.json()) as { draft_id?: string }).draft_id;
  expect(typeof draftId).toBe("string");

  // The confirmation becomes a LIVE deep-link (not a static "✓ Draft created" label).
  await expect(draftBtn).toHaveText(/open dry-run in Policies/i, { timeout: 10000 });

  // Clicking it navigates into the catalog on the draft's deep-link — and the draft row is really there
  // (dry-run, non-enforcing). This is the layered effect: the draft PERSISTED and is openable.
  await draftBtn.click();
  await expect(page).toHaveURL(/\/policies\/catalog\?.*intent_draft=/, { timeout: 15000 });
  await page.waitForLoadState("networkidle");
  await expect(page.getByText("Intent drafts · dry-run (not enforcing)")).toBeVisible({ timeout: 15000 });
  await expect(page.locator('[data-testid^="intent-draft-"]').first()).toBeVisible();
});

// ── Ranked path list placement ───────────────────────────────────────────────────────────────────
test("the ranked path list drops below the KPI/severity divider (top offset present)", async ({ page }) => {
  await realLogin(page);
  await page.goto("/threats/graph");
  await page.waitForLoadState("networkidle");
  await expect(page.getByTestId("attack-graph-canvas")).toBeVisible({ timeout: 20000 });

  const rows = page.locator('button[aria-pressed]').filter({ hasText: "→" });
  test.skip((await rows.count()) === 0, "No paths — the list is not rendered. BEST-EFFORT.");

  // The list column = the parent div of the "Attack paths · worst first" header.
  const list = page.getByText("Attack paths · worst first").locator("xpath=..");
  await expect(list).toBeVisible();

  // The stat strip (the six KPI cells) ends with a bottom divider. The list must start at/below that edge
  // AND carry the intended top offset (paddingTop) so it visually clears the divider.
  const stripCell = page.getByText("Critical paths", { exact: true }).locator("xpath=../..");
  const stripBox = await stripCell.boundingBox();
  const listBox = await list.boundingBox();
  expect(stripBox).not.toBeNull();
  expect(listBox).not.toBeNull();
  // The list top sits at or below the KPI strip's bottom (no overlap with the divider).
  expect(listBox!.y).toBeGreaterThanOrEqual(stripBox!.y + stripBox!.height - 2);
  // The top offset is present in the served bundle (computed padding-top ≥ the nudge).
  const padTop = await list.evaluate((el) => parseFloat(getComputedStyle(el).paddingTop || "0"));
  expect(padTop).toBeGreaterThanOrEqual(10);
});
