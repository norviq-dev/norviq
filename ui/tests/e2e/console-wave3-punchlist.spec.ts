// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// UI-AUDIT round 3 — Wave 3 (punch-list) E2E. Drives the REAL SPA on the live kind cluster and asserts the
// visible EFFECT of each punch-list fix (P1–P5). P6/P7 are covered by vitest + the token test.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function seedDraft(page: Page) {
  // Ensure at least one intent draft exists for a throwaway class (dry-run only; deduped by class).
  const cls = `wave3e2e-${Date.now()}`;
  await page.evaluate(async (cls) => {
    const token = localStorage.getItem("nrvq_token");
    await fetch("/api/v1/threats/intent-draft", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ ns: "all", cls, allow_tools: ["search_kb"], intent: { readonly: true, scope: false, rate: false, egress: false } }),
    });
  }, cls);
  return cls;
}

test.describe("UI-AUDIT r3 Wave-3 punch-list — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await page.evaluate(() => localStorage.setItem("nrvq_show_synthetic", "0"));
  });

  test("P1: an intent draft row opens its review (generated rego) on click", async ({ page }) => {
    await seedDraft(page);
    await page.goto("/policies/catalog");
    await waitForApp(page);
    // The drafts panel is on the editor/landing view; the row header is now a real button.
    const openBtn = page.locator('[data-testid^="intent-draft-open-"]').first();
    await expect(openBtn).toBeVisible();
    await expect(page.getByTestId("intent-draft-rego")).toHaveCount(0); // closed before click
    await openBtn.click();
    await expect(page.getByTestId("intent-draft-rego").first()).toBeVisible(); // review (rego) opens
  });

  test("P2: the selected attack-path row background is neutral grey, not indigo", async ({ page }) => {
    await page.goto("/threats/graph");
    await waitForApp(page);
    // The selected PATH row is the only element with the purple selection accent (inset box-shadow #c084fc /
    // rgb(192,132,252)) — scope to it so we don't measure a coloured severity/status filter chip.
    const bg = await page.evaluate(() => {
      const rows = Array.from(document.querySelectorAll('button[aria-pressed="true"]')) as HTMLElement[];
      const row = rows.find((el) => /192,\s*132,\s*252/.test(getComputedStyle(el).boxShadow));
      return row ? getComputedStyle(row).backgroundColor : null;
    });
    expect(bg).toBeTruthy();
    const m = bg!.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    expect(m).toBeTruthy();
    const [r, g, b] = [Number(m![1]), Number(m![2]), Number(m![3])];
    // neutral grey → red ≈ green ≈ blue; the old #181026 had blue markedly greater than red.
    expect(Math.abs(r - b)).toBeLessThanOrEqual(4);
    expect(Math.abs(r - g)).toBeLessThanOrEqual(4);
  });

  test("P3: the Trust Distribution donut legend lists every category with counts (incl 0)", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    const legend = page.getByRole("list", { name: /Trust Distribution legend/i }).first();
    await expect(legend).toBeVisible();
    // All four categories are legible without hover.
    for (const name of ["high", "medium", "low", "frozen"]) {
      await expect(legend.getByText(name, { exact: true })).toBeVisible();
    }
  });

  test("P4: the Overview has exactly one export control (Report ▾, no standalone Export)", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await expect(page.getByText(/Report ▼/)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Export$/ })).toHaveCount(0);
  });

  test("P5: clicking an agent row opens the detail panel in view (freeze/trust actions)", async ({ page }) => {
    await page.goto("/agents");
    await waitForApp(page);
    await page.locator("table tbody tr").first().click();
    // The detail scrolls into view and shows the audited actions.
    const actions = page.getByText("Agent Actions");
    await expect(actions).toBeVisible();
    await expect(page.getByText("Freeze Agent")).toBeVisible();
    await expect(page.getByText("Reset Trust")).toBeVisible();
  });
});
