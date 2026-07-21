// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// RANGE SELECTOR — scope + active state. Drives the REAL SPA on the live kind build.
// The header range chips are GONE on current-state pages (Policy Catalog/Packs/Target Settings) and on pages
//     with their own in-page range picker (Compliance/Attack Graph/Asset Graph); present on Overview + Audit.
// The selected chip has a visible active state (aria-pressed=true), distinct from the inactive chips.
// On Overview, switching 24h→1h actually refetches and the Total Calls value changes (1h ≠ 24h).

import { test, expect, waitForApp } from "./fixtures";

test.describe("Header range selector — scoped to time-series routes, active chip, real refetch", () => {
  test.beforeEach(async ({ page }) => { await page.goto("/"); await waitForApp(page); });

  test("range selector is HIDDEN on current-state + own-range pages, SHOWN on Overview + Audit", async ({ page }) => {
    const bad: string[] = [];
    page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${r.url()}`); });

    // Shown where the global range drives the page.
    await expect(page.getByTestId("time-range")).toBeVisible();            // Overview
    await page.goto("/audit"); await waitForApp(page);
    await expect(page.getByTestId("time-range")).toBeVisible();            // Audit
    await page.goto("/compliance"); await waitForApp(page);
    await expect(page.getByTestId("time-range")).toBeVisible();            // Compliance IS range-scoped

    // Hidden on current-state + own-range pages (NOT Compliance anymore).
    for (const path of ["/policies/catalog", "/policies/packs", "/policies/targets", "/threats/graph", "/asset-graph"]) {
      await page.goto(path); await waitForApp(page); await page.waitForTimeout(400);
      await expect(page.getByTestId("time-range"), `range selector must be hidden on ${path}`).toHaveCount(0);
      // and no clickable 24h chip either
      await expect(page.getByTestId("range-chip-24h")).toHaveCount(0);
    }
    expect(bad, `unexpected 4xx/5xx: ${bad.join(", ")}`).toEqual([]);
  });

  test("the selected range chip is ACTIVE (aria-pressed=true) and the others are not", async ({ page }) => {
    // default is 24h
    await expect(page.getByTestId("range-chip-24h")).toHaveAttribute("aria-pressed", "true");
    for (const r of ["1h", "6h", "7d", "30d"]) {
      await expect(page.getByTestId(`range-chip-${r}`)).toHaveAttribute("aria-pressed", "false");
    }
    // clicking 7d moves the active state
    await page.getByTestId("range-chip-7d").click();
    await expect(page.getByTestId("range-chip-7d")).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByTestId("range-chip-24h")).toHaveAttribute("aria-pressed", "false");
    // active chip resolves to the teal accent, not the muted inactive color (computed RGB check)
    const activeBg = await page.getByTestId("range-chip-7d").evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(activeBg).toBe("rgb(45, 218, 184)"); // --accent #2ddab8
  });

  test("switching range on Overview actually refetches — 1h total ≠ 24h total", async ({ page }) => {
    // read the two totals straight from the API the page uses (no-mock anchor)
    const stat = async (range: string) => page.evaluate(async (range) => {
      const t = localStorage.getItem("nrvq_token");
      const r = await fetch(`/api/v1/audit/stats?range=${range}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
      return (await r.json())?.total ?? 0;
    }, range);
    const t1h = await stat("1h"), t24h = await stat("24h");
    expect(t24h).toBeGreaterThan(t1h);   // 24h window strictly contains 1h → more calls

    // drive it in the UI: default 24h renders the larger number; clicking 1h refetches to the smaller one.
    const fmt = (n: number) => n.toLocaleString("en-US");
    await page.getByTestId("range-chip-24h").click();
    await expect(page.getByText(fmt(t24h), { exact: false }).first()).toBeVisible({ timeout: 8000 });
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/v1/audit/stats") && r.url().includes("range=1h")),
      page.getByTestId("range-chip-1h").click()
    ]);
    expect(resp.ok()).toBeTruthy();
    await expect(page.getByText(fmt(t1h), { exact: false }).first()).toBeVisible({ timeout: 8000 });
  });
});
