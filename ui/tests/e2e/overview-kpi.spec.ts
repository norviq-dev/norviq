// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The Overview KPI cards must reflect the REAL /audit/stats numbers after a genuine form login + full
// reload (a token-injected / client-nav session gives false reads), and must NEVER be stuck at 0 while the API is
// non-zero. This spec does a REAL username/password login (no token injection), reloads the page 5×, and asserts
// each card's bound value equals /audit/stats for the active range on EVERY run; it also proves a warm-up {total:0}
// recovers to the real value (the exact bug), and that range switching re-binds.
//
// NOT using ./fixtures — that fixture injects an admin token on every nav, which would bypass the real login the
// spec is meant to exercise. Password comes from NRVQ_E2E_PASSWORD (the gate resets admin to a known value with
// must_change=false).

import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  // the app does a real window.location.replace("/") — a genuine full reload — after the sign-in.
  await page.waitForURL(/\/$/, { timeout: 20000 });
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible({ timeout: 15000 });
}

async function apiStats(page: Page, range: string): Promise<{ total: number; blocked: number; block_rate_pct: number; avg_latency_ms: number }> {
  return page.evaluate(async (r) => {
    // a real (non-"remember me") login stores the token in sessionStorage; fall back to localStorage.
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(`/api/v1/audit/stats?range=${r}`, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return res.json();
  }, range);
}

async function kpi(page: Page, id: string): Promise<number> {
  const v = await page.getByTestId(`${id}-value`).getAttribute("data-value");
  return Number(v);
}

async function activeRange(page: Page): Promise<string> {
  return (await page.locator(".range-chip.active").first().innerText()).trim();
}

test.describe("Overview KPI cards — real login + reload, never stuck at 0", () => {
  test("REAL form login + reload ×5: every card == /audit/stats for the active range; never 0 while API non-zero", async ({ page }) => {
    test.setTimeout(120000);
    const consoleErrors: string[] = [];
    page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
    const bad: string[] = [];
    page.on("response", (r) => {
      const u = r.url();
      if (u.includes("/api/v1") && r.status() >= 400) bad.push(`${r.status()} ${u}`);
    });

    await realLogin(page);

    for (let i = 0; i < 5; i++) {
      await page.reload();
      await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible({ timeout: 15000 });
      const range = await activeRange(page);
      const stats = await apiStats(page, range);
      // the cards bind the real numbers (poll for the retry/warm-up window to settle) — NEVER stuck at 0 when the
      // API is non-zero.
      await expect.poll(() => kpi(page, "kpi-total"), { timeout: 15000, message: `run ${i}: total must == ${stats.total}` }).toBe(stats.total);
      expect(await kpi(page, "kpi-blocked"), `run ${i}: blocked`).toBe(stats.blocked);
      expect(await kpi(page, "kpi-blockrate"), `run ${i}: block-rate`).toBe(Math.round(stats.block_rate_pct));
      // Avg-latency is the real avg_latency_ms from the same call.
      expect(await kpi(page, "kpi-latency"), `run ${i}: avg latency`).toBe(Math.round(stats.avg_latency_ms));
      if (stats.total > 0) expect(await kpi(page, "kpi-total"), `run ${i}: non-zero API must not render 0`).toBeGreaterThan(0);
    }

    expect(consoleErrors, `console errors: ${consoleErrors.join(", ")}`).toEqual([]);
    expect(bad, `4xx/5xx: ${bad.join(", ")}`).toEqual([]);
  });

  test("RECOVERY: landing on a 0-ish range then switching to one with data binds the real number (app's own fetch)", async ({ page }) => {
    await realLogin(page);
    const set = async (r: string) => {
      await page.locator(".range-chip", { hasText: new RegExp(`^${r}$`) }).first().click();
      // the card must equal the APP'S OWN /audit/stats for that range — a fresh fetch each switch, never stuck.
      await expect.poll(() => kpi(page, "kpi-total"), { timeout: 15000 }).toBe((await apiStats(page, r)).total);
    };
    await set("1h"); // genuinely empty → 0 (correct)
    const at1 = await kpi(page, "kpi-total");
    await set("7d"); // switch to a range WITH data — must recover from 0 to the real number
    const at7 = await kpi(page, "kpi-total");
    expect(at7, "7d must bind the real non-zero total, not stay stuck at 0").toBeGreaterThan(0);
    await set("1h"); // back to empty → 0 again (not a stale 7d value)
    await set("24h"); // and a third range with data re-binds
    const at24 = await kpi(page, "kpi-total");
    expect(at1).toBeLessThanOrEqual(at24);
    expect(at24).toBeLessThanOrEqual(at7);
  });

  test("NO STUCK under a SLOW first /audit/stats (real warm-up timing) — card binds the app's real fetch", async ({ page }) => {
    // Delay the app's OWN first /audit/stats (the REAL response passes through via route.continue — NOT a faked
    // value) to exercise the warm-up race that dropped the real response on 158c8ef. The card must still bind the
    // app's real number for the active range.
    let first = true;
    await page.route("**/api/v1/audit/stats**", async (route) => {
      if (first) { first = false; await new Promise((r) => setTimeout(r, 3000)); }
      await route.continue();
    });
    await realLogin(page);
    const range = await activeRange(page);
    const stats = await apiStats(page, range);
    await expect.poll(() => kpi(page, "kpi-total"), { timeout: 20000, message: "card must bind the app's real fetch despite a slow first response" }).toBe(stats.total);
    if (stats.total > 0) expect(await kpi(page, "kpi-total")).toBeGreaterThan(0);
  });
});
