// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Run lifecycle / retention, end-to-end on the REAL app + engine.
//  • History view + endpoint return SUMMARIES ONLY — zero per-attack rows in the history panel; the
//    /redteam/results list carries no `results` field per run.
//  • Retention SAFETY: after K+1 runs (K=3 detail window), an OLD run is detail-pruned (detail_pruned=true,
//    empty results) while its SUMMARY survives, and results/latest ALWAYS returns full detail.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function apiJson(page: Page, path: string, method = "GET"): Promise<any> {
  return page.evaluate(async ({ path, method }) => {
    const t = localStorage.getItem("nrvq_token");
    const r = await fetch(path, { method, headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return r.json();
  }, { path, method });
}
// POST /redteam/suite, retrying past the per-namespace concurrent guard (409 → run already in flight).
async function postSuite(page: Page, query: string): Promise<any> {
  for (let i = 0; i < 20; i++) {
    const r = await apiJson(page, `/api/v1/redteam/suite?${query}`, "POST");
    if (!(r?.detail?.error || /already running/i.test(JSON.stringify(r?.detail ?? "")))) return r;
    await page.waitForTimeout(1500);
  }
  throw new Error("suite stayed busy");
}

// Serial: these tests mutate the shared results/latest + run history for ns=default.
test.describe.configure({ mode: "serial" });
test.describe("run retention (summary-only history + detail-prune safety)", () => {
  test("history view + endpoint are summary-only (no per-attack detail rows)", async ({ page }) => {
    await page.goto("/redteam");
    await waitForApp(page);
    // ensure at least one run exists (scoped = fast)
    await postSuite(page, "target_agent=customer-support&target_namespace=default");
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByTestId("redteam-history")).toBeVisible({ timeout: 20000 });

    // the history PANEL shows summary rows but ZERO per-attack detail rows
    const historyPanel = page.getByTestId("redteam-history");
    await expect(historyPanel.getByTestId("redteam-history-row").first()).toBeVisible();
    expect(await historyPanel.getByTestId("redteam-attack-row").count()).toBe(0);

    // the history ENDPOINT carries summaries only — no `results` array on any run
    const hist = await apiJson(page, "/api/v1/redteam/results?limit=10");
    expect(Array.isArray(hist.runs)).toBeTruthy();
    expect(hist.runs.every((r: any) => !("results" in r))).toBeTruthy();
    expect(hist).toHaveProperty("total");
    expect(hist).toHaveProperty("offset");
  });

  test("SAFETY: K+1 runs → an old run's detail is pruned (summary kept), results/latest stays full", async ({ page }) => {
    test.setTimeout(120000);
    await page.goto("/redteam");
    await waitForApp(page);

    // fire 4 scoped runs (K=3 detail window) so the oldest ages out of the DETAIL tier by count
    const ids: string[] = [];
    for (let i = 0; i < 4; i++) {
      const r = await postSuite(page, "target_agent=customer-support&target_namespace=default");
      ids.push(r.run_id);
    }

    // the FIRST (oldest) of the four is now beyond the detail window → detail-pruned, summary intact
    const oldest = await apiJson(page, `/api/v1/redteam/results/${ids[0]}`);
    expect(oldest.detail_pruned, "oldest run should be detail-pruned after K+1 runs").toBe(true);
    expect(oldest.results).toEqual([]);
    expect(oldest.efficacy.overall).toHaveProperty("proven_blocking_pct"); // summary survives

    // results/latest is ALWAYS full detail (never pruned)
    const latest = await apiJson(page, "/api/v1/redteam/results/latest");
    expect(latest.has_run).toBe(true);
    expect(latest.detail_pruned).toBeFalsy();
    expect((latest.results ?? []).length).toBeGreaterThan(0);
  });

  test("DETAIL_KEEP=1 → after just 2 runs the immediately-PRIOR run is detail-pruned (only latest full)", async ({ page }) => {
    test.setTimeout(90000);
    await page.goto("/redteam");
    await waitForApp(page);

    // two runs is enough with the last-run-only default (K=1): run #1 becomes the prior → detail-pruned
    const first = await postSuite(page, "target_agent=customer-support&target_namespace=default");
    const second = await postSuite(page, "target_agent=customer-support&target_namespace=default");

    const prior = await apiJson(page, `/api/v1/redteam/results/${first.run_id}`);
    expect(prior.detail_pruned, "with K=1 the prior run must be detail-pruned after the 2nd run").toBe(true);
    expect(prior.results).toEqual([]);
    expect(prior.efficacy.overall).toHaveProperty("proven_blocking_pct"); // summary intact

    const latest = await apiJson(page, `/api/v1/redteam/results/${second.run_id}`);
    expect(latest.detail_pruned).toBeFalsy();
    expect((latest.results ?? []).length).toBeGreaterThan(0);
    // results/latest == the second run, full detail
    const rl = await apiJson(page, "/api/v1/redteam/results/latest");
    expect(rl.run_id).toBe(second.run_id);
    expect(rl.detail_pruned).toBeFalsy();
  });
});
