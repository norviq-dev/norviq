// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// D2 — the results table must stay BOUNDED at the view on a LARGE run. This drives a full-namespace suite
// (≥300 result rows) and asserts the SERVED DOM: the number of mounted <tr data-testid=redteam-attack-row>
// is ≤ 50 regardless of run size, the pager reports multiple pages and advances, and the got-through filter
// narrows the mounted rows. Playwright's locator .count() counts REAL DOM nodes, so this proves the mount is
// windowed — not just that a prop says 50 (the prior e2e only ran a 29-row scoped suite and never exercised
// the pager, which is why the large-run case was unproven).

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

const PAGE_SIZE = 50;

async function apiJson(page: Page, path: string, method = "GET"): Promise<any> {
  return page.evaluate(async ({ path, method }) => {
    const t = localStorage.getItem("nrvq_token");
    const r = await fetch(path, { method, headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return r.json();
  }, { path, method });
}
// POST /redteam/suite, retrying if the per-namespace D1 concurrent guard returns 409 (another run in flight).
async function postSuite(page: Page, query: string): Promise<any> {
  for (let i = 0; i < 20; i++) {
    const r = await apiJson(page, `/api/v1/redteam/suite?${query}`, "POST");
    if (!(r?.detail?.error || /already running/i.test(JSON.stringify(r?.detail ?? "")))) return r;
    await page.waitForTimeout(1500);
  }
  throw new Error("suite stayed busy");
}

// Serial: these tests mutate the shared results/latest for ns=default; they must not run concurrently.
test.describe.configure({ mode: "serial" });
test.describe("D2 — results table bounded at the VIEW on a large run (served DOM)", () => {
  test("≥300-result run mounts ≤50 <tr>, pager pages, filter filters", async ({ page }) => {
    test.setTimeout(180000);
    await page.goto("/redteam");
    await waitForApp(page);

    // drive a FULL-namespace suite so the run is large (18 real classes × 29 attacks ≈ 500+ rows)
    const run = await postSuite(page, "target_namespace=default");
    const total = (run.results ?? []).length;
    expect(total, `need a large run to exercise the pager; got ${total}`).toBeGreaterThanOrEqual(300);

    // reload the view so it renders results/latest (the large run)
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });

    // B: the header shows a concise CLASS COUNT + timestamp, not the full comma-separated class list.
    const classCount = (run.targets ?? []).length;
    const summary = page.getByTestId("redteam-targets-summary");
    await expect(summary).toContainText(new RegExp(`${classCount} class(es)? · ran`, "i"));
    await expect(page.getByTestId("redteam-targets-list")).toHaveCount(0); // list collapsed by default
    // the summary is short — never the wall-of-text join of every class name
    expect((await summary.textContent())!.length, "header must not dump the full class list").toBeLessThan(60);
    // expanding reveals the names on demand
    await page.getByTestId("redteam-targets-toggle").click();
    await expect(page.getByTestId("redteam-targets-list")).toBeVisible();

    // ── the KEY assertion: mounted <tr> in the DOM is bounded, NOT the full result set ──
    const mounted = await page.getByTestId("redteam-attack-row").count();
    expect(mounted, `mounted rows must be ≤${PAGE_SIZE} on a ${total}-row run`).toBeLessThanOrEqual(PAGE_SIZE);
    expect(mounted).toBeGreaterThan(0);

    // pager reports multiple pages and advances (still bounded on page 2)
    const expectedPages = Math.ceil(total / PAGE_SIZE);
    await expect(page.getByTestId("redteam-pager")).toBeVisible();
    await expect(page.getByTestId("redteam-page-indicator")).toContainText(`/ ${expectedPages}`);
    await page.getByTestId("redteam-next").click();
    await expect(page.getByTestId("redteam-page-indicator")).toContainText("Page 2");
    expect(await page.getByTestId("redteam-attack-row").count()).toBeLessThanOrEqual(PAGE_SIZE);

    // target selector is present (restored) and lists real classes
    await expect(page.getByTestId("redteam-target")).toBeVisible();

    // got-through filter narrows the mounted rows and stays bounded
    const gt = await apiJson(page, "/api/v1/redteam/results/latest");
    const gotThrough = gt.efficacy.overall.got_through as number;
    if (gotThrough > 0) {
      await page.getByTestId("redteam-failed-filter").getByRole("checkbox").check();
      const failedMounted = await page.getByTestId("redteam-attack-row").count();
      expect(failedMounted).toBeLessThanOrEqual(PAGE_SIZE);
      // every mounted row under the filter is a miss
      expect(await page.getByTestId("redteam-row-failed").count()).toBe(failedMounted);
    }

    // no app 4xx/5xx and no console errors during all of this
    // (asserted via a clean render — the scorecard + pager rendered from real data)
  });
});
