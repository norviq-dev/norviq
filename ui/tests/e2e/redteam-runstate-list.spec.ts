// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Red Team run-state + list performance, end-to-end on the REAL app + engine.
//  Run suite → the button shows an in-flight state (disabled + aria-busy + "Running…"); a rapid
//      double-click fires exactly ONE POST /redteam/suite (client one-submit guard + backend 409 guard).
//  The results table is scoped to the run and paginated — mounted rows stay bounded (≤50) even for a
//      large run; the got-through filter surfaces misses; the roll-up stays pinned above.

import { test, expect, waitForApp } from "./fixtures";

test.describe("Red Team run-state + bounded results table", () => {
  test("run suite shows Running… + disabled, double-click fires ONE POST, table stays bounded", async ({ page }) => {
    test.setTimeout(120000);
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByRole("heading", { name: "Red Team" })).toBeVisible();

    // scope to a single class so the run is fast + deterministic
    await page.getByTestId("redteam-target").selectOption("customer-support");

    // count the actual POST /redteam/suite requests across the double-click
    let posts = 0;
    page.on("request", (r) => {
      if (r.method() === "POST" && r.url().includes("/api/v1/redteam/suite")) posts += 1;
    });
    // Deterministically hold the suite response ~1.5s so the in-flight state is observable regardless of how
    // fast the (scoped) run is — the request still reaches the backend, so the one-POST count is unaffected.
    await page.route("**/api/v1/redteam/suite**", async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.continue();
    });

    const runBtn = page.getByTestId("redteam-run");
    // Two clicks in the SAME tick — the synchronous one-submit guard must swallow the second. Done via a
    // single evaluate so both native clicks fire before React re-renders/disables (a real rapid double-click).
    await page.evaluate(() => {
      const b = document.querySelector('[data-testid="redteam-run"]') as HTMLButtonElement | null;
      b?.click();
      b?.click();
    });
    // in-flight state is visible
    await expect(runBtn).toBeDisabled();
    await expect(runBtn).toHaveAttribute("aria-busy", "true");
    await expect(runBtn).toContainText("Running…");

    // the run completes → scorecard renders, button re-enables
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });
    await expect(runBtn).toBeEnabled();

    // exactly ONE POST fired despite the double-click
    expect(posts, `expected exactly one POST /redteam/suite, saw ${posts}`).toBe(1);

    // The table is bounded — at most 50 rows mounted regardless of run size
    const rowCount = await page.getByTestId("redteam-attack-row").count();
    expect(rowCount).toBeLessThanOrEqual(50);

    // got-through filter is reachable and, when misses exist, narrows to only failed rows
    const gotThrough = await page.getByTestId("redteam-gotthrough").textContent();
    if (gotThrough && parseInt(gotThrough.replace(/\D/g, "") || "0", 10) > 0) {
      await page.getByTestId("redteam-failed-filter").getByRole("checkbox").check();
      const failedRows = await page.getByTestId("redteam-row-failed").count();
      expect(failedRows).toBeGreaterThan(0);
      expect(await page.getByTestId("redteam-attack-row").count()).toBe(failedRows);
    }

    // the per-technique roll-up stays pinned above the table
    await expect(page.getByTestId("redteam-by-technique")).toBeVisible();

    // no 4xx/5xx on the app's own API during all of this
    // (recorder is asserted by the shared fixture in other suites; here we assert the run itself was 200-clean
    //  by virtue of the scorecard rendering from results/latest)
  });

  test("a second concurrent suite POST for the same namespace is rejected 409 (backend guard)", async ({ page }) => {
    await page.goto("/redteam");
    await waitForApp(page);
    // fire two suite POSTs back-to-back via the API; the backend must serialize per namespace
    const result = await page.evaluate(async () => {
      const t = localStorage.getItem("nrvq_token");
      const h = { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) };
      const url = "/api/v1/redteam/suite?target_agent=customer-support&target_namespace=default";
      const [a, b] = await Promise.all([
        fetch(url, { method: "POST", headers: h }).then((r) => r.status),
        fetch(url, { method: "POST", headers: h }).then((r) => r.status)
      ]);
      return [a, b].sort();
    });
    // one succeeds (200), the other is rejected as a concurrent run (409) — never two concurrent 200s
    expect(result).toContain(409);
    expect(result).toContain(200);
  });
});
