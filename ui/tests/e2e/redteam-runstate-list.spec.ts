// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Red Team run-state + list performance, end-to-end on the REAL app + engine.
//  Run suite → the button shows an in-flight state (disabled + aria-busy + "Running…"); a rapid
//      double-click fires exactly ONE POST /redteam/suite (client one-submit guard + backend 409 guard).
//  The results table is scoped to the run and paginated — mounted rows stay bounded (≤50) even for a
//      large run; the got-through filter lists exactly the scorecard's "Got through" rows; the roll-up
//      stays pinned above.

import { test, expect, waitForApp } from "./fixtures";

const PAGE_SIZE = 50; // RedTeam.tsx PAGE_SIZE — the most result rows the table mounts at once

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
    expect(rowCount).toBeLessThanOrEqual(PAGE_SIZE);

    // The got-through filter lists EXACTLY the rows the scorecard counted, whatever that number is.
    //
    // This used to assert only "> 0 rows, all red" when the scorecard was above zero, and it flaked: the
    // scorecard counts the server's verdict, while the table re-derived one from `passed`. A throttled
    // block (`rate_limit_exceeded` — 17 of them in the kind cluster's audit_log) passes and is a
    // got-through, so on a run that happened to be throttled the scorecard read N and the filter listed
    // none. Rows now carry the server's `outcome`, and the count must match both ways — including zero.
    // `toHaveCount` auto-waits for the filtered re-render instead of sampling it once.
    const scored = parseInt((await page.getByTestId("redteam-gotthrough").textContent())?.replace(/\D/g, "") || "0", 10);
    await page.getByTestId("redteam-failed-filter").getByRole("checkbox").check();
    const mounted = Math.min(scored, PAGE_SIZE);
    await expect(page.getByTestId("redteam-row-failed")).toHaveCount(mounted);
    if (scored > 0) {
      await expect(page.getByTestId("redteam-attack-row")).toHaveCount(mounted);
    } else {
      await expect(page.getByTestId("redteam-attack-row")).toHaveCount(0);
      await expect(page.getByTestId("redteam-attacks")).toContainText("No matching results.");
    }
    // Past one page the pager carries the rest; its total must still be the scorecard's number.
    if (scored > PAGE_SIZE) {
      await expect(page.getByTestId("redteam-pager")).toContainText(`of ${scored}`);
    } else {
      await expect(page.getByTestId("redteam-pager")).toHaveCount(0);
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
