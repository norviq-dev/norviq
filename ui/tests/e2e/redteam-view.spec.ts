// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Red Team view, end-to-end on the REAL app + engine. Drives the nav → runs the attack suite against
// the deployed posture → proves the scorecard, per-attack rows, per-technique breakdown, and run HISTORY all
// render from the durable backend. Reloading the page keeps the results (durable, not in-memory), and
// the run's proven-blocking % matches what /api/v1/redteam/results/latest reports (no fabricated number).

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

// FAIL LOUDLY ON A NON-2xx. These helpers used to return `r.json()` and drop the status, so a 401
// (expired token), a 429 (rate-limited) and a 500 all arrived as a body with no `results` — and the
// assertion downstream reported "got 0" or "element(s) not found". Whole runs were mis-triaged as
// missing fixtures or product defects on the strength of that. A 409 is EXPECTED here (the
// per-namespace concurrent guard) so it is passed through for the retry loop to handle.
async function apiJson(page: Page, path: string): Promise<any> {
  const { status, body } = await page.evaluate(async (path) => {
    const t = localStorage.getItem("nrvq_token");
    const r = await fetch(path, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return { status: r.status, body: await r.json().catch(() => null) };
  }, path);
  if (status >= 400 && status !== 409) {
    throw new Error(`GET ${path} -> HTTP ${status}: ${JSON.stringify(body)?.slice(0, 200)}`);
  }
  return body;
}

test.describe("Red Team view runs the suite + renders durable efficacy (real engine)", () => {
  test("nav → run suite → scorecard/attacks/history render and survive a reload", async ({ page }) => {
    // reach the view via the TESTING nav (proves the route + nav item ship)
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByRole("heading", { name: "Red Team" })).toBeVisible();

    // run the suite against the deployed posture
    await page.getByTestId("redteam-run").click();
    // the scorecard appears once the run completes + persists
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });

    // the proven-blocking % rendered on screen matches the durable API (no fabricated number)
    const apiLatest = await apiJson(page, "/api/v1/redteam/results/latest");
    expect(apiLatest.has_run).toBe(true);
    const pct = `${apiLatest.efficacy.overall.proven_blocking_pct}%`;
    await expect(page.getByTestId("redteam-proven-pct")).toHaveText(pct);

    // per-attack rows + per-technique breakdown + history all render from the payload
    expect((await page.getByTestId("redteam-attack-row").count())).toBeGreaterThan(0);
    expect((await page.getByTestId("redteam-breakdown-row").count())).toBeGreaterThan(0);
    expect((await page.getByTestId("redteam-history-row").count())).toBeGreaterThan(0);

    // DURABLE: reload → the scorecard is still there (read from redteam_runs, not in-memory state)
    await page.reload();
    await waitForApp(page);
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 15000 });
    await expect(page.getByTestId("redteam-proven-pct")).toHaveText(pct);

    // evidence link points at the Audit log
    const firstAudit = page.getByTestId("redteam-attack-row").first().getByRole("link", { name: "Audit" });
    await expect(firstAudit).toHaveAttribute("href", /\/audit\?rule=/);
  });
});
