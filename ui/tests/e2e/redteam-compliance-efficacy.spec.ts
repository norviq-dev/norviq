// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The Red Team efficacy is wired INTO Compliance + Overview. After a real suite run, Compliance shows
// "X% proven-blocking (last run)" and the Overview coverage caption upgrades from "not efficacy-tested" to the
// same proven-blocking number — both matching /api/v1/redteam/results/latest (no fabricated value).
//
// CRITICAL coexistence: the Compliance page must show BOTH the restored header range
// selector AND the efficacy banner at the same time — this test asserts both are present together.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function api(page: Page, path: string, method = "GET"): Promise<any> {
  return page.evaluate(async ({ path, method }) => {
    const t = localStorage.getItem("nrvq_token");
    const r = await fetch(path, { method, headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return r.json();
  }, { path, method });
}

test.describe("Red Team efficacy wired into Compliance + Overview", () => {
  test("after a run, Compliance shows proven-blocking % (with the range selector) and Overview matches", async ({ page }) => {
    test.setTimeout(120000);
    await page.goto("/");
    await waitForApp(page);

    // ensure a durable run exists, then read the proven-blocking % straight from the API (no-mock anchor).
    // Scope to a single class so the run is fast + deterministic (the full-namespace suite is 2800+ evals).
    await api(page, "/api/v1/redteam/suite?target_agent=customer-support&target_namespace=default", "POST");
    const latest = await api(page, "/api/v1/redteam/results/latest");
    expect(latest.has_run).toBe(true);
    const pct = `${latest.efficacy.overall.proven_blocking_pct}% proven-blocking`;

    // COMPLIANCE: the banner shows the proven-blocking %, AND the header range selector is present together
    await page.goto("/compliance");
    await waitForApp(page);
    const banner = page.getByTestId("compliance-efficacy-banner");
    await expect(banner).toBeVisible();
    await expect(banner.getByTestId("compliance-proven-blocking")).toContainText(pct);
    // Coexistence: the restored header range selector still renders on Compliance
    await expect(page.getByTestId("time-range")).toBeVisible();
    await expect(page.getByTestId("range-chip-24h")).toBeVisible();

    // OVERVIEW: the coverage caption upgrades to the same proven-blocking number (not the
    // "not efficacy-tested" placeholder).
    //
    // The caption gained its DENOMINATOR in F-023 and this assertion was never updated. Dashboard.tsx
    // now renders "rules present · N% proven-blocking of T evaluate-reachable red-team attacks (last
    // run)", so a regex demanding "N% proven-blocking (last run)" contiguously could never match —
    // the words it needs adjacent have the subject of the whole change sitting between them.
    //
    // Asserting the denominator too, because that is the point of F-023: a bare "100%" reads as total
    // coverage when it is efficacy over the evaluate-reachable subset, and the Compliance page for the
    // same posture honestly says 80% ATLAS with named gaps. Both numbers come from the same live
    // payload, so a fabricated percentage OR a mismatched subset size now fails. Scoped to the gauge
    // caption's own testid rather than a page-wide text match, which would also match every ancestor.
    await page.goto("/");
    await waitForApp(page);
    const overall = latest.efficacy.overall;
    await expect(page.getByTestId("score-gauge-caption")).toContainText(
      `${overall.proven_blocking_pct}% proven-blocking of ${overall.total} evaluate-reachable red-team attacks (last run)`,
      { timeout: 10000 }
    );
  });
});
