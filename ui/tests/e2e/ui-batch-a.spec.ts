// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A4 — the Overview "Policy Coverage" caption must NOT compute to block-red (#ff3b5c / rgb(255,59,92)); that
//      hue is reserved for real block decisions. A5 — the RedTeam scorecard secondary metrics render as a
//      grouped, evenly-spaced cluster (no overlap/clip) at desktop AND narrow widths, values from results/latest.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

const BLOCK_RED = "rgb(255, 59, 92)";

async function postSuite(page: Page, query: string): Promise<any> {
  for (let i = 0; i < 20; i++) {
    const r = await page.evaluate(async (q) => {
      const t = localStorage.getItem("nrvq_token");
      const res = await fetch(`/api/v1/redteam/suite?${q}`, { method: "POST", headers: t ? { Authorization: `Bearer ${t}` } : {} });
      return res.json();
    }, query);
    if (!(r?.detail?.error || /already running/i.test(JSON.stringify(r?.detail ?? "")))) return r;
    await page.waitForTimeout(1500);
  }
  throw new Error("suite stayed busy");
}

test.describe("A4 — Overview Policy Coverage caption is neutral, not block-red", () => {
  test("the coverage caption color ∉ block-red; a real block decision badge stays red", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    const caption = page.getByTestId("score-gauge-caption");
    await expect(caption).toBeVisible({ timeout: 15000 });
    const color = await caption.evaluate((el) => getComputedStyle(el).color);
    expect(color, "coverage caption must be neutral, not block-red").not.toBe(BLOCK_RED);

    // meanwhile a REAL block signal is still red — the Audit log's block decision badges resolve to block-red
    await page.goto("/audit");
    await waitForApp(page);
    const blockBadge = page.locator('[data-testid="decision-badge"], .decision-badge, [class*="badge"]').filter({ hasText: /block/i }).first();
    if (await blockBadge.count()) {
      const bg = await blockBadge.evaluate((el) => getComputedStyle(el).color + "|" + getComputedStyle(el).backgroundColor + "|" + getComputedStyle(el).borderColor);
      expect(bg, "a real block label should still use block-red somewhere").toContain("255, 59, 92");
    }
  });
});

test.describe.configure({ mode: "serial" });
test.describe("A5 — RedTeam scorecard metrics are a spaced grouped cluster (desktop + narrow)", () => {
  test("cluster renders spaced, no overlap/clip at 1440 and 720; values == results/latest", async ({ page }) => {
    test.setTimeout(120000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/redteam");
    await waitForApp(page);
    const run = await postSuite(page, "target_agent=customer-support&target_namespace=default");
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });

    const cluster = page.getByTestId("redteam-metric-cluster");
    await expect(cluster).toBeVisible();

    // values map straight from results/latest (layout-only change)
    await expect(page.getByTestId("redteam-gotthrough")).toContainText(String(run.efficacy.overall.got_through));
    await expect(cluster).toContainText(String(run.efficacy.overall.caught));
    await expect(cluster).toContainText(`${run.pass_rate}%`);

    // no overlap between the four stat cells + no horizontal clip, at desktop then narrow
    const noOverlapNoClip = async () => {
      const clip = await cluster.evaluate((el) => el.scrollWidth - el.clientWidth);
      expect(clip, "cluster must not clip horizontally").toBeLessThanOrEqual(1);
      const boxes = await page.getByTestId("redteam-metric-cluster").locator(":scope > div").evaluateAll((els) =>
        els.map((e) => { const r = e.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; })
      );
      for (let i = 0; i < boxes.length; i++) {
        for (let j = i + 1; j < boxes.length; j++) {
          const a = boxes[i], b = boxes[j];
          const overlap = a.l < b.r && b.l < a.r && a.t < b.b && b.t < a.b;
          expect(overlap, `stat cells ${i} and ${j} must not overlap`).toBeFalsy();
        }
      }
    };
    await noOverlapNoClip();
    await page.setViewportSize({ width: 720, height: 900 });
    await page.waitForTimeout(300);
    await noOverlapNoClip();
  });
});
