// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// UI polish — four visual outcomes proven on the live build:
//  The Overview coverage caption sits BELOW the gauge arc (no overlap with the number/arc).
//  Policy Packs lay out as a horizontal rail (overflow-x auto, cards side-by-side), actions intact.
//  The RedTeam scorecard metric cluster is UNBOXED (no --bg-surface/--border) + nudged right; values==latest.
//  Compliance framework cards carry no "coverage steady" trend line.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

// Read a GET endpoint from the page, carrying the real session token, and FAIL LOUDLY on a non-2xx.
// Returning `res.json()` and dropping the status is how a 401 or a 429 arrives downstream as a body
// with no fields and the assertion reports "undefined" — which mis-triaged whole runs in this repo.
async function apiJson(page: Page, path: string): Promise<any> {
  const { status, body } = await page.evaluate(async (p) => {
    const t = localStorage.getItem("nrvq_token");
    const res = await fetch(p, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
  if (status >= 400) throw new Error(`GET ${path} -> HTTP ${status}: ${JSON.stringify(body)?.slice(0, 200)}`);
  return body;
}

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

test.describe("Overview coverage caption sits below the gauge (no overlap)", () => {
  test("the score-gauge-caption is below the number and out of the arc; text preserved", async ({ page, recorder }) => {
    await page.goto("/");
    await waitForApp(page);
    const caption = page.getByTestId("score-gauge-caption");
    const value = page.getByTestId("score-gauge-value");
    const chart = page.locator(".chart-box").first();
    await expect(caption).toBeVisible({ timeout: 15000 });
    await expect(value).toBeVisible();

    const capBox = (await caption.boundingBox())!;
    const valBox = (await value.boundingBox())!;
    const chartBox = (await chart.boundingBox())!;
    // the caption is strictly BELOW the big number — they do not overlap
    expect(capBox.y, "caption must sit below the % number").toBeGreaterThanOrEqual(valBox.y + valBox.height - 2);
    // …and it clears the arc entirely (the half-gauge arc ends near 90% of the canvas height + roundcap) so no
    // caption text is superimposed on the donut.
    expect(capBox.y, "caption must be below the gauge arc").toBeGreaterThanOrEqual(chartBox.y + chartBox.height * 0.88);
    // the caption text is still present (moved, not dropped)
    await expect(caption).toContainText(/rules present/i);
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });
});

test.describe("Policy Packs flat side-by-side grid", () => {
  test("all packs render in ONE flat grid (~4 per row, side-by-side), actions intact, no page clip", async ({ page, recorder }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    // `?ns=` matters. The default scope is "all", where every mutation is DELIBERATELY disabled
    // ("Select a namespace to apply changes.") — a pack has to land somewhere, so applying one across
    // an unspecified set is refused. This spec asserts the pack actions are intact, which is only a
    // meaningful question once a concrete namespace is selected. `packs-governance-batch1.spec.ts`
    // asserts the disabled-at-all behaviour and passes, so this is not a product bug to fix; it is
    // this spec asking its question in the one scope where the answer is always "no".
    await page.goto("/policies/packs?ns=default");
    await waitForApp(page);
    await expect(page.getByText("Sector Starter Packs")).toBeVisible({ timeout: 15000 });

    // a SINGLE flat grid holds every pack (not one rail per sector).
    const rails = page.getByTestId("pack-rail");
    await expect(rails).toHaveCount(1);
    const rail = rails.first();
    const display = await rail.evaluate((el) => getComputedStyle(el).display);
    expect(display, "the packs container must be a grid").toBe("grid");

    // cards sit side-by-side: the first FOUR cards share (approximately) the same top (4-up row).
    const cards = rail.locator(":scope > .panel");
    const n = await cards.count();
    expect(n, "the grid has multiple cards").toBeGreaterThanOrEqual(4);
    const tops = await cards.evaluateAll((els) => els.slice(0, 4).map((e) => Math.round(e.getBoundingClientRect().top)));
    const rowSpread = Math.max(...tops) - Math.min(...tops);
    expect(rowSpread, "the first four cards form one row (side-by-side)").toBeLessThanOrEqual(4);
    const xs = await cards.evaluateAll((els) => els.slice(0, 4).map((e) => Math.round(e.getBoundingClientRect().left)));
    expect(xs[1] > xs[0] && xs[2] > xs[1] && xs[3] > xs[2], "cards flow left→right in the row").toBe(true);

    // the page does not clip horizontally.
    const bodyClip = await page.evaluate(() => document.body.scrollWidth - document.body.clientWidth);
    expect(bodyClip, "the page must not clip horizontally").toBeLessThanOrEqual(1);

    // a non-mutating action still works: View rego opens the read-only rego drawer.
    const viewRego = page.getByRole("button", { name: /View rego/i }).first();
    await expect(viewRego).toBeVisible();
    await viewRego.click();
    await expect(page.getByText(/Pack rego —/i)).toBeVisible({ timeout: 10000 });
    // the admin toggle (Enable/Disable) is present + enabled (mutating action wired, not exercised here).
    await expect(page.getByRole("button", { name: /^(Enable|Disable)$/ }).first()).toBeEnabled();
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });
});

test.describe.configure({ mode: "serial" });
test.describe("RedTeam scorecard metric cluster is unboxed + nudged right", () => {
  test("cluster has no box (transparent bg, no border) + positive left margin; values==latest; no overlap/clip", async ({ page }) => {
    test.setTimeout(120000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/redteam");
    await waitForApp(page);
    // READ the newest run rather than starting another one. `ui-batch-a.spec.ts:53` already POSTs an
    // identical suite (same target, same namespace) — these two are copy-paste twins asserting
    // different CSS against the same cluster. Each suite POST costs ~12s, fans out over every agent
    // class, and `redteam_detail_keep_runs = 1` means it PRUNES the previous run's detail rows, so the
    // duplicate was actively destroying the fixture other red-team specs read. The assertions here are
    // about the scorecard's layout and its agreement with the latest run; `results/latest` is that run.
    const run = await apiJson(page, "/api/v1/redteam/results/latest?namespace=default");
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });
    const cluster = page.getByTestId("redteam-metric-cluster");
    await expect(cluster).toBeVisible();

    // UNBOXED: no --bg-surface fill, no border, and nudged right (positive left margin)
    const box = await cluster.evaluate((el) => {
      const s = getComputedStyle(el);
      return { bg: s.backgroundColor, borderTop: s.borderTopWidth, borderStyle: s.borderTopStyle, ml: parseFloat(s.marginLeft) };
    });
    expect(["rgba(0, 0, 0, 0)", "transparent"], "cluster must have no --bg-surface fill").toContain(box.bg);
    expect(box.borderTop === "0px" || box.borderStyle === "none", "cluster must have no border box").toBeTruthy();
    expect(box.ml, "cluster must be nudged right").toBeGreaterThan(0);

    // values still map from results/latest
    await expect(page.getByTestId("redteam-gotthrough")).toContainText(String(run.efficacy.overall.got_through));
    await expect(cluster).toContainText(String(run.efficacy.overall.caught));
    await expect(cluster).toContainText(`${run.pass_rate}%`);

    // no overlap/clip at desktop then narrow
    const noOverlapNoClip = async () => {
      const clip = await cluster.evaluate((el) => el.scrollWidth - el.clientWidth);
      expect(clip, "cluster must not clip horizontally").toBeLessThanOrEqual(1);
      const boxes = await cluster.locator(":scope > div").evaluateAll((els) =>
        els.map((e) => { const r = e.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; })
      );
      for (let i = 0; i < boxes.length; i++)
        for (let j = i + 1; j < boxes.length; j++) {
          const a = boxes[i], b = boxes[j];
          expect(a.l < b.r && b.l < a.r && a.t < b.b && b.t < a.b, `stat cells ${i},${j} overlap`).toBeFalsy();
        }
    };
    await noOverlapNoClip();
    await page.setViewportSize({ width: 720, height: 900 });
    await page.waitForTimeout(300);
    await noOverlapNoClip();
  });
});

test.describe("Compliance framework cards have no 'coverage steady' line", () => {
  test("no 'coverage steady' text on the framework cards; counts + donut intact", async ({ page, recorder }) => {
    await page.goto("/compliance");
    await waitForApp(page);
    await expect(page.getByText("MITRE ATLAS")).toBeVisible({ timeout: 15000 });
    // the framework cards render (donut %, counts) but no trend "coverage steady" line
    await expect(page.getByText(/coverage steady/i)).toHaveCount(0);
    await expect(page.getByText(/enforced/i).first()).toBeVisible(); // counts still there
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });
});
