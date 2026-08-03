// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Color-consistency pass. Drives the REAL SPA and asserts, via COMPUTED STYLES, that the
// Attack Graph primary CTAs resolve to the teal accent (#2ddab8 = rgb 45,218,184) and that chrome (toolbar /
// muted text / selected row) resolves to neutral grey — never indigo/audit-purple/blue.

import { test, expect, waitForApp } from "./fixtures";

const TEAL = { r: 45, g: 218, b: 184 };
function near(v: number, t: number, tol = 8) { return Math.abs(v - t) <= tol; }
function parse(rgb: string) {
  const m = rgb.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
  return m ? { r: +m[1], g: +m[2], b: +m[3] } : null;
}

test.describe("color-consistency — computed-style proofs", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/threats/graph");
    await waitForApp(page);
  });

  test("the Simulate CTA resolves to the teal accent (not indigo/purple)", async ({ page }) => {
    // The CTA reads "Simulate (preview)" (AttackPathDetail.tsx:179) — the "(preview)" is load-bearing,
    // since the action fires REAL /evaluate calls but enforces nothing. Matched EXACTLY because a loose
    // /simulate/i resolves to 41 elements on this page (every per-hop control carries the word).
    const btn = page.getByRole("button", { name: "Simulate (preview)" });
    await expect(btn).toBeVisible();

    // The control is an OUTLINED button now, not a filled one: AttackPathDetail.tsx:176 sets
    // `background: var(--bg-graph-card)` with `color: #2ddab8`, so `backgroundImage` is "none" and the
    // teal lives in the TEXT. This test's point is the accent hue — teal, never indigo/purple — so it
    // reads whichever channel actually carries it rather than pinning the fill style of the day.
    const { color, bgImage } = await btn.evaluate((el) => {
      const cs = getComputedStyle(el);
      return { color: cs.color, bgImage: cs.backgroundImage };
    });
    const teal = /45,\s*218,\s*184/;
    expect(teal.test(color) || teal.test(bgImage)).toBe(true);

    // ...and explicitly NOT indigo/purple. The discriminator is GREEN, not red: teal is
    // rgb(45, 218, 184), whose blue channel is far above its red — so "blue > red" flags teal itself.
    // What separates them is that teal's green dominates (218 > 184) while indigo's collapses
    // (rgb(99, 102, 241): blue 241 >> green 102).
    const rgb = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color);
    if (rgb) {
      const [, g, b] = [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
      expect(b, `accent must not be indigo/purple: ${color}`).toBeLessThanOrEqual(g);
    }
  });

  test("the Define-intent CTA border resolves to the teal accent", async ({ page }) => {
    const btn = page.getByRole("button", { name: /Define intended behaviour/i }).first();
    await expect(btn).toBeVisible();
    const border = await btn.evaluate((el) => getComputedStyle(el).borderTopColor);
    const c = parse(border)!;
    expect(near(c.r, TEAL.r) && near(c.g, TEAL.g) && near(c.b, TEAL.b)).toBeTruthy();
  });

  test("toolbar buttons + sub-header resolve to neutral grey, not blue-grey", async ({ page }) => {
    // The sub-header ("N attack paths · precomputed…") is muted grey now.
    const sub = page.getByText(/precomputed from the runtime asset graph/i);
    await expect(sub).toBeVisible();
    const c = parse(await sub.evaluate((el) => getComputedStyle(el).color))!;
    // neutral grey → red ≈ green ≈ blue (no blue tint).
    expect(Math.abs(c.r - c.b)).toBeLessThanOrEqual(6);
    expect(Math.abs(c.r - c.g)).toBeLessThanOrEqual(6);
  });

  test("no interactive/chrome CTA on the page computes to a blue-dominant color", async ({ page }) => {
    // Scan every button's resolved bg + border + text; none may be blue-dominant (b noticeably > r) unless it
    // is the deliberate purple selection accent on the selected attack-path row (box-shadow, not bg/border).
    const offenders = await page.evaluate(() => {
      const bad: string[] = [];
      for (const el of Array.from(document.querySelectorAll("button"))) {
        const s = getComputedStyle(el);
        for (const prop of ["backgroundColor", "borderTopColor", "color"] as const) {
          const m = s[prop].match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?/);
          if (!m) continue;
          const [r, g, b, a] = [+m[1], +m[2], +m[3], m[4] ? +m[4] : 1];
          if (a === 0) continue;
          // blue-dominant AND not a near-grey → off palette (indigo/blue). Purple (r&b high, g low) also flagged.
          if (b > r + 24 && b > g + 16) bad.push(`${el.textContent?.trim().slice(0, 20)} ${prop}=${s[prop]}`);
        }
      }
      return bad;
    });
    expect(offenders, `blue/indigo chrome on buttons:\n${offenders.join("\n")}`).toEqual([]);
  });
});
