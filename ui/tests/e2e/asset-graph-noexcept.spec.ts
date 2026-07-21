// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// /asset-graph must render + reload with ZERO uncaught console exceptions. Guards against the live
// render-timing bugs on 39a2019: "Cannot read properties of null (reading 'clientWidth')" (AssetGraph) and
// "SVGLength: Could not resolve relative length" (d3 sizing before the container resolved a size). Asserts
// no pageerror / console error / 4xx on first load AND on reload, and that the graph actually renders.

import { test, expect } from "./fixtures";
import { type Page } from "@playwright/test";

function watch(page: Page) {
  const pageErrors: string[] = [];
  const consoleErrors: string[] = [];
  const badResponses: string[] = [];
  page.on("pageerror", (e) => pageErrors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
  page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) badResponses.push(`${r.status()} ${r.url()}`); });
  return { pageErrors, consoleErrors, badResponses };
}

// Some console.error chatter is benign (dev warnings, font/telemetry, favicon). Only the render-timing
// exceptions this spec targets (and any genuine app error) must be zero.
const IGNORE = [/Download the React DevTools/i, /React Router Future Flag/i, /\[vite\]/i, /favicon/i, /ResizeObserver loop/i];
const real = (xs: string[]) => xs.filter((m) => !IGNORE.some((re) => re.test(m)));

test.describe("/asset-graph renders + reloads with zero uncaught exceptions", () => {
  test("first load + reload → 0 pageerror, 0 console error, 0 4xx; graph renders", async ({ page }) => {
    const w = watch(page);

    await page.goto("/asset-graph");
    await expect(page.getByTestId("asset-graph-canvas")).toBeVisible({ timeout: 15000 });
    // the d3 world actually built (the svg has children once the container sized)
    await expect
      .poll(async () => page.getByTestId("asset-graph-canvas").evaluate((el) => el.childElementCount), { timeout: 10000 })
      .toBeGreaterThan(0);

    // reload — the previous crash reproduced on reload (container measured before layout)
    await page.reload();
    await expect(page.getByTestId("asset-graph-canvas")).toBeVisible({ timeout: 15000 });
    await expect
      .poll(async () => page.getByTestId("asset-graph-canvas").evaluate((el) => el.childElementCount), { timeout: 10000 })
      .toBeGreaterThan(0);

    // the specific exceptions must be absent, and nothing uncaught at all
    const errs = [...w.pageErrors, ...real(w.consoleErrors)];
    expect(errs.join("\n")).not.toMatch(/clientWidth/);
    expect(errs.join("\n")).not.toMatch(/SVGLength|Could not resolve relative length/);
    expect(w.pageErrors, `uncaught page exceptions:\n${w.pageErrors.join("\n")}`).toEqual([]);
    expect(real(w.consoleErrors), `console errors:\n${real(w.consoleErrors).join("\n")}`).toEqual([]);
    expect(w.badResponses, `4xx/5xx:\n${w.badResponses.join("\n")}`).toEqual([]);
  });
});
