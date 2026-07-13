// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Playwright config for the Norviq console E2E suite. Drives the REAL React SPA (nginx) + API on a
// live cluster — NEVER a mock. The admin token is read from disk at runtime by global-setup.ts and
// seeded into localStorage `nrvq_token` via a storageState file, so no secret is ever committed.
//
// Run: PLAYWRIGHT_BASE_URL=http://localhost:3400 npx playwright test   (after a redeploy + port-forward)

import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3400";

export default defineConfig({
  testDir: ".",
  // Each spec is fully independent; parallelize files, serialize nothing.
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // One retry absorbs the rare interactive-dropdown flake when many workers share the single kind backend.
  retries: 1,
  // Cap parallelism: the suite runs against ONE kind API pod behind one port-forward — too many concurrent
  // browser contexts contend on it and make interactive (dropdown re-render) steps flaky. 3 is a safe balance.
  workers: process.env.CI ? 2 : 3,
  reporter: [["list"], ["html", { outputFolder: "artifacts/html-report", open: "never" }]],
  outputDir: "artifacts/test-results",
  timeout: 60_000,
  expect: { timeout: 15_000 },

  // Seed the admin session for every test (localStorage nrvq_token) before the SPA boots.
  globalSetup: "./global-setup.ts",

  use: {
    baseURL: BASE_URL,
    storageState: "./artifacts/storageState.json",
    screenshot: "only-on-failure",
    trace: "on-first-retry",
    video: "off",
    viewport: { width: 1560, height: 940 },
    deviceScaleFactor: 2,
    // The cluster serves self-signed / dev certs on some ports — don't fail the browser on them.
    ignoreHTTPSErrors: true
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1560, height: 940 }, deviceScaleFactor: 2 }
    }
  ]
});
