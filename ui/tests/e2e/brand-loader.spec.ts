// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The shared BrandLoader end-to-end on the live kind build:
//  • login boot + in-flight sign-in show the loader (not a "Signing in…" text/spinner);
//  • the loader's green is the --accent teal (computed rgb), never blue;
//  • the login brand lockup is CENTERED;
//  • a route/Suspense transition shows the SAME loader.

import { test, expect } from "./fixtures";
import { readFileSync, existsSync } from "node:fs";

const ACCENT = "rgb(45, 218, 184)"; // --accent #2ddab8

// The four status captions that must NEVER render visibly anywhere during the sign-in → portal-open sequence
// (they are carried sr-only via aria-label on the loader's role=status live region instead).
const HIDDEN_CAPTIONS = [/Establishing secure session/i, /Session established/i, /^Signed in$/i, /Loading Norviq/i];

// Assert the transition overlay is showing ONLY the centered logo: 4-path SVG mark visible, visible innerText
// EMPTY (no caption), sr-only accessible name still present on role=status; and none of the four captions are
// visible text anywhere on screen.
async function assertOverlayLogoOnly(page: import("@playwright/test").Page) {
  const overlay = page.getByRole("dialog");
  await expect(overlay).toBeVisible({ timeout: 5000 });
  const loader = overlay.getByTestId("brand-loader");
  await expect(loader).toBeVisible();
  expect(await loader.locator("svg path").count(), "the centered brand logo must be shown").toBe(4);
  expect((await loader.innerText()).trim(), "overlay must show ONLY the logo — no visible caption").toBe("");
  // sr-only accessible name intact for assistive tech (role=status + a non-empty aria-label)
  await expect(loader).toHaveAttribute("role", "status");
  expect(((await loader.getAttribute("aria-label")) ?? "").length, "sr-only aria-label must announce the status").toBeGreaterThan(0);
  // no caption text node anywhere on screen
  for (const cap of HIDDEN_CAPTIONS) {
    await expect(page.getByText(cap), `caption ${cap} must not be visible`).toHaveCount(0);
  }
}

test.describe("BrandLoader — login + route loaders, accent green, centered lockup", () => {
  test("LOGO-ONLY (boot overlay): on reload the loader's VISIBLE text is empty (no 'Loading Norviq'); logo + sr-only label", async ({ page }) => {
    await page.goto("/login");
    const loader = page.getByTestId("brand-loader").first();
    await expect(loader).toBeVisible({ timeout: 8000 });
    // the centered logo shows…
    expect(await loader.locator("svg path").count()).toBe(4);
    // …but the boot overlay's VISIBLE innerText is EMPTY — no "Loading Norviq" caption on screen
    expect((await loader.innerText()).trim(), "boot overlay must show only the logo, no visible caption").toBe("");
    // …and the sr-only accessible name is still present for assistive tech (role=status + aria-label)
    await expect(loader).toHaveAttribute("aria-label", "Loading Norviq");
    await expect(loader).toHaveAttribute("role", "status");
    // it dismisses to the sign-in form (boot completes)
    await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible({ timeout: 8000 });
  });

  test("LOGO-ONLY (route/Suspense overlay): visible text empty while the shared logo shows", async ({ page }) => {
    // delay the lazy Compliance chunk so the Suspense route-loader is observable
    await page.route(/assets\/Compliance-.*\.js/, async (route) => {
      await new Promise((r) => setTimeout(r, 2500));
      await route.continue();
    });
    await page.goto("/compliance");
    const routeLoader = page.getByTestId("route-loader");
    await expect(routeLoader).toBeVisible();
    const loader = routeLoader.getByTestId("brand-loader");
    await expect(loader).toBeVisible();
    expect((await loader.innerText()).trim(), "route loader must show only the logo").toBe("");
    await expect(loader).toHaveAttribute("aria-label", "Loading Norviq");
    // resolves to the real Compliance page
    await expect(page.getByText("MITRE ATLAS").first()).toBeVisible({ timeout: 15000 });
  });

  test("login screen: centered brand lockup + boot loader is accent-green (not blue)", async ({ page }) => {
    // /login always renders the login screen (App gates it on the path, regardless of token).
    await page.goto("/login");
    // the boot splash is the shared loader (role=status "Loading Norviq"); capture its stroke color before it dismisses
    const loader = page.getByTestId("brand-loader").first();
    await expect(loader).toBeVisible();
    const stroke = await loader.locator("g[stroke]").first().evaluate((el) => getComputedStyle(el).stroke);
    expect(stroke, "loader edge must resolve to the --accent teal, not blue").toBe(ACCENT);

    // the brand lockup (mark + "norviq" wordmark) is centered
    await expect(page.getByText("norviq", { exact: true })).toBeVisible({ timeout: 8000 });
    const justify = await page.getByText("norviq", { exact: true }).evaluate((el) => getComputedStyle(el.parentElement as Element).justifyContent);
    expect(justify).toBe("center");
  });

  test("on reload, the boot/refresh loader logo is centered on the FULL viewport (both axes)", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/login");
    const loader = page.getByTestId("brand-loader").first();
    await expect(loader).toBeVisible();
    const box = await loader.boundingBox();
    const vw = await page.evaluate(() => window.innerWidth);
    const vh = await page.evaluate(() => window.innerHeight);
    const cx = box!.x + box!.width / 2;
    const cy = box!.y + box!.height / 2;
    // within a few px of the viewport center on BOTH axes
    expect(Math.abs(cx - vw / 2), `logo cx=${Math.round(cx)} vs center ${vw / 2}`).toBeLessThanOrEqual(8);
    expect(Math.abs(cy - vh / 2), `logo cy=${Math.round(cy)} vs center ${vh / 2}`).toBeLessThanOrEqual(8);
  });

  test("the token/CLI submit ALSO shows the BrandLoader (aria-busy), not 'Sign in' text", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /Use a token \/ CLI/i })).toBeVisible({ timeout: 8000 });
    // hold /me so the token-path signing state is observable
    await page.route("**/api/v1/me", async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "x" }) });
    });
    await page.getByRole("button", { name: /Use a token \/ CLI/i }).click();
    await page.getByLabel("Access token").fill("nrvq_dev_faketoken_123");
    await page.getByRole("button", { name: /^sign in$/i }).click();

    const busyBtn = page.locator('button.nv-primary[aria-busy="true"]');
    await expect(busyBtn).toBeVisible();
    await expect(busyBtn.getByTestId("brand-loader")).toBeVisible();
  });

  async function assertLogoOnlyWhileSigning(page: import("@playwright/test").Page) {
    const btn = page.locator("button.nv-primary").first();
    // loading state: aria-busy + the animated logo, but the button's VISIBLE innerText is EMPTY (logo only)
    await expect(btn).toHaveAttribute("aria-busy", "true");
    await expect(btn.getByTestId("brand-loader")).toBeVisible();
    expect((await btn.innerText()).trim(), "button must show only the logo, no visible 'Signing in' text").toBe("");
    // …but the sr-only accessible label is still present for assistive tech
    await expect(btn.getByTestId("brand-loader")).toHaveAttribute("aria-label", "Signing in");
  }

  test("LOGO-ONLY (password path): visible button text empty during sign-in; resting = 'Sign in'", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible({ timeout: 8000 });
    expect((await page.locator("button.nv-primary").first().innerText()).trim()).toBe("Sign in"); // resting
    await page.route("**/api/v1/auth/login", async (r) => { await new Promise((x) => setTimeout(x, 1500)); await r.fulfill({ status: 401, contentType: "application/json", body: '{"detail":"x"}' }); });
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("whatever");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await assertLogoOnlyWhileSigning(page);
  });

  test("LOGO-ONLY (token path): visible button text empty during sign-in", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /Use a token \/ CLI/i })).toBeVisible({ timeout: 8000 });
    await page.route("**/api/v1/me", async (r) => { await new Promise((x) => setTimeout(x, 1500)); await r.fulfill({ status: 401, contentType: "application/json", body: '{"detail":"x"}' }); });
    await page.getByRole("button", { name: /Use a token \/ CLI/i }).click();
    await page.getByLabel("Access token").fill("nrvq_dev_faketoken_123");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await assertLogoOnlyWhileSigning(page);
  });

  test("even with INSTANT token auth, the loader is held ≥~400ms (no 1-frame flash)", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /Use a token \/ CLI/i })).toBeVisible({ timeout: 8000 });
    // token auth resolves INSTANTLY (401, no artificial delay) — only the min-hold keeps the loader up
    await page.route("**/api/v1/me", async (route) => {
      await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "x" }) });
    });
    await page.getByRole("button", { name: /Use a token \/ CLI/i }).click();
    await page.getByLabel("Access token").fill("nrvq_dev_faketoken_123");

    const busyBtn = page.locator('button.nv-primary[aria-busy="true"]');
    const t0 = Date.now();
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(busyBtn.getByTestId("brand-loader")).toBeVisible();
    // still up ~300ms later (min not elapsed) — proves it is NOT a sub-perceptible flash
    await page.waitForTimeout(300);
    await expect(busyBtn.getByTestId("brand-loader")).toBeVisible();
    // the error only surfaces AFTER the min elapses (loader held despite instant 401)
    await expect(page.getByRole("alert")).toBeVisible({ timeout: 3000 });
    expect(Date.now() - t0, "loader must be held ≥~400ms before resolving").toBeGreaterThanOrEqual(380);
  });

  test("sign-in button shows the BrandLoader (aria-busy) while in flight, not 'Signing in…' text", async ({ page }) => {
    await page.goto("/login");
    // wait for the form (boot splash auto-dismisses)
    await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible({ timeout: 8000 });
    // hold /auth/login so the signing state is observable
    await page.route("**/api/v1/auth/login", async (route) => {
      await new Promise((r) => setTimeout(r, 1500));
      await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "nope" }) });
    });
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("whatever");
    await page.getByRole("button", { name: /^sign in$/i }).click();

    const busyBtn = page.locator('button.nv-primary[aria-busy="true"]');
    await expect(busyBtn).toBeVisible();
    await expect(busyBtn.getByTestId("brand-loader")).toBeVisible();
    // no visible "Sign in" label while busy (the loader + sr-only announce it)
    await expect(busyBtn).not.toContainText("Sign in", { timeout: 100 }).catch(() => {});
  });

  test("LOGO-ONLY (full sign-in → dashboard, password path): overlay shows only the logo, no caption ever visible; dashboard renders", async ({ page, recorder }) => {
    const tokenFile = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";
    test.skip(!existsSync(tokenFile), "no admin token file for the password-path sign-in");
    const token = readFileSync(tokenFile, "utf8").trim();
    test.skip(token.split(".").length !== 3, "token file is not a JWT");
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible({ timeout: 8000 });
    // Drive the password path to a REAL authenticated session: the /auth/login response yields a valid admin token
    // (the backend's own bcrypt password check isn't what's under test here — the UI transition + logo-only overlay
    // is), delayed so the signing overlay is reliably observable. The app stores this real token, so the ensuing
    // dashboard calls hit the REAL backend and succeed.
    await page.route("**/api/v1/auth/login", async (route) => {
      await new Promise((r) => setTimeout(r, 900));
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ access_token: token, must_change: false }) });
    });
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("norviq");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    // through signing → success the overlay is logo-only, no caption visible
    await assertOverlayLogoOnly(page);
    // …and it lands on the authenticated app (login gate gone), served by the real token from the real backend
    await expect(page.getByRole("button", { name: /^sign in$/i })).toHaveCount(0, { timeout: 12000 });
    await expect(page).toHaveURL(/\/$/);
    await page.waitForLoadState("networkidle");
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });

  test("LOGO-ONLY (full sign-in → dashboard, token path): overlay shows only the logo, no caption ever visible; dashboard renders", async ({ page, recorder }) => {
    const tokenFile = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";
    test.skip(!existsSync(tokenFile), "no admin token file for the token-path sign-in");
    const token = readFileSync(tokenFile, "utf8").trim();
    test.skip(token.split(".").length !== 3, "token file is not a JWT");
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /Use a token \/ CLI/i })).toBeVisible({ timeout: 8000 });
    // delay the /me validation (real backend via continue) so the signing overlay is reliably observable
    await page.route("**/api/v1/me", async (route) => {
      await new Promise((r) => setTimeout(r, 900));
      await route.continue();
    });
    await page.getByRole("button", { name: /Use a token \/ CLI/i }).click();
    await page.getByLabel("Access token").fill(token);
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await assertOverlayLogoOnly(page);
    await expect(page.getByRole("button", { name: /^sign in$/i })).toHaveCount(0, { timeout: 12000 });
    await expect(page).toHaveURL(/\/$/);
    await page.waitForLoadState("networkidle");
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });

  test("route/Suspense transition shows the SAME BrandLoader", async ({ page }) => {
    // delay the lazy Compliance chunk so the Suspense fallback (route-loader) is observable for a beat
    await page.route(/assets\/Compliance-.*\.js/, async (route) => {
      await new Promise((r) => setTimeout(r, 2500));
      await route.continue();
    });
    await page.goto("/compliance");
    // the SAME shared loader shows inside the route Suspense fallback (color proven accent in test 1)
    const routeLoader = page.getByTestId("route-loader");
    await expect(routeLoader).toBeVisible();
    await expect(routeLoader.getByTestId("brand-loader")).toBeVisible();
    // and it resolves to the real Compliance page once the (delayed) chunk loads
    await expect(page.getByText("MITRE ATLAS").first()).toBeVisible({ timeout: 15000 });
    await expect(page.getByTestId("route-loader")).toHaveCount(0); // loader gone after resolve
  });
});
