// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Security regression — REAL form login, REAL logout control. Proves the layered effect,
// not a 200: clicking Logout (1) returns the user to the login screen, (2) revokes the token
// SERVER-SIDE (the captured pre-logout token gets 401 on /api/v1/me via a page-independent request),
// and (3) the browser back-button cannot restore an authenticated view.
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

// This suite is about the session lifecycle — never start from the seeded storageState token.
test.use({ storageState: { cookies: [], origins: [] } });

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

function storedToken(page: Page): Promise<string> {
  return page.evaluate(
    () => sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token") || ""
  );
}

async function clickLogout(page: Page): Promise<void> {
  await page.locator("button.avatar").click();
  await page.getByRole("button", { name: /logout/i }).click();
}

const loginForm = (page: Page) => page.getByLabel("Username");

test("logout returns to the login screen and the token is rejected server-side", async ({ page, request }) => {
  await realLogin(page);
  const token = await storedToken(page);
  expect(token).not.toEqual("");

  // Sanity: the session is live before logout.
  const before = await request.get("/api/v1/me", { headers: { Authorization: `Bearer ${token}` } });
  expect(before.status()).toBe(200);

  await clickLogout(page);

  // (1) Back at the login screen, session storage cleared.
  await expect(loginForm(page)).toBeVisible({ timeout: 15000 });
  expect(await storedToken(page)).toEqual("");

  // (2) THE defect: the same token must be dead server-side.
  await expect
    .poll(
      async () =>
        (await request.get("/api/v1/me", { headers: { Authorization: `Bearer ${token}` } })).status(),
      { timeout: 10000 }
    )
    .toBe(401);
});

test("back-button after logout cannot restore an authenticated view", async ({ page }) => {
  await realLogin(page);
  // Visit a protected page so it is in the history behind the logout.
  await page.goto("/policies");
  await expect(page.locator("button.avatar")).toBeVisible({ timeout: 15000 });

  await clickLogout(page);
  await expect(loginForm(page)).toBeVisible({ timeout: 15000 });

  await page.goBack();
  // The login gate must swallow the history entry: login form, no authenticated chrome.
  await expect(loginForm(page)).toBeVisible({ timeout: 15000 });
  await expect(page.locator("button.avatar")).toHaveCount(0);
});
