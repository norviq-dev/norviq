// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// GRAPH-GLOBAL-NS-SYNC — REAL form login, REAL controls. Proves both graphs FOLLOW the top-level
// (global) namespace selector, which is the surface the defect was filed against:
//   * Asset Graph: pick a concrete ns in the GLOBAL header selector → the page's "Showing:" text, its
//     in-panel Namespace dropdown, and the issued /asset-graph request all scope to that ns; switch to a
//     second ns → it follows; back to "All namespaces" → unscoped again.
//   * Attack Graph: the same, against /threats/attack-paths (this ALSO tests the ledger's assumption that
//     the Attack Graph shares the defect — it does not; it already followed the global selector).
//   * The page-local "Reset" on the Attack Graph must NOT clobber the global scope.
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

// Drive the real login form; never the seeded storageState token.
test.use({ storageState: { cookies: [], origins: [] } });

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

/** The GLOBAL namespace selector in the header (the control the defect is about). */
async function selectGlobalNamespace(page: Page, ns: string): Promise<void> {
  const trigger = page.locator("button.cluster-sel");
  await trigger.waitFor({ state: "visible", timeout: 15000 });
  await trigger.click();
  await expect(page.locator(".cluster-dd")).toBeVisible({ timeout: 8000 });
  await page.locator(".cluster-dd .dd-item").filter({ hasText: new RegExp(`^${ns}$`) }).first().click();
  await expect(trigger).toContainText(ns, { timeout: 8000 });
}

/** Two concrete namespaces this deployment actually has — read from the API that feeds the selector
 *  (/cluster-info), NOT by scraping the dropdown, so we never leave the header in a half-open state. */
async function twoNamespaces(page: Page): Promise<string[]> {
  const info = await page.evaluate(async () => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch("/api/v1/cluster-info", { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return (await res.json()) as { namespaces?: string[] };
  });
  return (info.namespaces ?? []).filter((n) => n && n !== "all").slice(0, 2);
}

test("the Asset Graph follows the GLOBAL namespace selector", async ({ page }) => {
  await realLogin(page);
  await page.goto("/asset-graph");
  await expect(page.getByRole("button", { name: /^namespace$/i })).toBeVisible({ timeout: 20000 });

  const [nsA, nsB] = await twoNamespaces(page);
  test.skip(!nsA || !nsB, "need two concrete namespaces in this environment");

  // Global → nsA. The graph must re-fetch scoped and say so.
  const reqA = page.waitForRequest(
    (r) => r.url().includes("/api/v1/asset-graph") && new RegExp(`[?&]namespace=${nsA}(&|$)`).test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, nsA);
  await reqA;
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsA} namespace`))).toBeVisible({ timeout: 15000 });
  // the in-panel dropdown is a VIEW of the global, not a second source of truth
  await expect(page.getByRole("button", { name: /^namespace$/i })).toContainText(nsA);

  // Global → nsB. It follows.
  const reqB = page.waitForRequest(
    (r) => r.url().includes("/api/v1/asset-graph") && new RegExp(`[?&]namespace=${nsB}(&|$)`).test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, nsB);
  await reqB;
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsB} namespace`))).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole("button", { name: /^namespace$/i })).toContainText(nsB);

  // Global → All namespaces. Unscoped again.
  const reqAll = page.waitForRequest(
    (r) => r.url().includes("/api/v1/asset-graph") && /[?&]namespace=all(&|$)/.test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, "All namespaces");
  await reqAll;
  await expect(page.getByText(/Showing:\s*All namespaces/)).toBeVisible({ timeout: 15000 });
});

test("the Attack Graph follows the GLOBAL namespace selector", async ({ page }) => {
  await realLogin(page);
  await page.goto("/threats/graph");
  await expect(page.getByTestId("attack-graph-canvas")).toBeVisible({ timeout: 20000 });

  const [nsA, nsB] = await twoNamespaces(page);
  test.skip(!nsA || !nsB, "need two concrete namespaces in this environment");

  const reqA = page.waitForRequest(
    (r) => r.url().includes("/api/v1/threats/attack-paths") && new RegExp(`[?&]ns=${nsA}(&|$)`).test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, nsA);
  await reqA;
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsA}`))).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole("button", { name: "Namespace", exact: true })).toContainText(nsA);

  const reqB = page.waitForRequest(
    (r) => r.url().includes("/api/v1/threats/attack-paths") && new RegExp(`[?&]ns=${nsB}(&|$)`).test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, nsB);
  await reqB;
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsB}`))).toBeVisible({ timeout: 15000 });

  const reqAll = page.waitForRequest(
    (r) => r.url().includes("/api/v1/threats/attack-paths") && /[?&]ns=all(&|$)/.test(r.url()),
    { timeout: 20000 }
  );
  await selectGlobalNamespace(page, "All namespaces");
  await reqAll;
  await expect(page.getByText(/Showing:\s*All namespaces/)).toBeVisible({ timeout: 15000 });
});

test("the Attack Graph's page-local Reset does not clobber the global namespace", async ({ page }) => {
  await realLogin(page);
  await page.goto("/threats/graph");
  await expect(page.getByTestId("attack-graph-canvas")).toBeVisible({ timeout: 20000 });

  const [nsA] = await twoNamespaces(page);
  test.skip(!nsA, "need a concrete namespace in this environment");
  await selectGlobalNamespace(page, nsA);
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsA}`))).toBeVisible({ timeout: 15000 });

  // "Reset" only renders in the empty state — reach it deterministically by switching every severity off.
  for (const sev of ["critical", "high", "medium", "low"]) {
    const chip = page.getByRole("button", { name: new RegExp(`^${sev}$`, "i") });
    if ((await chip.getAttribute("aria-pressed")) === "true") await chip.click();
  }
  const reset = page.getByRole("button", { name: /^reset$/i });
  await expect(reset).toBeVisible({ timeout: 15000 });

  // Any /threats/attack-paths refetch triggered by Reset must NOT widen the scope to ns=all.
  const widened: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/v1/threats/attack-paths") && /[?&]ns=all(&|$)/.test(r.url())) widened.push(r.url());
  });

  await reset.click();

  // Page filters are restored…
  await expect(page.getByRole("button", { name: /^critical$/i })).toHaveAttribute("aria-pressed", "true");
  // …and the GLOBAL scope survives (pre-fix: resetFilters called setNamespace("all"), rescoping the console).
  await expect(page.getByText(new RegExp(`Showing:\\s*${nsA}`))).toBeVisible({ timeout: 15000 });
  await expect(page.locator("button.cluster-sel")).toContainText(nsA);
  expect(widened).toEqual([]);
});
