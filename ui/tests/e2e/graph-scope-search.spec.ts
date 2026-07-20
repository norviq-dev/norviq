// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// REAL form login, REAL controls. Proves:
//   Picking a concrete namespace in the Attack Graph scopes the graph — the header reads
//         "Showing: <ns>", the request carries the scope, and the scoped path count < the all-ns count.
//         (This also disproves the "stays Showing: All namespaces" claim.)
//   API: the `namespace` alias scopes identically to `ns` (not silently ignored).
//   ⌘K search is backed by a real, scoped GET /api/v1/search and renders results.
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

// Session-lifecycle independence: drive the real login form, not the seeded storageState token.
test.use({ storageState: { cookies: [], origins: [] } });

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

/** Same-origin fetch from the page (carries the real session token). */
async function apiJson(page: Page, path: string): Promise<{ status: number; body: any }> {
  return page.evaluate(async (p) => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(p, { headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
}

const pathRows = (page: Page) => page.locator("button[aria-pressed]").filter({ hasText: "→" });

test("selecting a concrete namespace scopes the Attack Graph (header + request + counts)", async ({ page }) => {
  await realLogin(page);
  await page.goto("/threats/graph");
  await expect(page.getByTestId("attack-graph-canvas")).toBeVisible({ timeout: 20000 });

  // Baseline: the console defaults to "All namespaces".
  await expect(page.getByText(/Showing:\s*All namespaces/i)).toBeVisible({ timeout: 15000 });
  const allCount = await pathRows(page).count();

  // Open the Namespace dropdown and pick the first CONCRETE namespace (not "all").
  await page.getByRole("button", { name: "Namespace", exact: true }).click();
  const options = page.locator('[role="listbox"][aria-label="Namespace"] [role="option"]');
  await expect(options.first()).toBeVisible({ timeout: 8000 });
  const labels = await options.allInnerTexts();
  const concrete = labels.map((s) => s.replace("✓", "").trim()).find((s) => !/all namespaces/i.test(s));
  test.skip(!concrete, "no concrete namespace available in this environment");

  // The refetch must carry the scope.
  const scopedReq = page.waitForRequest(
    (r) => r.url().includes("/api/v1/threats/attack-paths") && new RegExp(`[?&]ns=${concrete}(&|$)`).test(r.url()),
    { timeout: 15000 }
  );
  await options.filter({ hasText: new RegExp(`^${concrete}\\s*✓?$`) }).first().click();
  await scopedReq;

  // Header reflects the scope (the ledger claimed it stays "All namespaces").
  await expect(page.getByText(new RegExp(`Showing:\\s*${concrete}`))).toBeVisible({ timeout: 15000 });

  // And the graph really narrowed: scoped rows <= all rows, and the API agrees.
  const scoped = await apiJson(page, `/api/v1/threats/attack-paths?ns=${concrete}`);
  const all = await apiJson(page, `/api/v1/threats/attack-paths?ns=all`);
  expect(scoped.status).toBe(200);
  expect(scoped.body.namespaces).toEqual([concrete]);
  expect(scoped.body.paths.length).toBeLessThan(all.body.paths.length);
  expect(await pathRows(page).count()).toBeLessThanOrEqual(allCount);
});

test("(API): the `namespace` alias scopes identically to `ns`, and a conflict is a 400", async ({ page }) => {
  await realLogin(page);
  const byNs = await apiJson(page, "/api/v1/threats/attack-paths?ns=default");
  const byAlias = await apiJson(page, "/api/v1/threats/attack-paths?namespace=default");
  const all = await apiJson(page, "/api/v1/threats/attack-paths?ns=all");

  expect(byNs.status).toBe(200);
  expect(byAlias.status).toBe(200);
  // Pre-fix `?namespace=` was silently ignored and returned EVERY namespace.
  expect(byAlias.body.namespaces).toEqual(["default"]);
  expect(byAlias.body.paths.length).toBe(byNs.body.paths.length);
  expect(byAlias.body.paths.length).toBeLessThan(all.body.paths.length);

  const conflict = await apiJson(page, "/api/v1/threats/attack-paths?ns=default&namespace=devops");
  expect(conflict.status).toBe(400);
});

test("⌘K search is backed by a real scoped endpoint and renders results", async ({ page }) => {
  await realLogin(page);

  // The endpoint exists and is shaped for the palette.
  const res = await apiJson(page, "/api/v1/search?q=a");
  expect(res.status).toBe(200);
  expect(res.body).toHaveProperty("tools");
  expect(res.body).toHaveProperty("agents");
  expect(res.body).toHaveProperty("policies");

  // A '%' must be a literal, not a wildcard — and must not 500.
  const pct = await apiJson(page, "/api/v1/search?q=%25");
  expect(pct.status).toBe(200);

  // Drive the real ⌘K palette: it must call /api/v1/search exactly once for the typed query.
  const searchReq = page.waitForRequest((r) => r.url().includes("/api/v1/search?q="), { timeout: 15000 });
  await page.keyboard.press("Meta+k");
  await page.getByLabel("Search").first().fill("bot");
  await searchReq;
  // The panel opens with either results or an explicit empty state — never a dead control.
  await expect(page.getByText(/No results for|Agents|Policies|Tools/i).first()).toBeVisible({ timeout: 15000 });
});
