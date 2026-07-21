// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Catalog precedence hierarchy + governance — REAL form login. Proves:
//   The Catalog hierarchy for a seeded class === a direct GET /policies/effective (scope, order, priority,
//         overlay flag) — the UI renders the real resolution stack, never re-derived.
//   Target Settings shows a "See how this resolves →" link instead of the effective-policy table; the link opens the
//         Catalog hierarchy with the namespace preserved.
//   Enabling a pack for a concrete namespace makes its overlay layer APPEAR in the hierarchy (no reload);
//         disabling makes it disappear.
//   The selected concrete namespace STICKS across Packs → Targets → Catalog (3 hops).
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";
const NS = "default";

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}
async function apiRaw(page: Page, path: string, method = "GET", body?: unknown) {
  return page.evaluate(async ({ path, method, body }) => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(path, { method, headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}
async function selectNamespace(page: Page, ns: string) {
  await page.locator("button.cluster-sel").click();
  await expect(page.locator(".cluster-dd")).toBeVisible({ timeout: 8000 });
  await page.locator(".cluster-dd .dd-item").filter({ hasText: new RegExp(`^${ns}$`) }).first().click();
  await expect(page.locator("button.cluster-sel")).toContainText(ns, { timeout: 8000 });
}
async function openHierarchy(page: Page) {
  await page.goto("/policies/catalog?tab=catalog");
  await expect(page.getByTestId("policy-hierarchy-table")).toBeVisible({ timeout: 15000 });
  // the class list loads async — wait for a class to bind (the empty-state table renders first)
  await expect.poll(async () => page.getByTestId("policy-hierarchy-class").inputValue(), { timeout: 15000 }).not.toEqual("");
}
// rendered rows → [{scope, priority}] in DOM order
async function renderedStack(page: Page): Promise<{ scope: string; priority: string }[]> {
  const rows = page.getByTestId("policy-hierarchy-row");
  const n = await rows.count();
  const out: { scope: string; priority: string }[] = [];
  for (let i = 0; i < n; i++) {
    const r = rows.nth(i);
    out.push({ scope: (await r.getByTestId("policy-hierarchy-scope").innerText()).trim(), priority: (await r.getByTestId("policy-hierarchy-priority").innerText()).trim() });
  }
  return out;
}

test.describe("Catalog hierarchy + governance — real login", () => {
  test.beforeEach(async ({ page }) => {
    await realLogin(page);
    for (const id of ["ecommerce", "erp-crm"]) await apiRaw(page, `/api/v1/policy-packs/${id}/disable`, "POST", { namespace: NS });
    await apiRaw(page, `/api/v1/settings`, "PUT", { namespace: NS, apply_mode: "enforce" });
  });

  test("rendered hierarchy === direct /policies/effective (scope, order, priority)", async ({ page }) => {
    await page.goto("/policies/catalog");
    await selectNamespace(page, NS);
    await openHierarchy(page);
    const cls = await page.getByTestId("policy-hierarchy-class").inputValue();
    expect(cls, "a seeded class must be available").not.toEqual("");
    const api = (await apiRaw(page, `/api/v1/policies/effective?namespace=${NS}&agent_class=${encodeURIComponent(cls)}`)).body;
    const apiStack = (api.layers as { scope: string; priority: number }[]).map((l) => ({ scope: l.scope, priority: String(l.priority) }));
    await expect.poll(async () => (await renderedStack(page)).length).toBe(apiStack.length);
    expect(await renderedStack(page)).toEqual(apiStack); // same scopes, same ORDER, same priorities
    // every row carries the reserved static Mode = Enforce
    const modes = page.getByTestId("policy-hierarchy-mode");
    expect(await modes.count()).toBe(apiStack.length);
    expect(await modes.first().innerText()).toMatch(/Enforce/);
  });

  test("Target Settings has no effective-policy table; the link opens the hierarchy (ns preserved)", async ({ page }) => {
    await page.goto("/policies/targets");
    await selectNamespace(page, NS);
    await expect(page.getByRole("heading", { name: "Namespace Governance" })).toBeVisible({ timeout: 15000 });
    // no resolved-stack table on this page
    await expect(page.getByTestId("policy-hierarchy-table")).toHaveCount(0);
    // the link navigates to the Catalog hierarchy with the namespace preserved
    await page.getByTestId("see-how-resolves").click();
    await expect(page.getByTestId("policy-hierarchy-table")).toBeVisible({ timeout: 15000 });
    await expect(page.locator("button.cluster-sel")).toContainText(NS);
  });

  test("enabling a pack makes its overlay layer appear in the hierarchy; disabling removes it", async ({ page }) => {
    await page.goto("/policies/catalog");
    await selectNamespace(page, NS);
    await openHierarchy(page);
    const packPresent = () => page.getByTestId("policy-hierarchy-slot-pack").getAttribute("data-present");
    // baseline: no pack overlay
    await expect.poll(packPresent).toBe("0");
    // enable a pack for this concrete namespace via the Packs page, then return to the hierarchy
    await page.goto("/policies/packs");
    await page.getByTestId("pack-toggle-ecommerce").click();
    await expect(page.getByTestId("pack-toggle-ecommerce")).toHaveText(/Disable/, { timeout: 15000 });
    await openHierarchy(page);
    await expect.poll(packPresent, { timeout: 15000 }).toBe("1"); // overlay layer now IN FORCE
    expect(await renderedStack(page)).toContainEqual(expect.objectContaining({ scope: expect.stringContaining("__pack__") }));
    // disable → the overlay disappears
    await page.goto("/policies/packs");
    await page.getByTestId("pack-toggle-ecommerce").click();
    await expect(page.getByTestId("pack-toggle-ecommerce")).toHaveText(/Enable/, { timeout: 15000 });
    await openHierarchy(page);
    await expect.poll(packPresent, { timeout: 15000 }).toBe("0");
  });

  test("the concrete namespace STICKS across Packs → Targets → Catalog", async ({ page }) => {
    await page.goto("/policies/packs");
    await selectNamespace(page, NS);
    for (const route of ["/policies/targets", "/policies/catalog", "/policies/packs"]) {
      await page.goto(route);
      await expect(page.locator("button.cluster-sel"), `ns must stick on ${route}`).toContainText(NS, { timeout: 8000 });
    }
    // and it survives a full reload
    await page.reload();
    await expect(page.locator("button.cluster-sel")).toContainText(NS, { timeout: 8000 });
  });
});
