// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Policy-Packs / Governance — REAL form login (not token injection). Proves the three fixes on the served
// build with EFFECT, not a 200:
//   Under "All namespaces" (the default aggregate scope) every pack/override/apply-mode mutation is DISABLED
//         with an inline "Select a namespace" prompt, and NO ?namespace=all write is ever sent.
//   Under a CONCRETE namespace, Enable flips the card to Enabled with no reload and Disable flips it back —
//         3× — and the write targets the concrete namespace; the Target-Settings "packs applied" chip updates.
//   A dry-run-only namespace surfaces the reason inline and disables pack applies up-front.
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
  // open the header namespace dropdown (button.cluster-sel) and pick `ns` from the NAMESPACES column.
  await page.locator("button.cluster-sel").click();
  await expect(page.locator(".cluster-dd")).toBeVisible({ timeout: 8000 });
  await page.locator(".cluster-dd .dd-item").filter({ hasText: new RegExp(`^${ns}$`) }).first().click();
  // confirm via the trigger label (stable across pages, unlike per-page subtitles).
  await expect(page.locator("button.cluster-sel")).toContainText(ns, { timeout: 8000 });
}

test.describe("Packs/Governance — real login", () => {
  test.beforeEach(async ({ page }) => {
    await realLogin(page);
    // clean slate: disable the throwaway packs under both default and the phantom "all".
    for (const scope of [NS, "all"]) for (const id of ["ecommerce", "erp-crm", "media-entertainment"]) {
      await apiRaw(page, `/api/v1/policy-packs/${id}/disable`, "POST", { namespace: scope });
    }
    await apiRaw(page, `/api/v1/settings`, "PUT", { namespace: NS, apply_mode: "enforce" });
  });

  test("All-namespaces disables every mutation + prompts, and sends NO ?namespace=all write", async ({ page }) => {
    const allWrites: string[] = [];
    page.on("request", (r) => {
      if (["POST", "PUT", "DELETE"].includes(r.method()) && r.url().includes("/policy-packs")) {
        const b = r.postData() || "";
        if (b.includes('"all"')) allWrites.push(`${r.method()} ${r.url()} ${b}`);
      }
    });
    await page.goto("/policies/packs");
    await expect(page.getByRole("heading", { name: "Policy Packs" })).toBeVisible({ timeout: 15000 });
    // aggregate scope → prompt + disabled toggles
    await expect(page.getByTestId("pack-scope-prompt")).toContainText(/Select a namespace/i);
    const firstToggle = page.locator('[data-testid^="pack-toggle-"]').first();
    await expect(firstToggle).toBeDisabled();
    await expect(page.getByTestId("override-apply")).toBeDisabled();
    // apply-mode toggle on Target Settings is likewise disabled under aggregate
    await page.goto("/policies/targets");
    await expect(page.getByTestId("apply-mode-scope-prompt")).toContainText(/Select a namespace/i);
    await expect(page.getByTestId("apply-mode-enforce")).toBeDisabled();
    expect(allWrites, `no ?namespace=all write may ever be sent: ${allWrites.join(" | ")}`).toEqual([]);
  });

  test("concrete-ns Enable flips the card 3× (no reload) + writes the concrete ns + Target chip updates", async ({ page }) => {
    const enableBodies: string[] = [];
    page.on("request", (r) => {
      if (r.method() === "POST" && /\/policy-packs\/[^/]+\/enable/.test(r.url())) enableBodies.push(r.postData() || "");
    });
    await page.goto("/policies/packs");
    await expect(page.getByRole("heading", { name: "Policy Packs" })).toBeVisible({ timeout: 15000 });
    await selectNamespace(page, NS);

    const toggle = page.getByTestId("pack-toggle-ecommerce");
    await expect(toggle).toBeEnabled();
    for (let i = 0; i < 3; i++) {
      // Enable → card flips to Enabled (poll, no reload)
      await expect(toggle).toHaveText(/Enable/);
      await toggle.click();
      await expect(toggle).toHaveText(/Disable/, { timeout: 15000 });
      // Disable → flips back
      await toggle.click();
      await expect(toggle).toHaveText(/Enable/, { timeout: 15000 });
    }
    // every enable wrote the concrete namespace, never "all"
    expect(enableBodies.length).toBeGreaterThanOrEqual(3);
    for (const b of enableBodies) { expect(b).toContain(`"${NS}"`); expect(b).not.toContain('"all"'); }

    // leave it enabled, then the Target-Settings "packs applied" chip must reflect it (cross-page cache-bust)
    await toggle.click();
    await expect(toggle).toHaveText(/Disable/, { timeout: 15000 });
    await page.goto("/policies/targets");
    await selectNamespace(page, NS);
    await expect(page.locator("text=Sector packs applied").locator("..")).toContainText(/ecommerce|E-?commerce/i, { timeout: 15000 });
    // cleanup
    await apiRaw(page, `/api/v1/policy-packs/ecommerce/disable`, "POST", { namespace: NS });
  });

  test("a dry-run-only namespace surfaces the reason and disables pack applies", async ({ page }) => {
    await realLogin(page);
    await apiRaw(page, `/api/v1/settings`, "PUT", { namespace: NS, apply_mode: "dry_run_only" });
    try {
      await page.goto("/policies/packs");
      await expect(page.getByRole("heading", { name: "Policy Packs" })).toBeVisible({ timeout: 15000 });
      await selectNamespace(page, NS);
      await expect(page.getByTestId("pack-dryrun-banner")).toContainText(/dry-run-only/i, { timeout: 15000 });
      await expect(page.getByTestId("pack-toggle-ecommerce")).toBeDisabled();
    } finally {
      await apiRaw(page, `/api/v1/settings`, "PUT", { namespace: NS, apply_mode: "enforce" });
    }
  });
});
