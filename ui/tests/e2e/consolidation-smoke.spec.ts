// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// CONSOLIDATION integration smoke — one GENUINE username/password login (NOT token injection), then prove the
// major features assembled into release/pre-ga-consolidated all work TOGETHER on the served build, in one session:
//   • app boots + login → Overview; KPI cards show real data == the app's OWN /audit/stats;
//   • apply→ENFORCE (create a policy via the client contract → /evaluate flips to its own rule — effect, not 200);
//   • RedTeam scorecard renders results/latest (proven-blocking %);
//   • Compliance efficacy wiring renders (the "% proven-blocking (last run)" seam);
//   • Editor create→ENFORCE then delete→FALL-BACK; reserved scopes show no delete affordance.
// 0 console errors / 0 api failures throughout. Throwaway classes only — never customer-support.

import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible({ timeout: 15000 });
}

async function api(page: Page, path: string, method = "GET", body?: unknown): Promise<{ status: number; body: any }> {
  return page.evaluate(async ({ path, method, body }) => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}
async function ev(page: Page, ns: string, cls: string, tool: string) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: { x: 1 },
    agent_identity: { spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`, namespace: ns, agent_class: cls },
    session_id: "consol-smoke", trust_score: 0.8, chain_depth: 0
  });
  return { decision: r.body?.decision, rule_id: r.body?.rule_id };
}
const kpi = async (page: Page, id: string) => Number(await page.getByTestId(`${id}-value`).getAttribute("data-value"));
const activeRange = async (page: Page) => (await page.locator(".range-chip.active").first().innerText()).trim();

const BLOCK_REGO = [
  "package norviq.custom",
  'default decision = "allow"',
  'rule_id = "custom_block_rule"',
  'reason = "blocked by a custom policy"',
  'decision = "block" { input.tool_name == "delete_database" }'
].join("\n");

test.describe("CONSOLIDATION — genuine-login integration smoke (features work together)", () => {
  test("boot + login + KPIs real + apply→enforce + RedTeam + Compliance + Editor create/delete, 0 console/4xx", async ({ page }) => {
    test.setTimeout(150000);
    const consoleErrors: string[] = [];
    page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
    const bad: string[] = [];
    const anyFail: string[] = []; // every >=400 (any host) so a failing resource is named, not just "404"
    page.on("response", (r) => {
      const u = r.url();
      if (r.status() >= 400) anyFail.push(`${r.status()} ${r.request().method()} ${u}`);
      if (u.includes("/api/v1") && r.status() >= 400) bad.push(`${r.status()} ${u}`);
    });
    const pageErrs: string[] = [];
    page.on("pageerror", (e) => pageErrs.push(e.message));

    // (1) app boots + GENUINE login → Overview
    await realLogin(page);

    // (2) KPI cards bind the app's OWN /audit/stats for the active range (the monotonic-fix, live)
    const range = await activeRange(page);
    const stats = (await api(page, `/api/v1/audit/stats?range=${range}`)).body;
    await expect.poll(() => kpi(page, "kpi-total"), { timeout: 15000 }).toBe(stats.total);
    expect(await kpi(page, "kpi-blocked")).toBe(stats.blocked);
    expect(await kpi(page, "kpi-latency")).toBe(Math.round(stats.avg_latency_ms));
    if (stats.total > 0) expect(await kpi(page, "kpi-total")).toBeGreaterThan(0);

    // (3) apply→ENFORCE: a created policy actually enforces on the running engine (effect, not 200)
    const NS = "default", CA = "consol-apply", TOOL = "delete_database";
    try {
      expect((await ev(page, NS, CA, TOOL)).rule_id).not.toBe("custom_block_rule");
      expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: CA, rego_source: BLOCK_REGO, enforcement_mode: "block" })).status).toBe(200);
      await expect.poll(async () => (await ev(page, NS, CA, TOOL)).rule_id, { timeout: 20000 }).toBe("custom_block_rule");
      expect((await ev(page, NS, CA, TOOL)).decision).toBe("block");
    } finally {
      await api(page, `/api/v1/policies/${NS}/${CA}`, "DELETE");
    }

    // (4) RedTeam scorecard renders results/latest (proven-blocking %)
    await page.goto("/redteam");
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 20000 });
    const latest = (await api(page, "/api/v1/redteam/results/latest")).body;
    if (latest?.efficacy?.overall) {
      await expect(page.getByTestId("redteam-proven-pct")).toContainText(`${latest.efficacy.overall.proven_blocking_pct}%`);
      await expect(page.getByTestId("redteam-metric-cluster")).toContainText(String(latest.efficacy.overall.caught));
    }

    // (5) Compliance efficacy wiring renders (frameworks + the proven-blocking seam)
    await page.goto("/compliance");
    await expect(page.getByText("MITRE ATLAS")).toBeVisible({ timeout: 20000 });
    await expect(page.getByText(/proven-blocking/i).first()).toBeVisible();

    // (6) Editor create→ENFORCE then delete→FALL-BACK (BATCH-B), on the same session
    const CE = "consol-editor";
    let deletedViaUI = false;
    try {
      await page.goto("/policies/catalog");
      await expect(page.getByRole("heading", { name: "Policy Catalog" })).toBeVisible({ timeout: 15000 });
      // New-policy raw-rego authoring → Create (the seeded template blocks delete_database as custom_block_rule)
      await page.getByTestId("editor-new-policy").click();
      await page.getByTestId("new-policy-namespace").fill(NS);
      await page.getByTestId("new-policy-class").fill(CE);
      await page.getByTestId("editor-save-policy").click();
      await expect.poll(async () => (await ev(page, NS, CE, TOOL)).rule_id, { timeout: 20000 }).toBe("custom_block_rule");
      // delete via the catalog row → confirm → the class falls back (its rule no longer fires)
      await page.getByRole("button", { name: /^catalog$/i }).click();
      await page.getByTestId(`catalog-delete-${CE}`).click();
      await expect(page.getByTestId("delete-policy-modal")).toContainText(`${NS}/${CE}`);
      await page.getByTestId("delete-policy-confirm").click();
      await expect.poll(async () => (await ev(page, NS, CE, TOOL)).rule_id, { timeout: 20000 }).not.toBe("custom_block_rule");
      deletedViaUI = true; // the UI delete IS the test — no redundant cleanup (a second DELETE would 404)
      // reserved scopes carry no delete affordance
      await expect(page.getByTestId("catalog-delete-__baseline__")).toHaveCount(0);
    } finally {
      // safety-net cleanup ONLY if the UI delete path didn't complete (avoids a 404 on an already-deleted policy).
      if (!deletedViaUI) await api(page, `/api/v1/policies/${NS}/${CE}`, "DELETE");
    }

    // (7) clean session — no console errors, no 4xx/5xx, no page errors
    // Benign, framework-level noise that is NOT an app defect (matches the fixtures.ts recorder convention):
    // Monaco cancels its async model/worker load when the editor unmounts on navigation → a "Canceled" pageerror;
    // React-Router future-flag / devtools / vite / favicon / ResizeObserver console chatter.
    const IGNORE = [/^Canceled$/i, /ResizeObserver loop/i, /React Router Future Flag/i, /Download the React DevTools/i, /\[vite\]/i, /favicon\.ico/i];
    const realPageErrs = pageErrs.filter((m) => !IGNORE.some((re) => re.test(m)));
    const realConsole = consoleErrors.filter((m) => !IGNORE.some((re) => re.test(m)));
    expect(realPageErrs, `pageerrors: ${realPageErrs.join(", ")}`).toEqual([]);
    expect(realConsole, `console errors: ${realConsole.join(" | ")} :: failing resources: ${[...new Set(anyFail)].join(" | ")}`).toEqual([]);
    expect(bad, `4xx/5xx (api): ${bad.join(", ")}`).toEqual([]);
  });
});
