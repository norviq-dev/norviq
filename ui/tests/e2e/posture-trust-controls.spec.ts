// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// REAL form login, REAL controls. Proves the deferred posture/trust controls now ENFORCE
// end-to-end through the console:
//   * Settings → set a namespace to Monitor (audit) mode via the real toggle + Save → a blocked tool in
//     that namespace softens to an allow-but-log `audit` decision; set it back to Block → it re-blocks.
//   * Agents → Freeze Agent via the real button → that agent's calls block; Reset Trust → recovers.
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";
const NS = "scen-e2e-posture";
const CLS = "e2e-bot";
const SPIFFE = `spiffe://norviq/ns/${NS}/sa/${CLS}`;

test.use({ storageState: { cookies: [], origins: [] } });

const RESOLVER = [
  'default decision = "allow"', 'default rule_id = "default_allow"', 'default reason = "Allowed"',
  'blocks["__never__"] { false }', 'block_fired { blocks[_] }',
  'decision = "block" { block_fired }',
  'rule_id = sort([id | blocks[id]])[0] { block_fired }',
  'reason = "blocked" { block_fired }',
].join("\n");
const REGO = `package norviq.strict\nblocks["e2e_block"] { input.tool_name == "blocked_tool" }\n${RESOLVER}\n`;

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

/** Same-origin API call carrying the real session token. */
async function api(page: Page, path: string, method = "GET", body?: unknown) {
  return page.evaluate(async ({ path, method, body }) => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}

async function evalTool(page: Page, tool: string, spiffe = SPIFFE) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: { n: Date.now() },
    agent_identity: { namespace: NS, agent_class: CLS, agent_id: CLS, spiffe_id: spiffe },
  });
  return `${r.body?.decision}/${r.body?.rule_id}`;
}

async function pickNamespace(page: Page, ns: string) {
  await page.locator("button.cluster-sel").click();
  await expect(page.locator(".cluster-dd")).toBeVisible({ timeout: 8000 });
  await page.locator(".cluster-dd .dd-item").filter({ hasText: new RegExp(`^${ns}$`) }).first().click();
  await expect(page.locator("button.cluster-sel")).toContainText(ns, { timeout: 8000 });
}

test.beforeAll(async ({ request, baseURL }) => {
  // Seed the scratch namespace + blocking policy via the API (allowed: test data setup).
  const login = await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } });
  const tok = (await login.json()).access_token as string;
  const h = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };
  await request.post(`${baseURL}/api/v1/policies`, { headers: h, data: {
    namespace: NS, agent_class: CLS, enforcement_mode: "block", priority: 300, policy_name: NS, rego_source: REGO } });
});

test.afterAll(async ({ request, baseURL }) => {
  const login = await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } });
  const tok = (await login.json()).access_token as string;
  const h = { Authorization: `Bearer ${tok}` };
  await request.delete(`${baseURL}/api/v1/policies/${NS}/${CLS}`, { headers: h });
  await request.put(`${baseURL}/api/v1/settings?namespace=${NS}`, {
    headers: { ...h, "Content-Type": "application/json" }, data: { enforcement_mode: "block", trust_threshold: 0.7, rate_limit: 60 } });
});

test("the Settings Monitor toggle softens enforcement, and back re-blocks", async ({ page }) => {
  await realLogin(page);
  // Confirm the seed enforces before we touch posture.
  expect(await evalTool(page, "blocked_tool")).toBe("block/e2e_block");

  await page.goto("/settings/general");
  // Switching the global namespace refetches the settings for NS — wait for that GET so the toggle reflects
  // NS's persisted mode (not the previously-loaded namespace's), removing the load/click race.
  const getForNs = page.waitForResponse(
    (r) => r.url().includes(`/api/v1/settings`) && r.url().includes(`namespace=${NS}`) && r.request().method() === "GET",
    { timeout: 15000 });
  await pickNamespace(page, NS);
  await getForNs;
  await expect(page.getByRole("button", { name: /^block$/i })).toBeVisible({ timeout: 10000 });

  // Drive the REAL enforcement-mode toggle → Monitor (audit) → Save.
  const putAudit = page.waitForResponse(
    (r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByRole("button", { name: /^audit$/i }).click();
  await page.getByRole("button", { name: /save changes/i }).click();
  const resp = await putAudit;
  expect((await resp.json()).enforcement_mode).toBe("audit");

  // The blocked tool now allow-but-logs — a would_block audit decision, not a block.
  await expect.poll(() => evalTool(page, "blocked_tool"), { timeout: 10000 }).toBe("audit/monitor_would_block:e2e_block");

  // Flip back to Block via the toggle → re-enforces immediately.
  const putBlock = page.waitForResponse(
    (r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByRole("button", { name: /^block$/i }).click();
  await page.getByRole("button", { name: /save changes/i }).click();
  await putBlock;
  await expect.poll(() => evalTool(page, "blocked_tool"), { timeout: 10000 }).toBe("block/e2e_block");
});

test("the real Agents 'Freeze Agent' button blocks the agent; 'Reset Trust' recovers it", async ({ page }) => {
  await realLogin(page);
  // Register the agent (one observed call) so it renders on the Agents page.
  const freezeSpiffe = `spiffe://norviq/ns/${NS}/sa/freeze-bot`;
  expect(await evalTool(page, "benign_tool", freezeSpiffe)).toBe("allow/default_allow");

  await page.goto("/agents");
  await pickNamespace(page, NS);
  // Open the agent's detail panel (which holds the Freeze/Reset controls).
  const row = page.getByText("freeze-bot").first();
  await expect(row).toBeVisible({ timeout: 20000 });
  await row.click();

  // Drive the REAL "Freeze Agent" button and assert the enforced effect.
  const putFreeze = page.waitForResponse(
    (r) => /\/api\/v1\/agents\/.+\/trust/.test(r.url()) && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByRole("button", { name: /freeze agent/i }).click();
  await putFreeze;
  await expect.poll(() => evalTool(page, "benign_tool", freezeSpiffe), { timeout: 10000 }).toBe("block/trust_frozen");

  // Drive the REAL "Reset Trust" button → recovers.
  const putReset = page.waitForResponse(
    (r) => /\/api\/v1\/agents\/.+\/trust/.test(r.url()) && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByRole("button", { name: /reset trust/i }).click();
  await putReset;
  await expect.poll(() => evalTool(page, "benign_tool", freezeSpiffe), { timeout: 10000 }).not.toContain("trust_frozen");
});
