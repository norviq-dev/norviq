// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// REAL form login, REAL controls. Proves the Namespace
// Governance card's Block ⇄ Monitor toggle drives the LIVE enforcement effect end-to-end, the hierarchy
// Mode column agrees, and the apply-mode is relabelled Live/Frozen.
import { test, expect, type Page } from "@playwright/test";

const PW = process.env.NRVQ_E2E_PASSWORD || "CHANGE_ME-e2e-pw";
const NS = "scen-a2-posture";
const CLS = "gov-bot";
const SPIFFE = `spiffe://norviq/ns/${NS}/sa/${CLS}`;

test.use({ storageState: { cookies: [], origins: [] } });

const RESOLVER = [
  'default decision = "allow"', 'default rule_id = "default_allow"', 'default reason = "Allowed"',
  'blocks["__never__"] { false }', 'block_fired { blocks[_] }',
  'decision = "block" { block_fired }',
  'rule_id = sort([id | blocks[id]])[0] { block_fired }', 'reason = "blocked" { block_fired }',
].join("\n");
const REGO = `package norviq.strict\nblocks["gov_block"] { input.tool_name == "delete_record" }\n${RESOLVER}\n`;

async function realLogin(page: Page): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/$/, { timeout: 20000 });
}

async function api(page: Page, path: string, method = "GET", body?: unknown) {
  return page.evaluate(async ({ path, method, body }) => {
    const t = sessionStorage.getItem("nrvq_token") || localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method, headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}
async function evalTool(page: Page, tool: string) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: { n: Date.now() },
    agent_identity: { namespace: NS, agent_class: CLS, agent_id: CLS, spiffe_id: SPIFFE },
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
  const tok = (await (await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } })).json()).access_token;
  await request.post(`${baseURL}/api/v1/policies`, { headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    data: { namespace: NS, agent_class: CLS, enforcement_mode: "block", priority: 300, policy_name: NS, rego_source: REGO } });
});
test.afterAll(async ({ request, baseURL }) => {
  const tok = (await (await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } })).json()).access_token;
  const h = { Authorization: `Bearer ${tok}` };
  await request.delete(`${baseURL}/api/v1/policies/${NS}/${CLS}`, { headers: h });
  await request.put(`${baseURL}/api/v1/settings?namespace=${NS}`, { headers: { ...h, "Content-Type": "application/json" }, data: { enforcement_mode: "block" } });
});

test("the Governance Block⇄Monitor toggle drives the live enforcement effect", async ({ page }) => {
  await realLogin(page);
  expect(await evalTool(page, "delete_record")).toBe("block/gov_block");   // seed enforces

  await page.goto("/policies/targets");
  await pickNamespace(page, NS);
  // The enforcement toggle shows Block/Monitor (not a read-only label).
  await expect(page.getByTestId("enforcement-mode-audit")).toHaveText("Monitor", { timeout: 15000 });

  // Drive Monitor → the blocked tool now softens to allow-but-log.
  const putMon = page.waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByTestId("enforcement-mode-audit").click();
  await putMon;
  await expect.poll(() => evalTool(page, "delete_record"), { timeout: 10000 }).toBe("audit/monitor_would_block:gov_block");

  // The hierarchy Mode column agrees (Monitor).
  await page.goto("/policies/catalog?tab=catalog");
  await pickNamespace(page, NS);
  await expect(page.getByTestId("policy-hierarchy-mode").first()).toHaveText("Monitor", { timeout: 15000 });

  // Back to Block → re-enforces.
  await page.goto("/policies/targets");
  await pickNamespace(page, NS);
  const putBlk = page.waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByTestId("enforcement-mode-block").click();
  await putBlk;
  await expect.poll(() => evalTool(page, "delete_record"), { timeout: 10000 }).toBe("block/gov_block");
});

test("apply-mode is relabelled Live/Frozen and gates applies only (live policy still enforces)", async ({ page }) => {
  await realLogin(page);
  await page.goto("/policies/targets");
  await pickNamespace(page, NS);
  await expect(page.getByTestId("apply-mode-enforce")).toHaveText("Live", { timeout: 15000 });
  await expect(page.getByTestId("apply-mode-dry_run_only")).toHaveText("Frozen");
  // Frozen gates policy edits, not traffic — the live seed policy still blocks.
  const putFrozen = page.waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByTestId("apply-mode-dry_run_only").click();
  await putFrozen;
  expect(await evalTool(page, "delete_record")).toBe("block/gov_block");   // traffic unaffected by Frozen
  // restore Live
  const putLive = page.waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByTestId("apply-mode-enforce").click();
  await putLive;
});
