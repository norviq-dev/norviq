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
/**
 * Wait for a pushed policy to be LIVE, then return the decision.
 *
 * `beforeAll` POSTs the governance policy and the first assertion evaluated immediately. A policy
 * push is not synchronous with the engine's view of it — the loader picks it up on its own schedule —
 * so `block/no_policy_loaded` is a legitimate TRANSIENT after a push, not a wrong answer. On kind the
 * window was short enough to hide the race; on a slower cluster the first evaluate lands inside it
 * and the test fails naming the wrong thing ("the toggle is broken" when the toggle is fine).
 *
 * Note it still asserts a BLOCK either way — `no_policy_loaded` is itself fail-closed, so nothing here
 * is waiting for enforcement to "turn on". It is waiting for the engine to be reading the policy this
 * test is about, which is the pre-condition, not the behaviour.
 *
 * This is the repo's own documented rule — poll, never sleep-once, after a policy push.
 */
async function evalToolWhenLoaded(page: Page, tool: string, expected: string, timeout = 30_000) {
  let last = "";
  await expect
    .poll(async () => { last = await evalTool(page, tool); return last; },
          { timeout, message: `policy never became live; last decision was ${last}` })
    .toBe(expected);
  return last;
}

async function pickNamespace(page: Page, ns: string) {
  await page.locator("button.cluster-sel").click();
  await expect(page.locator(".cluster-dd")).toBeVisible({ timeout: 8000 });
  await page.locator(".cluster-dd .dd-item").filter({ hasText: new RegExp(`^${ns}$`) }).first().click();
  await expect(page.locator("button.cluster-sel")).toContainText(ns, { timeout: 8000 });
}

test.beforeAll(async ({ request, baseURL }) => {
  const tok = (await (await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } })).json()).access_token;
  const h = { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" };

  // THAW FIRST. This test deliberately freezes its own namespace (apply_mode: dry_run_only) to prove
  // that freezing gates policy APPLIES without touching live traffic — and it restores that by
  // CLICKING the UI at the end. If it ever fails before that click, the namespace stays frozen, and
  // every subsequent run's seed below is refused with 409 ("policy applies are disabled").
  await request.put(`${baseURL}/api/v1/settings?namespace=${NS}`, { headers: h,
    data: { apply_mode: "enforce", enforcement_mode: "block" } });

  // ASSERT THE SEED LANDED. This POST's status was ignored, so a 409 was swallowed and the tests ran
  // against a namespace with NO policy — reporting `block/no_policy_loaded` from the first assertion,
  // which reads as "the Block/Monitor toggle is broken" when the toggle is fine and the fixture was
  // never allowed to land. A seed that silently fails is worse than one that throws: it moves the
  // failure to a line that has nothing to do with the cause.
  const seeded = await request.post(`${baseURL}/api/v1/policies`, { headers: h,
    data: { namespace: NS, agent_class: CLS, enforcement_mode: "block", priority: 300, policy_name: NS, rego_source: REGO } });
  expect(seeded.status(), `seed policy POST failed: ${await seeded.text()}`).toBeLessThan(300);
});
test.afterAll(async ({ request, baseURL }) => {
  const tok = (await (await request.post(`${baseURL}/api/v1/auth/login`, { data: { username: "admin", password: PW } })).json()).access_token;
  const h = { Authorization: `Bearer ${tok}` };
  await request.delete(`${baseURL}/api/v1/policies/${NS}/${CLS}`, { headers: h });
  // apply_mode TOO. Restoring only enforcement_mode left the namespace Frozen, which is the state
  // that poisons the next run's seed.
  await request.put(`${baseURL}/api/v1/settings?namespace=${NS}`, { headers: { ...h, "Content-Type": "application/json" }, data: { apply_mode: "enforce", enforcement_mode: "block" } });
});

test("the Governance Block⇄Monitor toggle drives the live enforcement effect", async ({ page }) => {
  await realLogin(page);
  await evalToolWhenLoaded(page, "delete_record", "block/gov_block");   // seed enforces (poll: a push is not instantly live)

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
  await evalToolWhenLoaded(page, "delete_record", "block/gov_block");   // traffic unaffected by Frozen
  // restore Live
  const putLive = page.waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", { timeout: 15000 });
  await page.getByTestId("apply-mode-enforce").click();
  await putLive;
});
