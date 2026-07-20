// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// New Policy composer MANUAL agent-class entry. Proves the fix end-to-end on the REAL app+engine:
//   1. The agent-class field is a real editable input (not the old dead-end fake dropdown) and works even
//      with NO labeled deployment for the class.
//   2. Driving the composer UI for a brand-new manual class + Confirm Apply CREATES an enforcing policy.
//   3. The EFFECT is proven by a before/after /evaluate decision-FLIP on the running engine (NOT a 200):
//      a call for the manual class carrying the configured keyword goes allow → block with the composer rule_id.
//
// The class name is UNIQUE per run (timestamp) so it is guaranteed to have NO matching deployment and NO
// prior agent registration — the empty-state assertion is deterministic. It never touches customer-support.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

const NS = "default";
const KEYWORD = "q2probe";
const TOOL = "q2probe_run";

// Mirror ui/src/lib/composerRego.ts sanitizeClassToken so we can predict the generated rule_id.
function token(cls: string): string {
  const t = cls.toLowerCase().replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  return t || "class";
}

async function api(page: Page, path: string, method = "GET", body?: unknown): Promise<{ status: number; body: any }> {
  return page.evaluate(async ({ path, method, body }) => {
    const t = localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", ...(t ? { Authorization: `Bearer ${t}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}
async function ev(page: Page, cls: string, tool: string, params: Record<string, unknown>) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: params,
    agent_identity: { spiffe_id: `spiffe://norviq/ns/${NS}/sa/${cls}`, namespace: NS, agent_class: cls },
    session_id: "q2-composer", trust_score: 0.8, chain_depth: 0
  });
  return { decision: r.body?.decision, rule_id: r.body?.rule_id };
}

test.describe("composer manual-class entry creates an enforcing policy (real /evaluate flip)", () => {
  test("manual class with no deployment → Confirm Apply → allow flips to block on the engine", async ({ page }) => {
    const CLS = `q2-manual-${Date.now()}`;
    const BLOCK_RULE = `composer_block_${token(CLS)}`;

    await page.goto("/policies/catalog");
    await waitForApp(page);

    // Drive the composer UI for a class that has NO labeled deployment and NO prior registration.
    await page.getByRole("button", { name: "New Policy" }).click();
    const classInput = page.getByTestId("composer-agent-class-input");
    await expect(classInput).toBeVisible();
    expect(await classInput.evaluate((el) => el.tagName)).toBe("INPUT"); // a real input, not a fake dropdown
    // with nothing typed, the empty-state invites manual entry rather than dead-ending
    await expect(page.getByTestId("composer-no-deployments")).toContainText(/Type an agent-class name/i);
    await classInput.fill(CLS);
    // still no matching deployment → the empty-state now confirms the manual class is authorable anyway
    await expect(page.getByTestId("composer-no-deployments")).toContainText(CLS);

    // BEFORE (baseline): nothing authored for this brand-new class → the keyword call is NOT our block.
    const before = await ev(page, CLS, TOOL, { note: "hello" });
    expect(before.rule_id).not.toBe(BLOCK_RULE);

    // set a NOVEL block keyword so the flip is unambiguously OUR policy (baseline never blocks q2probe)
    await page.getByText("Custom Parameters").click();
    const kw = page.locator(".field-row", { hasText: "Block keywords" }).getByRole("textbox");
    await kw.fill(KEYWORD);

    // Apply → review → Confirm Apply creates the policy (create() enforces on the read path).
    // Scope to the composer sheet — the editor pane also has an "Apply" button on the same page.
    const sheet = page.locator(".sheet-kit");
    await sheet.getByRole("button", { name: "Apply" }).click();
    const [createResp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/v1/policies") && r.request().method() === "POST"),
      sheet.getByRole("button", { name: "Confirm Apply" }).click()
    ]);
    expect(createResp.ok()).toBeTruthy();
    await expect(page.getByText(new RegExp(`Created ${NS}/${CLS}`, "i"))).toBeVisible({ timeout: 8000 });

    // AFTER (EFFECT, not a 200): the same call for the manual class is now BLOCKED by the composer policy.
    const after = await ev(page, CLS, TOOL, { note: "hello" });
    expect(after.decision).toBe("block");
    expect(after.rule_id).toBe(BLOCK_RULE);

    // control: a benign call with no keyword for the same class is NOT blocked by our policy (tighten-only)
    const benign = await ev(page, CLS, "list_items", { note: "hello" });
    expect(benign.rule_id).not.toBe(BLOCK_RULE);

    // cleanup
    await api(page, `/api/v1/policies/${NS}/${CLS}`, "DELETE");
  });
});
