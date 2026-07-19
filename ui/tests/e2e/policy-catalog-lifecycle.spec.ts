// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// POLICY-CATALOG DRAFTS LIFECYCLE + RETENTION + the CRITICAL apply→cluster enforcement proof (Parts A/B/C).
//
// Part C is the primary: applying a policy from the portal must ACTUALLY enforce on the running engine — a 200 is
// NOT proof. This drives the SAME apply the Policy Catalog's Confirm-Apply issues (POST /policies/{ns}/{cls}/apply
// with the target scope) and INDEPENDENTLY verifies the EFFECT via a before/after /evaluate decision-flip: the
// applied policy's own rule_id fires at the target (NOT `no_policy_loaded`). This is the exact regression that
// fails if apply stops reaching the engine (e.g. apply writing to the evaluator's unread dict). A
// THROWAWAY class is used and cleaned up — never customer-support (the attack-suite class), which a default-deny
// would break.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function api(page: Page, path: string, method = "GET", body?: unknown): Promise<{ status: number; body: any }> {
  return page.evaluate(async ({ path, method, body }) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, method, body });
}
async function evaluate(page: Page, ns: string, cls: string, tool: string) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: { x: 1 },
    agent_identity: { spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`, namespace: ns, agent_class: cls },
    session_id: "lc-e2e", trust_score: 0.8, chain_depth: 0
  });
  return { decision: r.body?.decision, rule_id: r.body?.rule_id };
}

const REGO = [
  "package norviq.intent.lce2e",
  'default decision = "allow"',
  'default rule_id = "lce2e_allow"',
  'default reason = "lc allow"',
  'decision = "block" { input.tool_name == "delete_database" }',
  'rule_id = "lce2e_block_delete" { input.tool_name == "delete_database" }',
  'reason = "lc blocked" { input.tool_name == "delete_database" }'
].join("\n");

test.describe("Policy Catalog — drafts lifecycle, retention & the apply→cluster enforcement proof", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
  });

  test("PART C (primary): applying from the portal ACTUALLY enforces at the target — before/after /evaluate flip", async ({ page }) => {
    const SRC = "lce2e-src", DST = "lce2e-dst", CLS = "lce2e-agent", TOOL = "delete_database";
    try {
      // BEFORE: the target scope has no policy → `delete_database` is not enforced by any lce2e rule.
      const before = await evaluate(page, DST, CLS, TOOL);
      expect(before.rule_id).not.toBe("lce2e_block_delete");

      // Save (create) the blocking policy at the SOURCE — the portal's Save path.
      expect((await api(page, "/api/v1/policies", "POST",
        { namespace: SRC, agent_class: CLS, rego_source: REGO, enforcement_mode: "block" })).status).toBe(200);
      // Sanity: it enforces at the source.
      expect((await evaluate(page, SRC, CLS, TOOL)).rule_id).toBe("lce2e_block_delete");

      // APPLY to the target scope — the EXACT call the Policy Catalog's Confirm-Apply issues.
      const applied = await api(page, `/api/v1/policies/${SRC}/${CLS}/apply`, "POST",
        { target_type: "agent_class", target_namespace: DST, target_name: CLS, enforcement_mode: "block" });
      expect(applied.status).toBe(200);
      expect(applied.body.applied).toBe(true);

      // AFTER (independent cluster read via /evaluate): the applied policy's OWN rule now fires at the target —
      // NOT `no_policy_loaded`. This is the decision-flip proof; a 200 alone would not catch the old no-op bug.
      const after = await evaluate(page, DST, CLS, TOOL);
      expect(after.decision).toBe("block");
      expect(after.rule_id).toBe("lce2e_block_delete");
    } finally {
      await api(page, `/api/v1/policies/${SRC}/${CLS}`, "DELETE");
      await api(page, `/api/v1/policies/${DST}/${CLS}`, "DELETE");
    }
  });

  test("PART C negative: an un-applied dry-run draft NEVER enforces", async ({ page }) => {
    // A compliance gap generates a default-deny DRAFT for customer-support — but a draft lives in intent_drafts,
    // which the evaluator never reads. So a normal customer-support call is unaffected (not intent_default_deny).
    await api(page, "/api/v1/compliance/owasp/generate", "POST", { technique_id: "LLM07:2025", namespace: "default" });
    const ev = await evaluate(page, "default", "customer-support", "search_kb");
    expect(ev.rule_id).not.toBe("intent_default_deny");
  });

  test("PART B: drafts endpoint is bounded + TTL-stamped; dismiss + GC work", async ({ page }) => {
    const gen = await api(page, "/api/v1/compliance/owasp/generate", "POST", { technique_id: "LLM07:2025", namespace: "default" });
    const draftId = gen.body.draft_id as string;

    // B6: the endpoint returns a BOUNDED page + a total count — not the whole list.
    const list = await api(page, "/api/v1/threats/intent-drafts?ns=default");
    expect(Array.isArray(list.body.drafts)).toBe(true);
    expect(typeof list.body.total).toBe("number");
    expect(list.body.limit).toBeGreaterThan(0);
    // B1: the draft carries a TTL expiry (real window = future date).
    const mine = (list.body.drafts as any[]).find((d) => d.draft_id === draftId);
    expect(mine?.expires_at).toBeTruthy();
    expect(Date.parse(mine.expires_at)).toBeGreaterThan(Date.now());

    // B7: dismiss removes it; GET then 404.
    expect((await api(page, `/api/v1/threats/intent-drafts/${draftId}`, "DELETE")).body.dismissed).toBe(true);
    expect((await api(page, `/api/v1/threats/intent-drafts/${draftId}`)).status).toBe(404);
    // GC endpoint responds with a cleared count.
    expect(typeof (await api(page, "/api/v1/threats/intent-drafts/gc?ns=default", "POST")).body.cleared).toBe("number");
  });

  test("PART A: the drafts inbox renders grouped by source, with status pill + provenance + dismiss control", async ({ page }) => {
    // Ensure a compliance-tagged draft exists, then open the Policy Catalog.
    const gen = await api(page, "/api/v1/compliance/owasp/generate", "POST", { technique_id: "LLM07:2025", namespace: "default" });
    const draftId = gen.body.draft_id as string;
    const bad: string[] = [];
    page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${r.url()}`); });

    await page.goto(`/policies/catalog?intent_draft=${encodeURIComponent(draftId)}`);
    await waitForApp(page);
    await page.waitForTimeout(1200);

    // A1: the compliance draft is grouped under "From Compliance gaps".
    await expect(page.getByTestId("draft-group-compliance")).toBeVisible({ timeout: 8000 });
    // A4: the subtitle reflects BOTH sources, not just the Attack Graph.
    await expect(page.getByText(/Attack Graph and Compliance gaps/i)).toBeVisible();
    // A2: the draft row shows a lifecycle status pill + a target-linkage line.
    await expect(page.getByTestId(`intent-draft-status-${draftId}`)).toBeVisible();
    await expect(page.getByTestId(`intent-draft-target-${draftId}`)).toContainText("would apply to agent-class");
    // F2 provenance still renders; A5 filter chips present; B7 per-draft dismiss present.
    await expect(page.getByTestId(`intent-draft-source-${draftId}`)).toContainText("LLM07:2025");
    await expect(page.getByTestId("draft-filter-new")).toBeVisible();
    await expect(page.getByTestId(`intent-draft-dismiss-${draftId}`)).toBeVisible();
    expect(bad, `unexpected 4xx/5xx on the catalog: ${bad.join(", ")}`).toEqual([]);

    // cleanup the demo draft
    await api(page, `/api/v1/threats/intent-drafts/${draftId}`, "DELETE");
  });
});
