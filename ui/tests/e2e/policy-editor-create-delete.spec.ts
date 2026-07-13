// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// BATCH-B — Policy Editor CREATE (raw rego) + DELETE (guardrails) + the DELETE reserved-scope guard.
//
// A 200 is NOT proof. Every mutation is driven through the REAL UI (or the exact client/API contract) and its
// EFFECT is proven INDEPENDENTLY via a before/after /evaluate decision-FLIP on the discriminator rule_id
// (custom_block_rule) on the running engine:
//   • B-1 create-from-editor  → the new class's OWN rule fires (not baseline / no_policy_loaded).
//   • B-2 delete              → the class FLIPS BACK (its rule no longer fires) — a true un-load, durable.
//   • B-2 reserved            → reserved rows show NO delete affordance.
//   • B-3 reserved DELETE     → refused server-side (422), baseline left intact.
// Everything runs on THROWAWAY classes in `default` and cleans up in `finally` — it NEVER mutates
// customer-support (the attack-suite class): the only thing done to it is a READ (/evaluate) and a REFUSED
// baseline delete (which the B-3 guard blocks, so its baseline is untouched).

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
async function ev(page: Page, ns: string, cls: string, tool: string) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: { x: 1 },
    agent_identity: { spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`, namespace: ns, agent_class: cls },
    session_id: "bce2e", trust_score: 0.8, chain_depth: 0
  });
  return { decision: r.body?.decision, rule_id: r.body?.rule_id };
}

// The SAME raw rego the editor seeds a new policy with (NEW_POLICY_REGO): blocks delete_database under the
// discriminator rule_id `custom_block_rule`. Used verbatim for the API-seeded throwaway policies so the
// /evaluate assertions are identical whether created via the UI or the API.
const REGO = [
  "package norviq.custom",
  'default decision = "allow"',
  'rule_id = "custom_block_rule"',
  'reason = "blocked by a custom policy"',
  'decision = "block" { input.tool_name == "delete_database" }'
].join("\n");
const RULE = "custom_block_rule";
const TOOL = "delete_database";

test.describe("Policy Editor — create (raw rego) + delete (guardrails), proven on the live engine", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/policies/catalog");
    await waitForApp(page);
  });

  test("B-1: New policy in the editor authors raw rego and ENFORCES on the running engine (rule flip)", async ({ page, recorder }) => {
    const NS = "default", CLS = "bce2e-create";
    try {
      // BEFORE: the throwaway class does not yet enforce our rule.
      expect((await ev(page, NS, CLS, TOOL)).rule_id).not.toBe(RULE);

      // Drive the REAL UI: rail "New policy" → scope fields → Create (the seeded template blocks delete_database).
      await page.getByTestId("editor-new-policy").click();
      await expect(page.getByTestId("new-policy-fields")).toBeVisible();
      await page.getByTestId("new-policy-namespace").fill(NS);
      await page.getByTestId("new-policy-class").fill(CLS);
      await page.getByTestId("editor-save-policy").click();

      // APPEARS IN LIST: the new class shows in the editor rail (admin "all" view lists every namespace).
      await expect(page.getByText(`${CLS}.rego`)).toBeVisible({ timeout: 10000 });

      // ENFORCES: independent cluster read — the new policy's OWN rule now fires (poll for the loader to pick it up).
      await expect.poll(async () => (await ev(page, NS, CLS, TOOL)).rule_id, { timeout: 20000 }).toBe(RULE);
      expect((await ev(page, NS, CLS, TOOL)).decision).toBe("block");
      recorder.expectNoConsoleErrors();
      recorder.expectNoApiFailures();
    } finally {
      await api(page, `/api/v1/policies/${NS}/${CLS}`, "DELETE");
    }
  });

  test("B-2: deleting from the catalog confirms ns+class+version + enforcing warning and FLIPS /evaluate back", async ({ page, recorder }) => {
    const NS = "default", CLS = "bce2e-delete";
    try {
      // Seed an enforcing throwaway policy (fast, deterministic) and confirm it enforces.
      expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: CLS, rego_source: REGO, enforcement_mode: "block" })).status).toBe(200);
      await expect.poll(async () => (await ev(page, NS, CLS, TOOL)).rule_id, { timeout: 20000 }).toBe(RULE);

      // Reload so the catalog reflects it, open the Catalog tab, use the per-row delete.
      await page.reload();
      await waitForApp(page);
      await page.getByRole("button", { name: /^catalog$/i }).click();
      await page.getByTestId(`catalog-delete-${CLS}`).click();

      // GUARDRAILS: the confirm names ns/class/version and carries the enforcing warning.
      const modal = page.getByTestId("delete-policy-modal");
      await expect(modal).toContainText(`${NS}/${CLS}`);
      await expect(modal).toContainText("v1");
      await expect(page.getByTestId("delete-policy-warning")).toContainText(/currently enforcing/i);
      await page.getByTestId("delete-policy-confirm").click();

      // EFFECT: the class FLIPS BACK — its own rule no longer fires (a true un-load, not a stale cache).
      await expect.poll(async () => (await ev(page, NS, CLS, TOOL)).rule_id, { timeout: 20000 }).not.toBe(RULE);
      // …and the row is gone from the catalog.
      await expect(page.getByTestId(`catalog-delete-${CLS}`)).toHaveCount(0);
      recorder.expectNoConsoleErrors();
      recorder.expectNoApiFailures();
    } finally {
      await api(page, `/api/v1/policies/${NS}/${CLS}`, "DELETE");
    }
  });

  test("B-2 audit + B-3: delete echoes the audited version; a reserved-scope DELETE is refused (422) and the baseline is left intact", async ({ page }) => {
    const NS = "default", CLS = "bce2e-audit";
    // The delete response echoes the audited scope + the version it destroyed (structlog records the same, NRVQ-API-7018).
    expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: CLS, rego_source: REGO, enforcement_mode: "block" })).status).toBe(200);
    const del = await api(page, `/api/v1/policies/${NS}/${CLS}`, "DELETE");
    expect(del.status).toBe(200);
    expect(del.body).toMatchObject({ deleted: true, namespace: NS, agent_class: CLS });
    expect(typeof del.body.version).toBe("number"); // the version removed — audited

    // B-3: a raw DELETE of a reserved/managed scope is refused server-side, and the baseline stays enforcing.
    const before = await ev(page, "default", "customer-support", "search_kb");
    const refused = await api(page, "/api/v1/policies/default/__baseline__", "DELETE");
    expect(refused.status).toBe(422);
    expect(String(refused.body?.detail)).toMatch(/managed scope/i);
    const after = await ev(page, "default", "customer-support", "search_kb");
    expect(after.rule_id).toBe(before.rule_id); // baseline untouched — the guard prevented the destructive delete
    // the reserved __cluster__ namespace is likewise refused.
    expect((await api(page, "/api/v1/policies/__cluster__/anything", "DELETE")).status).toBe(422);
  });

  test("B-2: reserved scopes show NO delete affordance (a normal class does)", async ({ page }) => {
    await page.getByRole("button", { name: /^catalog$/i }).click();
    // A normal class (the seeded customer-support) carries a delete control…
    await expect(page.getByTestId("catalog-delete-customer-support")).toBeVisible({ timeout: 8000 });
    // …but no reserved/managed scope ever does (baseline / pack / guardrail).
    await expect(page.getByTestId("catalog-delete-__baseline__")).toHaveCount(0);
    await expect(page.getByTestId("catalog-delete-__pack__")).toHaveCount(0);
  });
});
