// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// UI-AUDIT round 3 — Wave 1 (correctness) E2E. Drives the REAL SPA (nginx) + API on the live kind cluster
// and asserts the EFFECT (not 200s) for the three HIGH correctness fixes:
//   FIX-1  namespace=all resolves the real loaded policy (deny_shell_execution), same as namespace=default;
//          Target Settings "Effective policy" shows the real layer stack under All namespaces (not the empty
//          "No policy layers in force" state).
//   FIX-2  Policy apply surfaces an outcome the card consumes (last_applied populated); a forced failure
//          (reserved managed scope) returns a structured, visible failure — never a silent 200/close.
//   FIX-3  A clean search_kb evaluation returns a real decision (never evaluator_error); the engine-error
//          class is exposed as its own /audit/stats signal, distinct from policy blocks.
//
// Effects are proven with in-page fetches (they inherit the SPA's localStorage token + same origin, so the
// nginx /api proxy reaches the API) — the same requests the console makes. Component rendering of the panels
// is covered by the vitest suites (TargetSettings.test.tsx, PolicyCatalog.test.tsx, ApplyResultPanel.test.tsx).

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

type EvalResult = { status: number; decision?: string; rule_id?: string };

async function evaluate(page: Page, namespace: string, tool: string, params: Record<string, unknown>): Promise<EvalResult> {
  return page.evaluate(
    async ({ namespace, tool, params }) => {
      const token = localStorage.getItem("nrvq_token");
      const res = await fetch("/api/v1/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({
          tool_name: tool,
          tool_params: params,
          agent_identity: {
            spiffe_id: `spiffe://norviq/ns/${namespace}/sa/customer-support`,
            namespace,
            agent_class: "customer-support",
          },
          framework: "sdk",
        }),
      });
      const body = (await res.json()) as { decision?: string; rule_id?: string };
      return { status: res.status, decision: body.decision, rule_id: body.rule_id };
    },
    { namespace, tool, params }
  );
}

async function apiJson(page: Page, path: string): Promise<{ status: number; body: any }> {
  return page.evaluate(async (path) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
}

test.describe("UI-AUDIT r3 Wave-1 correctness — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    // Establish the app origin so in-page fetches carry the SPA's localStorage token through the nginx proxy.
    await page.goto("/policies/catalog");
    await waitForApp(page);
  });

  test("FIX-1: Policy Tester namespace=all resolves the SAME real rule as namespace=default", async ({ page }) => {
    const drop = { query: "DROP TABLE customers; --" };
    const def = await evaluate(page, "default", "execute_sql", drop);
    const all = await evaluate(page, "all", "execute_sql", drop);

    // namespace=default returns the real loaded rule (the pre-fix baseline).
    expect(def.decision).toBe("block");
    expect(def.rule_id).toBe("deny_shell_execution");

    // FIX-1: namespace=all now resolves the same real rule — NOT the pre-fix no_policy_loaded fall-through.
    expect(all.decision).toBe(def.decision);
    expect(all.rule_id).toBe(def.rule_id);
    expect(all.rule_id).not.toBe("no_policy_loaded");
  });

  test("FIX-1: Target Settings effective policy shows the real layer stack under All namespaces", async ({ page }) => {
    // The endpoint is the exact source of truth the Target Settings table renders from.
    const eff = await apiJson(page, "/api/v1/policies/effective?namespace=all&agent_class=customer-support");
    expect(eff.status).toBe(200);
    const layers: Array<{ scope: string }> = eff.body?.layers ?? [];
    expect(layers.length).toBeGreaterThan(0); // NOT "No policy layers in force"
    expect(layers.some((l) => l.scope.endsWith(":customer-support"))).toBeTruthy();

    // And the page itself renders without the spurious empty state for an enforcing class under All namespaces.
    await page.goto("/policies/targets");
    await waitForApp(page);
    await expect(page.getByText(/no policy layers in force/i)).toHaveCount(0);
  });

  test("FIX-3: a clean search_kb evaluation is a real decision, never evaluator_error", async ({ page }) => {
    const r = await evaluate(page, "default", "search_kb", { q: "password reset link" });
    expect(r.status).toBe(200);
    expect(r.rule_id).not.toBe("evaluator_error");
    expect(["allow", "escalate"]).toContain(r.decision);
  });

  test("FIX-3: /audit/stats exposes engine_errors as a distinct signal (not folded into blocks)", async ({ page }) => {
    const s = await apiJson(page, "/api/v1/audit/stats?range=30d");
    expect(s.status).toBe(200);
    expect(s.body).toHaveProperty("engine_errors");
    expect(typeof s.body.engine_errors).toBe("number");
    // engine errors are a strict subset of blocks — never larger than the block count.
    expect(s.body.engine_errors).toBeLessThanOrEqual(s.body.blocked);
  });

  test("FIX-2: apply populates last_applied (card data) and a forced failure is a structured, visible failure", async ({ page }) => {
    const cls = `wave1e2e-${Date.now()}`;
    const rego =
      'package norviq.strict\n' +
      'default decision = "allow"\n' +
      'decision = "block" { input.tool_name == "delete_record" }\n' +
      'rule_id = "e2e_block" { input.tool_name == "delete_record" }\n' +
      'reason = "e2e demo" { input.tool_name == "delete_record" }\n';

    // Apply (create) a policy — the same gated write the Editor's Confirm-Apply performs.
    const created = await page.evaluate(
      async ({ cls, rego }) => {
        const token = localStorage.getItem("nrvq_token");
        const res = await fetch("/api/v1/policies", {
          method: "POST",
          headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
          body: JSON.stringify({
            namespace: "default", agent_class: cls, rego_source: rego,
            enforcement_mode: "block", priority: 700, policy_name: cls,
          }),
        });
        return res.status;
      },
      { cls, rego }
    );
    expect(created).toBe(200);

    // The Catalog card's data source now carries last_applied for the applied policy (the "reflects reality" fix).
    const list = await apiJson(page, "/api/v1/policies?namespace=default");
    const row = (list.body as Array<{ agent_class: string; last_applied?: string }>).find((p) => p.agent_class === cls);
    expect(row).toBeTruthy();
    expect(row?.last_applied).toBeTruthy();

    // Forced FAILURE: applying to a reserved managed scope must return a structured failure (not a silent close).
    const fail = await page.evaluate(async () => {
      const token = localStorage.getItem("nrvq_token");
      const res = await fetch("/api/v1/policies/default/__baseline__/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ target_type: "agent_class", target_namespace: "default", enforcement_mode: "block" }),
      });
      return { status: res.status, body: await res.json().catch(() => null) };
    });
    expect(fail.status).toBeGreaterThanOrEqual(400);
    expect(String(fail.body?.detail ?? "")).toMatch(/managed scope/i);

    // Cleanup the throwaway policy so the suite stays idempotent.
    await page.evaluate(async (cls) => {
      const token = localStorage.getItem("nrvq_token");
      await fetch(`/api/v1/policies/default/${cls}`, { method: "DELETE", headers: token ? { Authorization: `Bearer ${token}` } : {} });
    }, cls);
  });
});
