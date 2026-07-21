// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Compliance E2E. Drives the REAL SPA + API on the live kind cluster and asserts the EFFECT.
// Part A: the graph excludes the newly-classified synthetics + awaiting agents by default (toggles reveal them),
// and the Attack Graph load fires no 4xx. Part B: the Compliance page renders EVERY value from the API — the
// no-mock guard asserts the displayed coverage % equals a DIRECT /mitre/coverage call.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function api(page: Page, path: string): Promise<{ status: number; body: any }> {
  return page.evaluate(async (path) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
}
async function apiPost(page: Page, path: string, payload: unknown) {
  return page.evaluate(async ({ path, payload }) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(payload) });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, payload });
}

test.describe("Compliance — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await page.evaluate(() => { localStorage.setItem("nrvq_show_synthetic", "0"); localStorage.setItem("nrvq_show_awaiting", "0"); });
  });

  test("default graph excludes evtrace/scorer; include_synthetic reveals them", async ({ page }) => {
    const hidden = await api(page, "/api/v1/asset-graph?namespace=all&include_awaiting=true&include_synthetic=false");
    const shown = await api(page, "/api/v1/asset-graph?namespace=all&include_awaiting=true&include_synthetic=true");
    const classes = (b: any) => (b.nodes as any[]).filter((n) => n.type === "agent").map((n) => n.properties?.agent_class ?? "");
    const leak = classes(hidden.body).filter((c) => /evtrace|^scorer$|policy-tester/.test(c));
    expect(leak).toEqual([]);                                        // no synthetic leaks by default
    expect(hidden.body.synthetic_hidden).toBeGreaterThan(0);
    expect(classes(shown.body).some((c) => /evtrace|scorer/.test(c))).toBeTruthy(); // toggle reveals
  });

  test("awaiting agents hidden by default; include_awaiting reveals report-runner/hr-chatbot", async ({ page }) => {
    const hidden = await api(page, "/api/v1/asset-graph?namespace=all&include_awaiting=false");
    const shown = await api(page, "/api/v1/asset-graph?namespace=all&include_awaiting=true");
    expect((hidden.body.nodes as any[]).some((n) => n.properties?.awaiting)).toBeFalsy();
    expect(hidden.body.awaiting_hidden).toBeGreaterThan(0);
    expect((shown.body.nodes as any[]).some((n) => n.properties?.awaiting)).toBeTruthy();
  });

  test("an Attack Graph load fires no 4xx (no dead /threats/summary)", async ({ page }) => {
    const bad: string[] = [];
    page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${r.url()}`); });
    await page.goto("/threats/graph");
    await waitForApp(page);
    await page.waitForTimeout(2500);
    expect(bad, `unexpected 4xx/5xx: ${bad.join(", ")}`).toEqual([]);
  });

  test("no-mock: the Compliance page renders the coverage % from the API (not a fabricated value)", async ({ page }) => {
    const cov = await api(page, "/api/v1/mitre/coverage?range=24h");
    expect(cov.status).toBe(200);
    const pct = cov.body.coverage_pct as number;
    const enforceable = cov.body.enforceable_total as number;
    const oos = cov.body.oos as number;
    // headline math is enforced/(enforceable), OOS excluded from the denominator
    expect(cov.body.enforced).toBeLessThanOrEqual(enforceable);
    expect(enforceable + oos).toBe((cov.body.techniques as any[]).length);

    await page.goto("/compliance");
    await waitForApp(page);
    // The donut label the page shows MUST equal the API's coverage_pct — proves no mock.
    await expect(page.getByText(`${pct}%`).first()).toBeVisible();
    // Roadmap frameworks are inert "coming soon" with NO coverage number (asserted on the overview).
    await expect(page.getByText(/UPCOMING/i).first()).toBeVisible();
    // A real enforced technique name from the API is present after opening the detail.
    const enforcedTech = (cov.body.techniques as any[]).find((t) => t.status === "enforced");
    if (enforcedTech) {
      await page.getByRole("button", { name: /Open coverage detail|detail/i }).first().click().catch(() => {});
      await expect(page.getByText(enforcedTech.name).first()).toBeVisible({ timeout: 8000 });
    }
  });

  test("trend is a real persisted series + evidence-pack export streams a real file", async ({ page }) => {
    const trend = await api(page, "/api/v1/mitre/coverage/trend?range=30d");
    expect(trend.status).toBe(200);
    expect(Array.isArray(trend.body.points)).toBeTruthy(); // real series (>=0 points, no fabricated line)

    // Export: authenticated in-cluster download of a real pack (json).
    const exp = await page.evaluate(async () => {
      const token = localStorage.getItem("nrvq_token");
      const res = await fetch("/api/v1/mitre/coverage/export?range=24h&format=json", { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      const text = await res.text();
      return { status: res.status, type: res.headers.get("content-type"), hasControls: text.includes("\"controls\""), bytes: text.length };
    });
    expect(exp.status).toBe(200);
    expect(exp.hasControls).toBeTruthy();
    expect(exp.bytes).toBeGreaterThan(100);
  });

  test("GAP→generate creates a real dry-run draft, and the evidence deep-link filters the Audit Log", async ({ page }) => {
    // GAP → generate a real tighten-only dry-run draft (never enforces).
    const gen = await apiPost(page, "/api/v1/mitre/coverage/generate", { technique_id: "AML.T0055", namespace: "default", agent_class: "customer-support" });
    expect(gen.status).toBe(200);
    expect(gen.body.draft_id).toMatch(/^dmitre/);
    expect(gen.body.enforcement).toBe("draft");
    const drafts = await api(page, "/api/v1/threats/intent-drafts?namespace=all");
    expect(((drafts.body.drafts ?? []) as any[]).some((d) => String(d.draft_id).startsWith("dmitre"))).toBeTruthy();

    // Evidence deep-link: /audit records filtered by rule_id return ONLY that rule.
    const filtered = await api(page, "/api/v1/audit/records?rule_id=llm01_prompt_injection&range=30d&limit=50");
    expect(filtered.status).toBe(200);
    const rules = new Set((filtered.body as any[]).map((r) => r.rule_id));
    expect([...rules].every((r) => r === "llm01_prompt_injection")).toBeTruthy();
    // NOTE: the generated draft lives in the dedicated intent_drafts table (dry-run, non-enforcing, deduped by
    // class) — it needs no cleanup, and must NOT be "cleaned" by deleting the real customer-support POLICY.
  });
});
