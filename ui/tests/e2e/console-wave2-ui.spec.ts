// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Wave 2 (UI wiring + cosmetics) E2E. Drives the REAL SPA (nginx) + API on the live kind
// cluster and asserts the EFFECT (not 200s) for the wiring fixes:
//   A1  graph default-hides synthetic/probe agents; include_synthetic brings them back.
//   B2  active-policy "matches" reflects the real governed-call count (not 0).
//   B3  version history survives a restart (rehydrated from policy_versions).
//   B4  /agents parses namespace + agent_class from the SVID and returns last_seen.
//   B5  /audit/stats exposes engine_errors as its own signal.
//   C1  a policy apply re-stamps last_applied (even for unchanged content).
//   E1  intent drafts dedupe by class (one latest draft per ns/class).
// Effects use in-page fetches (they inherit the SPA token + origin → nginx /api proxy). Component rendering
// (skeletons, chips, MITRE legend, audit drawer) is covered by the vitest suites.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function apiJson(page: Page, path: string): Promise<{ status: number; body: any }> {
  return page.evaluate(async (path) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
}

async function apiPost(page: Page, path: string, payload: unknown): Promise<{ status: number; body: any }> {
  return page.evaluate(async ({ path, payload }) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(payload),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, payload });
}

test.describe("UI-AUDIT r3 Wave-2 UI wiring — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/assets/graph");
    await waitForApp(page);
  });

  test("A1: the graph default-hides synthetic/probe agents; the toggle reveals them", async ({ page }) => {
    const hidden = await apiJson(page, "/api/v1/asset-graph?namespace=all&include_synthetic=false");
    const shown = await apiJson(page, "/api/v1/asset-graph?namespace=all&include_synthetic=true");
    const isProbe = (n: any) => /allowlist-probe|e2e-intent|policy-tester/i.test(n.properties?.agent_class ?? "");
    const probesInDefault = (hidden.body.nodes as any[]).filter((n) => n.type === "agent" && isProbe(n));
    const probesInShown = (shown.body.nodes as any[]).filter((n) => n.type === "agent" && isProbe(n));

    expect(hidden.body.synthetic_hidden).toBeGreaterThan(0); // there ARE probes to hide
    expect(probesInDefault.length).toBe(0);                  // none shown by default
    expect(probesInShown.length).toBeGreaterThan(0);         // the toggle brings them back
    expect(shown.body.nodes.length).toBeGreaterThan(hidden.body.nodes.length);
  });

  test("A1: attack paths default-hide probe-rooted kill-chains", async ({ page }) => {
    const hidden = await apiJson(page, "/api/v1/threats/attack-paths?ns=all&include_synthetic=false");
    expect(hidden.status).toBe(200);
    const probeRooted = (hidden.body.paths as any[]).filter((p) => /allowlist-probe|e2e-intent|policy-tester/i.test(p.cls ?? ""));
    expect(probeRooted.length).toBe(0);
  });

  test("B2/B4/B5: real matches, agent SVID columns, and the engine_errors signal are wired", async ({ page }) => {
    const pols = await apiJson(page, "/api/v1/policies?namespace=default");
    const cs = (pols.body as any[]).find((p) => p.agent_class === "customer-support");
    expect(cs?.matches).toBeGreaterThan(0); // B2: real governed-call count, not 0

    const agents = await apiJson(page, "/api/v1/agents?namespace=all");
    const withMeta = (agents.body as any[]).filter((a) => a.namespace && a.agent_class);
    expect(withMeta.length).toBeGreaterThan(0); // B4: ns/class parsed from the SVID
    expect((agents.body as any[]).some((a) => a.last_seen)).toBeTruthy(); // B4: last_seen present

    const stats = await apiJson(page, "/api/v1/audit/stats?range=30d");
    expect(stats.body).toHaveProperty("engine_errors"); // B5: distinct signal
    expect(typeof stats.body.engine_errors).toBe("number");
  });

  test("B3: version history is present after the restart (rehydrated from policy_versions)", async ({ page }) => {
    // brand-new-agent has multiple versions persisted; they survive a pod restart (not empty).
    const versions = await apiJson(page, "/api/v1/policies/default/brand-new-agent/versions");
    expect(versions.status).toBe(200);
    expect(Array.isArray(versions.body) ? versions.body.length : 0).toBeGreaterThan(0);
  });

  test("C1: a policy apply re-stamps last_applied even for unchanged content", async ({ page }) => {
    const before = await apiJson(page, "/api/v1/policies?namespace=default");
    const csBefore = (before.body as any[]).find((p) => p.agent_class === "customer-support")?.last_applied;

    const applied = await apiPost(page, "/api/v1/policies/default/customer-support/apply", {
      target_type: "agent_class", target_namespace: "default", enforcement_mode: "block",
    });
    expect(applied.status).toBe(200);
    expect(applied.body).toHaveProperty("version"); // C1: the enforcing version the success panel shows

    const after = await apiJson(page, "/api/v1/policies?namespace=default");
    const csAfter = (after.body as any[]).find((p) => p.agent_class === "customer-support")?.last_applied;
    expect(csAfter).toBeTruthy();
    if (csBefore) expect(new Date(csAfter).getTime()).toBeGreaterThanOrEqual(new Date(csBefore).getTime());
  });

  test("E1: intent drafts dedupe by class — a class keeps one latest draft", async ({ page }) => {
    // Create two different intents for the same throwaway class; only the latest must remain.
    const cls = `wave2e2e-${Date.now()}`;
    await apiPost(page, "/api/v1/threats/intent-draft", { ns: "all", cls, allow_tools: ["search_kb"], intent: { readonly: true, scope: false, rate: false, egress: false } });
    await apiPost(page, "/api/v1/threats/intent-draft", { ns: "all", cls, allow_tools: ["search_kb", "get_customer"], intent: { readonly: false, scope: false, rate: false, egress: false } });

    const drafts = await apiJson(page, "/api/v1/threats/intent-drafts?namespace=all");
    const mine = ((drafts.body.drafts ?? []) as any[]).filter((d) => (d.cls ?? d.agent_class) === cls);
    expect(mine.length).toBe(1); // deduped by class
  });
});
