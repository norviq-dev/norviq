// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// FABLE AUDIT — APPLY-PER-SURFACE ENFORCEMENT GATE (the durable net that CANNOT be skipped).
//
// For EVERY policy-mutation surface (Save/create, Apply-to-target, pack enable/disable, tighten-only override +
// revert, weaken overlay, rollback) this drives the mutation through the EXACT client/API contract the UI uses,
// then INDEPENDENTLY proves the EFFECT on the running engine via a before/after `/evaluate` decision-FLIP on the
// discriminator `rule_id` (NOT a 200). This is the exact Part-C bug class — a mutation that returns 200 but writes
// the wrong dict / skips persist / skips cache-invalidation would NOT flip the decision, and this spec FAILS.
//
// Everything runs on THROWAWAY namespaces/classes and cleans up — it NEVER touches customer-support (the attack
// suite class), which a default-deny/override would break. A permissive base (with a dummy block rule so it passes
// the "must contain a block rule" validation) is seeded so overlay/pack effects are visible against `allow`.

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
async function ev(page: Page, ns: string, cls: string, tool: string, params: Record<string, unknown>) {
  const r = await api(page, "/api/v1/evaluate", "POST", {
    tool_name: tool, tool_params: params,
    agent_identity: { spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`, namespace: ns, agent_class: cls },
    session_id: "fable-surfaces", trust_score: 0.8, chain_depth: 0
  });
  return { decision: r.body?.decision, rule_id: r.body?.rule_id };
}
// permissive base: allows everything EXCEPT a dummy tool (the dummy block rule satisfies create-validation).
const BASE = [
  "package norviq.base", 'default decision="allow"', 'default rule_id="fb_base_allow"', 'default reason="a"',
  'decision="block" { input.tool_name=="__never__" }', 'rule_id="fb_never" { input.tool_name=="__never__" }',
  'reason="b" { input.tool_name=="__never__" }'
].join("\n");
const mkBase = (page: Page, ns: string, cls: string) =>
  api(page, "/api/v1/policies", "POST", { namespace: ns, agent_class: cls, rego_source: BASE, enforcement_mode: "block" });
const rmPolicy = (page: Page, ns: string, cls: string) => api(page, `/api/v1/policies/${ns}/${cls}`, "DELETE");

test.describe("Apply-per-surface enforcement — each surface flips /evaluate on the cluster (not a 200)", () => {
  test.beforeEach(async ({ page }) => { await page.goto("/"); await waitForApp(page); });

  test("SAVE (create) + APPLY-to-target both load into the live engine (rule_id flip, not no_policy_loaded)", async ({ page }) => {
    const SRC = "fbe-src", DST = "fbe-dst", C = "fbe-a";
    const REGO = ["package norviq.p", 'default decision="allow"', 'default rule_id="p_allow"', 'default reason="a"',
      'decision="block" { input.tool_name=="delete_database" }', 'rule_id="fbe_block_delete" { input.tool_name=="delete_database" }',
      'reason="b" { input.tool_name=="delete_database" }'].join("\n");
    try {
      expect((await ev(page, DST, C, "delete_database", { p: 1 })).rule_id).not.toBe("fbe_block_delete");
      expect((await api(page, "/api/v1/policies", "POST", { namespace: SRC, agent_class: C, rego_source: REGO, enforcement_mode: "block" })).status).toBe(200);
      // SAVE enforces at the source.
      expect((await ev(page, SRC, C, "delete_database", { p: 2 })).rule_id).toBe("fbe_block_delete");
      // APPLY to a different target enforces there too (the Part-C surface).
      expect((await api(page, `/api/v1/policies/${SRC}/${C}/apply`, "POST", { target_type: "agent_class", target_namespace: DST, target_name: C, enforcement_mode: "block" })).status).toBe(200);
      const after = await ev(page, DST, C, "delete_database", { p: 3 });
      expect(after.decision).toBe("block");
      expect(after.rule_id).toBe("fbe_block_delete");
    } finally { await rmPolicy(page, SRC, C); await rmPolicy(page, DST, C); }
  });

  test("PACK enable/disable flips the decision (allow -> escalate -> allow) with correct un-load", async ({ page }) => {
    const NS = "fbe-pack", C = "fbe-a";
    try {
      await mkBase(page, NS, C);
      expect((await ev(page, NS, C, "wire_transfer", { amount: "20000" })).decision).toBe("allow");
      expect((await api(page, "/api/v1/policy-packs/finance-money-movement/enable", "POST", { namespace: NS })).status).toBe(200);
      const on = await ev(page, NS, C, "wire_transfer", { amount: "20000" });
      expect(on.decision).toBe("escalate");
      expect(on.rule_id).toBe("wire_over_threshold_escalate");
      expect((await api(page, "/api/v1/policy-packs/finance-money-movement/disable", "POST", { namespace: NS })).status).toBe(200);
      // cache-miss params → proves the pack was truly UN-loaded (not a stale eval cache).
      expect((await ev(page, NS, C, "wire_transfer", { amount: "20001" })).decision).toBe("allow");
    } finally { await rmPolicy(page, NS, C); }
  });

  test("OVERRIDE (tighten-only) enforces, and REVERT (?namespace=) truly un-loads it", async ({ page }) => {
    const NS = "fbe-ovr", C = "fbe-a";
    const OVR = ["package norviq.packoverride", 'decision = "block" { input.tool_name == "export_all" }',
      'rule_id = "pack_override_block" { decision == "block" }', 'reason = "r" { decision == "block" }'].join("\n");
    try {
      await mkBase(page, NS, C);
      expect((await ev(page, NS, C, "export_all", { p: 1 })).decision).toBe("allow");
      expect((await api(page, "/api/v1/policy-packs/override", "PUT", { namespace: NS, rego_source: OVR })).status).toBe(200);
      const on = await ev(page, NS, C, "export_all", { p: 2 });
      expect(on.decision).toBe("block");
      expect(on.rule_id).toBe("pack_override_block");
      // REVERT via the query param — the EXACT contract revertPackOverride() uses (body-param would silently no-op).
      expect((await api(page, `/api/v1/policy-packs/override?namespace=${NS}`, "DELETE")).status).toBe(200);
      expect((await ev(page, NS, C, "export_all", { p: 3 })).decision).toBe("allow");   // truly un-loaded
    } finally { await rmPolicy(page, NS, C); }
  });

  test("ROLLBACK re-loads the target version into the live engine (v1 block -> v2 allow -> rollback block)", async ({ page }) => {
    const NS = "fbe-rb", C = "fbe-a";
    const V1 = ["package norviq.rb", 'default decision="allow"', 'default rule_id="rb_allow"', 'default reason="a"',
      'decision="block" { input.tool_name=="delete_database" }', 'rule_id="rb_block_delete" { input.tool_name=="delete_database" }',
      'reason="b" { input.tool_name=="delete_database" }'].join("\n");
    const V2 = ["package norviq.rb", 'default decision="allow"', 'default rule_id="rb_allow2"', 'default reason="a"',
      'decision="block" { input.tool_name=="__never__" }', 'rule_id="rb_never" { input.tool_name=="__never__" }',
      'reason="b" { input.tool_name=="__never__" }'].join("\n");
    try {
      expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: C, rego_source: V1, enforcement_mode: "block" })).status).toBe(200);
      expect((await ev(page, NS, C, "delete_database", { p: 1 })).rule_id).toBe("rb_block_delete");
      expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: C, rego_source: V2, enforcement_mode: "block" })).status).toBe(200);
      expect((await ev(page, NS, C, "delete_database", { p: 2 })).decision).toBe("allow");   // v2
      expect((await api(page, `/api/v1/policies/${NS}/${C}/rollback`, "POST", { target_version: 1 })).status).toBe(200);
      const back = await ev(page, NS, C, "delete_database", { p: 3 });                          // cache-miss
      expect(back.decision).toBe("block");
      expect(back.rule_id).toBe("rb_block_delete");
    } finally { await rmPolicy(page, NS, C); }
  });

  test("BASELINE + no-policy: an unknown ns/class fails CLOSED (block), never fail-open allow", async ({ page }) => {
    const d = await ev(page, "fbe-nopol", "fbe-none", "anything_at_all", { p: 1 });
    expect(d.decision).toBe("block");   // F-04 fail-closed; NEVER allow when nothing is loaded
  });
});
