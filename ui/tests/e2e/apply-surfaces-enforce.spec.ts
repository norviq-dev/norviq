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
/**
 * Evaluate until the just-pushed policy is the one answering, then return the decision.
 *
 * A policy push is not synchronous with the ENGINE's view of it: `POST /policies` returns when the
 * policy is stored, and the loader picks it up on its own schedule. Every assertion in this file used
 * to fire in the next breath, and varied `tool_params` only defeats the DECISION cache — it does
 * nothing about load latency. On kind the window was short enough to hide; on a slower cluster the
 * evaluate lands inside it and reports the PREVIOUS version, so `v2 -> allow` fails with `block`
 * and reads as "rollback is broken" when nothing has rolled back yet.
 *
 * Params are made unique per attempt so no poll iteration can be served from the decision cache —
 * otherwise this would poll a cached answer and conclude nothing changed.
 *
 * The repo's own rule, applied: poll, never sleep-once, after a policy push.
 */
async function evUntil(
  page: Page, ns: string, cls: string, tool: string,
  want: { decision?: string; rule_id?: string }, timeout = 30_000
) {
  let last: { decision?: string; rule_id?: string } = {};
  let n = 0;
  await expect
    .poll(async () => {
      last = await ev(page, ns, cls, tool, { p: `poll-${Date.now()}-${n++}` });
      return want.rule_id ? last.rule_id : last.decision;
    }, { timeout, message: `policy never became live; last was ${JSON.stringify(last)}` })
    .toBe(want.rule_id ?? want.decision);
  return last;
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
    // `default decision = "allow"` is REQUIRED. `assert_decision_resolver` (policies.py) rejects a module
    // that defines a conditional `decision` without a default — the silent-allow guard: without it a
    // non-matching call yields an UNDEFINED decision rather than an explicit one. This fixture predates
    // that check and so 422'd on every run. The shipped OVERRIDE_TEMPLATE (PolicyPacks.tsx:36) carries
    // the same line, which is the proof the product accepts this shape.
    const OVR = ["package norviq.packoverride", 'default decision = "allow"',
      'decision = "block" { input.tool_name == "export_all" }',
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
      await evUntil(page, NS, C, "delete_database", { rule_id: "rb_block_delete" });   // v1 live
      expect((await api(page, "/api/v1/policies", "POST", { namespace: NS, agent_class: C, rego_source: V2, enforcement_mode: "block" })).status).toBe(200);
      await evUntil(page, NS, C, "delete_database", { decision: "allow" });            // v2 live
      expect((await api(page, `/api/v1/policies/${NS}/${C}/rollback`, "POST", { target_version: 1 })).status).toBe(200);
      // Rollback is the same push-then-load path, so it needs the same patience. Asserting the
      // rule_id (not just "block") is what proves the TARGET VERSION came back rather than some
      // other rule happening to block.
      const back = await evUntil(page, NS, C, "delete_database", { rule_id: "rb_block_delete" });
      expect(back.decision).toBe("block");
    } finally { await rmPolicy(page, NS, C); }
  });

  test("BASELINE + no-policy: an unknown ns/class allows, but NEVER anonymously", async ({ page }) => {
    // This asserted `block` and was correct when the engine shipped default-deny. It is not any
    // more: shipping block put 22 baseline rules in front of every tool call in every tenant
    // namespace on day one, and `deny_shell_execution` alone fires on roughly 1 in 8 ordinary
    // alphanumeric identifiers — so a stock install dropped real traffic before the customer had
    // written a policy. The default is now allow, decided deliberately (helm values
    // `baselineClusterPolicy.enforcementMode`, and `no_policy_decision` on the engine).
    //
    // What still matters is that the allow is ATTRIBUTABLE. An unjudged call must be countable and
    // alertable, so it carries the named `default_allow` rule rather than an empty rule_id — the
    // same reason `engine_unavailable_fallback` was given a name. An anonymous allow is the actual
    // regression to guard against here, because it is indistinguishable from a policy that ran and
    // permitted the call.
    const d = await ev(page, "fbe-nopol", "fbe-none", "anything_at_all", { p: 1 });
    expect(d.decision).toBe("allow");
    expect(d.rule_id).toBe("default_allow");   // named, never "" — an anonymous allow is the bug
  });

  test("the fail-CLOSED paths are still closed: a refused credential blocks, whatever the fallback", async ({ page }) => {
    // The complement of the test above, and the one that actually protects the posture. A 4xx from
    // the engine is not an outage, so it must block even with fail-open configured — otherwise an
    // expired sidecar credential becomes a total governance bypass. 0.2.1 shipped exactly that hole
    // via the SDK circuit breaker (three 401s tripped it, and the breaker is checked before the 4xx
    // rule), so this direction is worth asserting against the live engine too.
    const res = await page.request.post("/api/v1/evaluate", {
      headers: { Authorization: "Bearer not-a-real-token" },
      data: { tool_name: "anything_at_all", tool_params: { p: 1 }, framework: "langchain",
              agent_identity: { spiffe_id: "spiffe://cluster.local/ns/fbe-nopol/sa/x",
                                namespace: "fbe-nopol", agent_class: "fbe-none" } },
    });
    expect(res.status(), "a bogus credential must be refused, never served a decision").toBe(401);
  });
});
