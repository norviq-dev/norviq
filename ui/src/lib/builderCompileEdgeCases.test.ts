// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Edge cases at the graph -> rego boundary that the UI cannot produce but a REHYDRATED graph can.
 *
 * The compiled rego carries its own graph, base64-encoded in a header comment, and reopening a policy
 * JSON.parses that blob back into a `BuilderGraph`. That parse is the real trust boundary: the value is
 * `unknown` at runtime and only *cast* to the type. So the compiler has to hold for graphs the current UI
 * would never build — a hand-edited comment, or a policy authored by a different builder version whose
 * condition types this one does not know.
 */

import { describe, it, expect } from "vitest";
import { compileGraph } from "./builderCompile";

function graphWith(conditions: unknown[]): any {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "report-gen" },
    mode: "rules",
    defaults: { decision: "allow", reason: "default" },
    rules: [{ id: "r1", decision: "block", ruleId: "r_block", reason: "nope", conditions: [conditions] }],
  };
}

describe("unknown condition types cannot reach the emitted rego", () => {
  it("rejects a condition whose type this builder does not know", () => {
    // A future/older builder emitted `type: "toolCategory"`; this version has never heard of it.
    const result: any = compileGraph(graphWith([{ type: "toolCategory", category: "destructive" }]), "default");

    // Without a guard the emitter's `default:` branch returns the object itself, which interpolates into
    // the rule body as the literal text `[object Object]` — syntactically invalid rego that the server
    // then 422s, after the UI has already told the operator the policy is valid and offered Save.
    expect(result.rego ?? "").not.toContain("[object Object]");
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e: any) => e.code === "unknown_condition")).toBe(true);
  });

  it("rejects a condition with no type at all", () => {
    const result: any = compileGraph(graphWith([{ keywords: ["secret"] }]), "default");
    expect(result.rego ?? "").not.toContain("[object Object]");
    expect(result.errors.some((e: any) => e.code === "unknown_condition")).toBe(true);
  });

  it("rejects an unknown type nested inside a NOT", () => {
    // `not <garbage>` is the same failure wearing a negation.
    const result: any = compileGraph(
      graphWith([{ type: "not", inner: { type: "toolCategory", category: "x" } }]),
      "default",
    );
    expect(result.rego ?? "").not.toContain("[object Object]");
    expect(result.errors.some((e: any) => e.code === "unknown_condition")).toBe(true);
  });

  it("still compiles a fully-known graph unchanged", () => {
    const result: any = compileGraph(
      graphWith([{ type: "detector", detector: "sql_injection" }]),
      "default",
    );
    expect(result.errors).toEqual([]);
    expect(result.rego).toContain('blocks["r_block"]');
  });
});

describe("reserved scope: the remediation-overlay suffix (DOCUMENTED GAP, not a fix)", () => {
  /**
   * This block PINS CURRENT BEHAVIOUR and flags a decision, rather than changing anything.
   *
   * builderCompile.test.ts asserts deliberately that `<class>__remediation__` is NOT reserved, on the
   * grounds that `isReservedScope` only catches a DOUBLE LEADING underscore. That is an accurate
   * description of the predicate — but it is a statement about the mechanism, not about what the engine
   * does with the resulting key, and the engine does something surprising with it:
   *
   *   evaluator._collect_candidates, for a call whose class is `<C>`, additionally loads
   *   `(<ns>, "<C>__remediation__")` as a HARD tighten-only overlay — one that not even a
   *   `__pack_weaken__` overlay can relax.
   *
   * So a policy authored against the class `report-gen__remediation__` does not govern a class of that
   * name (no agent carries it). It silently becomes an un-weakenable overlay on `report-gen`, a class
   * the author never named — and it lands on the exact key the compliance dashboard's "Generate
   * enforcing policy" writes, so the two can overwrite each other.
   *
   * It fails CLOSED (an overlay can only tighten) and needs a deliberately odd class name, so this is a
   * footgun rather than a hole — which is why it is documented here instead of unilaterally reversed.
   * Reversing it is a one-line change: also consult `isRemediationOverlayClass`, which reservedScope.ts
   * already exports and the catalog already uses to render the "· compliance overlay" label.
   */
  it("currently ACCEPTS a class ending in __remediation__ (pins today's behaviour)", () => {
    const g: any = {
      schemaVersion: 1,
      scope: { kind: "class", agentClass: "report-gen__remediation__" },
      mode: "rules",
      defaults: { decision: "allow", reason: "default" },
      rules: [{ id: "r1", decision: "block", ruleId: "r_block", reason: "nope",
                conditions: [[{ type: "detector", detector: "sql_injection" }]] }],
    };
    const result: any = compileGraph(g, "default");
    expect(result.errors).toEqual([]);
    // If this ever starts failing because a reserved_scope error appeared, that is the gap above being
    // CLOSED on purpose — update this test to assert the rejection rather than reverting the guard.
  });

  it("allows a class that merely contains the word remediation", () => {
    const g: any = {
      schemaVersion: 1,
      scope: { kind: "class", agentClass: "remediation-bot" },
      mode: "rules",
      defaults: { decision: "allow", reason: "default" },
      rules: [{ id: "r1", decision: "block", ruleId: "r_block", reason: "nope",
                conditions: [[{ type: "detector", detector: "sql_injection" }]] }],
    };
    const result: any = compileGraph(g, "default");
    expect(result.errors).toEqual([]);
  });
});
