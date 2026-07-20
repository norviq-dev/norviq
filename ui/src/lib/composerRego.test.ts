// SPDX-License-Identifier: Apache-2.0
// The composer generates a VALID, enforcing keyword-block rego for a manually-entered agent class.
// These assert the generated source (a) satisfies the backend `validate_policy_create` guard and
// (b) is deterministic/normalized. The live OPA decision-flip is proven by the kind e2e (a 200 is not proof).
import { describe, it, expect } from "vitest";
import { composerRego, sanitizeClassToken, normalizeKeywords } from "./composerRego";

describe("composerRego — manual-class enforcing policy generation", () => {
  it("sanitizes class names into legal rego package tokens (never empty)", () => {
    expect(sanitizeClassToken("customer-support")).toBe("customer_support");
    expect(sanitizeClassToken("Q2 Manual.Demo!")).toBe("q2_manual_demo");
    expect(sanitizeClassToken("---")).toBe("class");
    expect(sanitizeClassToken("")).toBe("class");
  });

  it("normalizes keywords: lower-case, trim, de-dupe, sort", () => {
    expect(normalizeKeywords([" Token ", "secret", "TOKEN", "", "password"])).toEqual([
      "password",
      "secret",
      "token"
    ]);
  });

  it("emits a package, a reachable block decision, rule_id and reason (satisfies validate_policy_create)", () => {
    const rego = composerRego("customer-support", "block", ["secret", "token"]);
    expect(rego).toContain("package norviq.composer.customer_support");
    // the API guard requires a reachable `decision = "block"|"escalate" { … }` rule
    expect(rego).toMatch(/decision\s*=\s*"block"\s*\{/);
    expect(rego).toContain("rule_id");
    expect(rego).toContain("reason");
    // the block rule is guarded by `matched`, not the literal `false` (reachability heuristic)
    expect(rego).toMatch(/decision = "block" \{ matched \}/);
    // keyword set is normalized + quoted
    expect(rego).toContain('composer_keywords := {"secret", "token"}');
    // class-scoped: only THIS class's calls can match
    expect(rego).toContain('input.agent.agent_class == "customer-support"');
  });

  it("escalate mode emits an escalate decision instead of block", () => {
    const rego = composerRego("billing", "escalate", ["wire"]);
    expect(rego).toMatch(/decision\s*=\s*"escalate"\s*\{/);
  });

  it("audit mode falls back to a block decision (audit-only is rejected by the API guard)", () => {
    const rego = composerRego("ops", "audit", ["rm"]);
    expect(rego).toMatch(/decision\s*=\s*"block"\s*\{/);
  });

  it("is TIGHTEN-ONLY: non-matching calls fall through to a default allow (baseline unweakened)", () => {
    const rego = composerRego("svc", "block", ["danger"]);
    expect(rego).toContain('default decision = "allow"');
  });
});
