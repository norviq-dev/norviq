// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { isOverlayScope, policyVerdict, rulesPresentWord, verdictFromSettings } from "./posture";

describe("verdictFromSettings", () => {
  it("reads Monitor only when the namespace sets audit itself", () => {
    expect(verdictFromSettings({ namespace: "a", enforcement_mode: "audit", enforcement_mode_source: "namespace" }, "a")).toBe("monitor");
    // Inherited from the cluster default: the engine still blocks on this namespace's policies.
    expect(
      verdictFromSettings({ namespace: "a", enforcement_mode: "audit", enforcement_mode_source: "cluster_default" }, "a")
    ).toBe("enforcing");
    expect(verdictFromSettings({ namespace: "a", enforcement_mode: "block", enforcement_mode_source: "namespace" }, "a")).toBe("enforcing");
  });

  it("is unknown for no read, another namespace's read, or the all-namespaces scope", () => {
    expect(verdictFromSettings(null, "a")).toBe("unknown");
    expect(verdictFromSettings({ namespace: "default", enforcement_mode: "block" }, "a")).toBe("unknown");
    expect(verdictFromSettings({ namespace: "all", enforcement_mode: "block" }, "all")).toBe("unknown");
    expect(verdictFromSettings({ namespace: "a", enforcement_mode: "block" }, "")).toBe("unknown");
  });
});

describe("policyVerdict: one policy, not only its namespace", () => {
  it("an audit-mode base policy never reads as enforcing, even where the namespace enforces", () => {
    // evaluator `_apply_policy_mode` softens its block/escalate to an audit row.
    expect(policyVerdict("enforcing", "audit", "payments-agent")).toBe("policy_audit");
    expect(policyVerdict("unknown", "audit", "payments-agent")).toBe("policy_audit");
    expect(policyVerdict("enforcing", "audit", "__baseline__")).toBe("policy_audit");
  });

  it("Monitor in the namespace wins over the policy's own mode", () => {
    expect(policyVerdict("monitor", "audit", "payments-agent")).toBe("monitor");
    expect(policyVerdict("monitor", "block", "payments-agent")).toBe("monitor");
  });

  it("a block-mode policy does what its namespace does", () => {
    expect(policyVerdict("enforcing", "block", "payments-agent")).toBe("enforcing");
    expect(policyVerdict("unknown", "block", "payments-agent")).toBe("unknown");
    expect(policyVerdict("enforcing", undefined, "payments-agent")).toBe("enforcing");
  });

  it("an overlay's stored mode is ignored by the engine, so it is not read as audit", () => {
    for (const ac of ["__pack__", "__guardrail__", "__mcp__", "report-gen__remediation__"]) {
      expect(isOverlayScope(ac)).toBe(true);
      expect(policyVerdict("enforcing", "audit", ac)).toBe("enforcing");
    }
    expect(isOverlayScope("__baseline__")).toBe(false);
    expect(isOverlayScope("__remediation__")).toBe(false);
  });
});

describe("rulesPresentWord: the Compliance 'enforced' status in each posture", () => {
  it("says enforced only where the namespace enforces", () => {
    expect(rulesPresentWord("enforcing")).toBe("enforced");
    expect(rulesPresentWord("monitor")).toBe("rules present · monitor");
    expect(rulesPresentWord("unknown")).toBe("rules present");
  });
});
