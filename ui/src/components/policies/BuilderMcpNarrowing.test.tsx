// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The step-① MCP narrowing: a CONDITION, never a fourth tier.
//
// `loaderKeyFor` maps the scope to the loader key that selects WHICH REGO PROGRAM RUNS, and all three
// tiers are attested — agent_class is rewritten from the credential by `scoped_identity`, namespace
// comes from the SVID, workload from the webhook's owner-reference derivation. `mcp.server` is
// PEP-reported, and ToolCallEvent's own docstring draws the line: it says what is being called, never
// who is calling. Make it a tier and a forgeable string chooses the policy program — the same defect
// `keys.py` refuses for service keys.

import { describe, expect, it } from "vitest";
import { mcpNarrowedRules, scopeSentence } from "./BuilderSheet";
import type { BuilderCondition, BuilderRule } from "../../lib/builderGraph";

const CLAUSE = (v: string): BuilderCondition => ({ type: "scalarFact", field: "mcp.server", op: "equals", value: v });
const TOOL = (name: string): BuilderCondition => ({ type: "toolIn", tools: [name] });

const rule = (rows: BuilderCondition[][]): BuilderRule => ({
  id: "rule-1", decision: "block", ruleId: "r", reason: "because", conditions: rows
});

describe("the narrowing is ANDed into every row", () => {
  it("adds the server clause to a single-row rule", () => {
    const out = mcpNarrowedRules([rule([[TOOL("send_email")]])], "reporting-kb");
    expect(out[0].conditions).toEqual([[TOOL("send_email"), CLAUSE("reporting-kb")]]);
  });

  it("ANDs into EVERY row rather than adding a row of its own", () => {
    // The property that matters. A builder rule's rows are ORed, so a narrowing appended as its own
    // row would WIDEN the rule to "…or any call through this server" — the exact opposite of what the
    // affordance promises.
    const out = mcpNarrowedRules([rule([[TOOL("a")], [TOOL("b")]])], "kb");
    expect(out[0].conditions).toHaveLength(2);
    expect(out[0].conditions.every((row) => row.some((c) => c.type === "scalarFact"))).toBe(true);
  });

  it("gives a rule with no conditions one, rather than dropping the narrowing", () => {
    const out = mcpNarrowedRules([rule([])], "kb");
    expect(out[0].conditions).toEqual([[CLAUSE("kb")]]);
  });

  it("narrows every rule in the policy, not just the first", () => {
    const out = mcpNarrowedRules([rule([[TOOL("a")]]), rule([[TOOL("b")]])], "kb");
    expect(out.every((r) => r.conditions[0].some((c) => c.type === "scalarFact"))).toBe(true);
  });

  it("is a no-op with no narrowing, by REFERENCE", () => {
    // So a policy that does not use this compiles byte-identically to one authored before it existed.
    const rules = [rule([[TOOL("a")]])];
    expect(mcpNarrowedRules(rules, "")).toBe(rules);
    expect(mcpNarrowedRules(rules, "   ")).toBe(rules);
  });

  it("trims the server id", () => {
    expect(mcpNarrowedRules([rule([])], "  kb  ")[0].conditions).toEqual([[CLAUSE("kb")]]);
  });
});

describe("the scope sentence reads it as subordinate", () => {
  const base = {
    scopeReady: true, namespaceReady: true, agentClass: "support-agent",
    workloadName: "api", targetNamespace: "agents"
  };

  it("says nothing when there is no narrowing", () => {
    const s = scopeSentence({ ...base, tier: "class" });
    expect(s).toBe("Applies to every `support-agent` agent in namespace `agents`.");
  });

  it("adds a subordinate clause, not a second subject", () => {
    const s = scopeSentence({ ...base, tier: "class", mcpServer: "reporting-kb" });
    expect(s).toBe(
      "Applies to every `support-agent` agent in namespace `agents`, and only when served by MCP server `reporting-kb`."
    );
  });

  it("reads correctly on the namespace tier too", () => {
    const s = scopeSentence({ ...base, tier: "namespace", mcpServer: "kb" });
    expect(s).toContain("whatever its class, and only when served by MCP server `kb`");
  });

  it("reads correctly on the workload tier", () => {
    expect(scopeSentence({ ...base, tier: "workload", mcpServer: "kb" }))
      .toContain("and only when served by MCP server `kb`");
  });
});
