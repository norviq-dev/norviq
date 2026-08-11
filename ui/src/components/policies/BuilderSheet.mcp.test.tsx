// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * MCP facts must be authorable as RULES, not only as grant facts.
 *
 * `FACT_FIELDS` already offered `mcp.server` / `mcp.pin_status` / `mcp.scan_severity` inside an
 * allowlist grant, so an operator could NARROW a grant with them. What was impossible was the negative
 * form — "block when the pin drifted" — because `scalarFact` was left out of `CONDITION_TYPES` for want
 * of an editor. That is exactly the shape of the shipped `mcp_integration_guardrail.rego`, so the one
 * MCP policy operators most want to reproduce in the builder was the one they could not.
 *
 * The closed vocabularies are asserted against the ENGINE's values, because a picker that offers a
 * value the evaluator never emits produces a rule that validates, compiles, and matches nothing.
 */

import { describe, expect, it } from "vitest";
import {
  CONDITION_TYPES,
  CONDITION_TYPE_LABEL,
  SCALAR_ENUM_VALUES,
  assertGroupsCoverConditionTypes,
  defaultConditionFor
} from "./BuilderSheet";
import { compileGraph } from "../../lib/builderCompile";
import type { BuilderGraph } from "../../lib/builderGraph";

function rulesGraph(condition: unknown): BuilderGraph {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "support" },
    mode: "rules",
    rules: [
      {
        id: "r1",
        ruleId: "block_mcp_drift",
        decision: "block",
        reason: "tool definition drifted since approval",
        conditions: [[condition]]
      }
    ],
    defaults: { decision: "allow", reason: "default" }
  } as unknown as BuilderGraph;
}

function compiled(condition: unknown): string {
  const res = compileGraph(rulesGraph(condition), "payments");
  expect(res.errors).toEqual([]);
  return res.rego;
}

describe("MCP facts are authorable as rules", () => {
  it("scalarFact is offered in the condition palette", () => {
    expect([...CONDITION_TYPES]).toContain("scalarFact");
    expect(CONDITION_TYPE_LABEL.scalarFact).toMatch(/MCP/i);
  });

  it("and is actually REACHABLE from the dropdown, not just present in the constant", () => {
    // This assertion exists because the first version of this test did not have it, and was therefore
    // vacuous: the dropdown renders from CONDITION_TYPE_GROUPS, whose element type
    // `(typeof CONDITION_TYPES)[number]` checks membership but NOT coverage. scalarFact was added to
    // CONDITION_TYPES, the test passed, tsc passed, the build passed — and the option was still absent
    // from the only control an operator can reach. Verified live in the browser, which is how it was
    // caught. `assertGroupsCoverConditionTypes` throws if the two lists ever diverge again.
    expect(() => assertGroupsCoverConditionTypes()).not.toThrow();
  });

  it("compiles the guardrail shape — block when the pin drifted", () => {
    const rego = compiled({ type: "scalarFact", field: "mcp.pin_status", op: "equals", value: "drift" });
    // The nested object.get form matters: a bare input.mcp.pin_status makes the WHOLE rule body
    // undefined when no MCP context is present, rather than making one predicate false.
    expect(rego).toContain('object.get(object.get(input, "mcp", {}), "pin_status", "")');
    expect(rego).toContain("drift");
  });

  it("compiles the set form — block on any severity we refuse to serve", () => {
    const rego = compiled({ type: "scalarFact", field: "mcp.scan_severity", op: "in", values: ["high", "critical"] });
    expect(rego).toContain('"scan_severity"');
  });
});

describe("closed vocabularies match what the engine actually emits", () => {
  it("pin_status covers every PIN_* constant", () => {
    // norviq/mcp/pins.py — PIN_OK / PIN_FIRST_SEEN / PIN_DRIFT / PIN_QUARANTINED, plus the "unknown"
    // the Gate-B context reports for a tool with no catalog entry.
    expect(SCALAR_ENUM_VALUES["mcp.pin_status"]).toEqual(
      expect.arrayContaining(["pinned", "first_seen", "drift", "quarantined", "unknown"])
    );
  });

  it("scan_severity covers the ladder AND unknown", () => {
    expect(SCALAR_ENUM_VALUES["mcp.scan_severity"]).toEqual(
      expect.arrayContaining(["none", "low", "medium", "high", "critical", "unknown"])
    );
    // "unknown" must be present and must NOT be treated as the bottom of the ladder — a tool Gate A
    // never scanned is not a tool that scanned clean.
    expect(SCALAR_ENUM_VALUES["mcp.scan_severity"]).toContain("unknown");
  });

  it("tool_kind offers only what _tool_kind returns", () => {
    // evaluator.py::_tool_kind returns "sql" or "other" — nothing else. Offering read/write/exec here
    // would invent a vocabulary the engine never emits, so every such rule would match nothing.
    expect([...SCALAR_ENUM_VALUES.tool_kind].sort()).toEqual(["other", "sql"]);
  });

  it("direction offers exactly the two planes the firewall sets", () => {
    expect([...SCALAR_ENUM_VALUES.direction].sort()).toEqual(["answer", "call"]);
  });

  it("scalarFact still defaults to param_paths, which is why the type exists", () => {
    const d = defaultConditionFor("scalarFact");
    expect(d).toMatchObject({ type: "scalarFact", field: "param_paths." });
  });
});
