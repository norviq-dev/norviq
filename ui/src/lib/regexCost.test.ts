// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The cost hint must agree with the compiler, not with the label.
 *
 * The server caps a policy at 25 regex ops. `hostIn` READS like set membership and emits
 * `regex.match` on an anchored alternation; `destinations.hosts anyOf` READS like a pattern and
 * compiles to a free set comprehension. An operator budgeting by how a clause sounds gets it
 * backwards in both directions, so the hint is derived from the encoding.
 *
 * These tests compile a real graph per clause kind and compare `computeStats().regexOps` — measured
 * on the emitted rego — against the predicate. A change to any emitter fails here rather than quietly
 * making the hint wrong.
 */

import { describe, expect, it } from "vitest";
import {
  compileGraph,
  computeStats,
  constraintCostsRegexOp,
  factCostsRegexOp
} from "./builderCompile";
import type { BuilderGrantFact, BuilderGraph, BuilderParamConstraint } from "./builderGraph";

function graphWith(constraints: BuilderParamConstraint[], facts: BuilderGrantFact[]): BuilderGraph {
  // No cast. The two fixture bugs this file already hit — a missing `refinements` and a missing
  // `schemaVersion` — were both invisible behind `as BuilderGraph`, and the first one made every
  // measurement read zero so the comparison passed vacuously. A fixture that typechecks honestly is
  // the cheapest guard there is.
  return {
    schemaVersion: 1,
    mode: "allowlist",
    scope: { kind: "class", agentClass: "support-bot" },
    rules: [],
    defaults: { decision: "allow", reason: "No builder rule matched" },
    allowlist: {
      tools: ["send_email"],
      // `refinements` is REQUIRED — omitting it makes `compileGraph` return `invalid_allowlist` with
      // an empty rego, so every measurement reads zero and the whole comparison passes vacuously in
      // the wrong direction. The `as BuilderGraph` cast hid it; the assertion is what caught it.
      refinements: { readonly: false, egress: false, scope: false, rate: false },
      grants: [{ tool: "send_email", constraints, facts }]
    }
  };
}

/** Regex ops the COMPILER actually emitted for this clause, above an empty-grant baseline. */
function measuredOps(constraints: BuilderParamConstraint[], facts: BuilderGrantFact[]): number {
  const baseline = computeStats(compileGraph(graphWith([], [])).rego).regexOps;
  return computeStats(compileGraph(graphWith(constraints, facts)).rego).regexOps - baseline;
}

const CONSTRAINTS: BuilderParamConstraint[] = [
  { kind: "matches", field: "to", pattern: "^a$" },
  { kind: "notMatches", field: "to", pattern: "^b$" },
  { kind: "hostIn", field: "url", hosts: ["api.internal.example.com"] },
  { kind: "oneOf", field: "to", values: ["a", "b"] },
  { kind: "noneOf", field: "to", values: ["c"] },
  { kind: "maxNumber", field: "retries", max: 3 },
  { kind: "required", field: "to" },
  { kind: "forbidden", field: "debug" }
];

const FACTS: BuilderGrantFact[] = [
  { type: "scalarFact", field: "verb", op: "matches", value: "^read$" },
  { type: "scalarFact", field: "verb", op: "notMatches", value: "^write$" },
  { type: "scalarFact", field: "verb", op: "equals", value: "read" },
  { type: "scalarFact", field: "verb", op: "in", values: ["read", "send"] },
  { type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] },
  { type: "collectionFact", field: "destinations.hosts", op: "anyOf", values: ["api.example.com"] },
  { type: "numericFact", field: "param_bytes", op: "max", value: 65536 }
];

describe("constraintCostsRegexOp", () => {
  it.each(CONSTRAINTS)("agrees with the emitted rego for $kind", (c) => {
    expect(constraintCostsRegexOp(c)).toBe(measuredOps([c], []) > 0);
  });

  it("charges hostIn, which reads like set membership", () => {
    // The counter-intuitive direction, called out explicitly so it cannot regress silently.
    expect(constraintCostsRegexOp({ kind: "hostIn", field: "url", hosts: ["x.example.com"] })).toBe(true);
  });
});

describe("factCostsRegexOp", () => {
  it.each(FACTS)("agrees with the emitted rego for $field $op", (f) => {
    expect(factCostsRegexOp(f)).toBe(measuredOps([], [f]) > 0);
  });

  it("does NOT charge destinations.hosts anyOf, which reads like a pattern", () => {
    // The other counter-intuitive direction: a set comprehension, and free.
    expect(
      factCostsRegexOp({ type: "collectionFact", field: "destinations.hosts", op: "anyOf", values: ["a.example.com"] })
    ).toBe(false);
  });

  it("charges a negated regex, because the inner clause is what gets emitted", () => {
    expect(
      factCostsRegexOp({ type: "not", inner: { type: "scalarFact", field: "verb", op: "matches", value: "^x$" } })
    ).toBe(true);
    expect(
      factCostsRegexOp({
        type: "not",
        inner: { type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] }
      })
    ).toBe(false);
  });
});
