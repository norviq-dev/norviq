// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The seam between the two authoring surfaces. The property under test is not "does it convert" —
// it is "does it ever convert QUIETLY WRONG", because a dropped predicate makes the resulting policy
// MORE PERMISSIVE than the one the operator dry-ran and approved, while looking like the same policy.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import { intentToBuilderGraph } from "./intentToGraph";

function opaAvailable(): boolean {
  try {
    execFileSync("opa", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const itOpa = opaAvailable() ? it : it.skip;

function writeFixture(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- mkdtemp dir + literal basename
  writeFileSync(path, body, "utf8");
  return path;
}

function decide(rego: string, toolName: string, params: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-i2g-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  const pkg = /^package\s+(\S+)/m.exec(rego)![1];
  const input = {
    tool_name: toolName,
    tool_name_normalized: toolName.toLowerCase(),
    tool_params: params,
    agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
    call_depth: 0
  };
  const inputPath = writeFixture(dir, "input.json", JSON.stringify(input));
  const out = execFileSync(
    "opa",
    ["eval", "--v0-compatible", "-d", policyPath, "-i", inputPath, "-f", "json", `data.${pkg}.decision`],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  return JSON.parse(out)?.result?.[0]?.expressions?.[0]?.value ?? "<undefined>";
}

describe("intent -> builder graph", () => {
  it("carries tool names and a top-level argument constraint across", () => {
    const { graph, dropped } = intentToBuilderGraph({
      name: "select-only",
      class: "report-gen",
      call: [{ id: "select-only", match: { tool_name: "execute_sql" }, require: { "param_paths.query": { matches: "(?i)^\\s*select\\b" } } }]
    });
    expect(dropped).toEqual([]);
    expect(graph.mode).toBe("allowlist");
    expect(graph.allowlist?.tools).toEqual(["execute_sql"]);
    expect(graph.allowlist?.grants).toEqual([
      { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" }] }
    ]);
  });

  itOpa("the converted graph enforces what the intent said", () => {
    const { graph } = intentToBuilderGraph({
      class: "report-gen",
      call: [{ id: "select-only", match: { tool_name: "execute_sql" }, require: { "param_paths.query": { matches: "(?i)^\\s*select\\b" } } }]
    });
    const res = compileGraph(graph, "analytics");
    expect(res.errors).toEqual([]);
    expect(decide(res.rego, "execute_sql", { query: "SELECT id FROM orders" })).toBe("allow");
    expect(decide(res.rego, "execute_sql", { query: "DROP TABLE orders" })).toBe("block");
    expect(decide(res.rego, "delete_kb", { id: "1" })).toBe("block");
  });

  it("REPORTS a nested path instead of retargeting it at a different argument", () => {
    // Taking the last segment would produce a grant on `ids`, which is a different parameter. That is
    // the silent-wrong case this whole function is shaped to avoid.
    const { dropped, graph } = intentToBuilderGraph({
      class: "c",
      call: [{ id: "r", match: { tool_name: "read_rows" }, require: { "param_paths.filters.ids[0]": "C-91" } }]
    });
    expect(dropped.join(" ")).toContain("nested path");
    expect(graph.allowlist?.grants ?? []).toEqual([]);
  });

  it("carries engine-derived facts into the grant — the gap this used to record", () => {
    // This test previously asserted the OPPOSITE: that data_classes was reported as unrepresentable.
    // Grants now carry scoping facts, so the restriction crosses instead of being refused, and
    // tests/fixtures/cross_compiler/credential-egress.json has a builder half for the first time.
    const { graph, dropped } = intentToBuilderGraph({
      class: "c",
      call: [
        {
          id: "r",
          match: { tool_name: "send_email" },
          require: { data_classes: { noneOf: ["secret"] }, "destinations.emails": { subsetOf: ["ops@acme.com"] } }
        }
      ]
    });
    expect(dropped).toEqual([]);
    expect(graph.allowlist?.grants?.[0].facts).toEqual([
      { type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] },
      { type: "collectionFact", field: "destinations.emails", op: "subsetOf", values: ["ops@acme.com"] }
    ]);
  });

  it("REPORTS a rule that does not scope by tool name", () => {
    const { dropped } = intentToBuilderGraph({ class: "c", call: [{ id: "by-verb", match: { verb: "read" } }] });
    expect(dropped.join(" ")).toContain("does not scope by tool name");
  });

  it("REPORTS the answer and content planes, which the builder has no notion of", () => {
    const { dropped } = intentToBuilderGraph({
      class: "c",
      call: [{ id: "r", match: { tool_name: "x" } }],
      answer: [{ id: "a", match: { tool_name: "x" } }]
    });
    expect(dropped.join(" ")).toContain("answer plane");
  });

  it("never returns a graph that is MORE permissive than the intent without saying so", () => {
    // The invariant the caller relies on to decide whether the handoff is safe: any predicate that
    // narrows the intent and has no representation must appear in `dropped`. If this ever passes
    // silently, an operator edits a policy that admits more than the one they approved.
    const intent = {
      class: "c",
      call: [
        {
          id: "r",
          match: { tool_name: "send_email" },
          require: {
            "param_paths.to": { matches: "@acme\\.com$" }, // -> a per-field constraint
            data_classes: { noneOf: ["secret"] }, // -> a grant fact
            "destinations.hosts": { subsetOf: ["acme.com"] }, // -> a grant fact
            "param_paths.filters.ids[0]": "C-91" // -> nothing: a nested path has no grant form
          }
        }
      ]
    };
    const { graph, dropped } = intentToBuilderGraph(intent);
    const narrowing = Object.keys(intent.call[0].require);
    const g = (graph.allowlist?.grants ?? [])[0];
    const represented = (g?.constraints.length ?? 0) + (g?.facts?.length ?? 0);
    // EVERY narrowing predicate is either represented or named — none may simply vanish.
    expect(represented + dropped.length).toBe(narrowing.length);
    expect(dropped.join(" ")).toContain("nested path");
  });
});

describe("the conversion must preserve SENSE, not just count", () => {
  it("a negative constraint stays negative across the handoff", () => {
    // The exhaustiveness assertion above is arithmetic — represented + dropped === stated — so it is
    // blind to a predicate that IS represented but represented WRONGLY. Flipping constraintFor's
    // notMatches arm to emit `matches` inverts every negative argument constraint that crosses the
    // handoff, leaves `dropped` empty, and passes the count check: the operator's "the body must NOT
    // contain a password" silently becomes "the body MUST contain a password".
    const { graph, dropped } = intentToBuilderGraph({
      class: "c",
      call: [{
        id: "r",
        match: { tool_name: "send_email" },
        require: { "param_paths.body": { notMatches: "(?i)password" }, "param_paths.to": { matches: "@acme\\.com$" } }
      }]
    });
    expect(dropped).toEqual([]);
    const cs = graph.allowlist?.grants?.[0].constraints ?? [];
    const neg = cs.find((c) => c.field === "body");
    const pos = cs.find((c) => c.field === "to");
    expect(neg?.kind, "a notMatches must not become a matches").toBe("notMatches");
    expect(pos?.kind, "a matches must not become a notMatches").toBe("matches");
  });

  it("a collection operator keeps its own sense", () => {
    // Same hazard on the fact side: noneOf and anyOf are opposites, and the count check cannot tell
    // them apart.
    const { graph } = intentToBuilderGraph({
      class: "c",
      call: [{
        id: "r",
        match: { tool_name: "send_email" },
        require: { data_classes: { noneOf: ["secret"] }, "destinations.hosts": { anyOf: ["acme.com"] } }
      }]
    });
    const facts = graph.allowlist?.grants?.[0].facts ?? [];
    expect(facts.find((f) => f.type === "collectionFact" && f.field === "data_classes")).toMatchObject({ op: "noneOf" });
    expect(facts.find((f) => f.type === "collectionFact" && f.field === "destinations.hosts")).toMatchObject({ op: "anyOf" });
  });
});
