// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Scoping facts in the builder — the condition types that mirror the SERVER intent schema's
// SCALAR_FIELDS / COLLECTION_FIELDS / NUMERIC_FIELDS (norviq/engine/intent/schema.py).
//
// These assert DECISIONS through the real `opa` binary, not emitted text. A scoping rule that reads
// correctly and evaluates wrongly is the whole failure this feature exists to prevent: the operator
// believes the recipient is pinned to their own domain, and it is not.
//
// Skipped automatically when `opa` is absent so the suite stays green without it — but when it is
// present these are the tests that catch a policy that compiles and enforces the wrong thing.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import type { BuilderCondition, BuilderGraph } from "./builderGraph";

function opaAvailable(): boolean {
  try {
    execFileSync("opa", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const itOpa = opaAvailable() ? it : it.skip;
const REPO_ROOT = join(__dirname, "..", "..", "..");

/** Single writeFileSync call site — see builderIntentGrants.test.ts for why this is funnelled. */
function writeFixture(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- mkdtemp dir + literal basename
  writeFileSync(path, body, "utf8");
  return path;
}

/** A rules-mode graph with one block rule whose single AND-row is `conditions`. */
function rulesGraph(conditions: BuilderCondition[]): BuilderGraph {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "report-gen" },
    mode: "rules",
    rules: [{ ruleId: "r_scope", decision: "block", reason: "out of scope", conditions: [conditions] }],
    defaults: { decision: "allow", reason: "default" }
  };
}

function compileOk(graph: BuilderGraph): string {
  const res = compileGraph(graph, "analytics");
  expect(res.errors).toEqual([]);
  expect(res.rego).not.toBe("");
  return res.rego;
}

/** Evaluate the compiled module against one input document and return decision + rule_id. */
function decide(rego: string, input: Record<string, unknown>): { decision: string; rule_id: string } {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-facts-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  const pkg = /^package\s+(\S+)/m.exec(rego)?.[1];
  if (!pkg) throw new Error("compiled rego has no package line");
  const inputPath = writeFixture(dir, "input.json", JSON.stringify(input));
  const read = (field: string): string => {
    const out = execFileSync(
      "opa",
      ["eval", "--v0-compatible", "-d", policyPath, "-i", inputPath, "-f", "json", `data.${pkg}.${field}`],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    const parsed = JSON.parse(out);
    if (parsed?.errors?.length) throw new Error(`opa errors: ${JSON.stringify(parsed.errors)}`);
    return parsed?.result?.[0]?.expressions?.[0]?.value ?? "<undefined>";
  };
  return { decision: read("decision"), rule_id: read("rule_id") };
}

/** An input document shaped like the one the evaluator builds, with `derived` fully populated. */
function call(toolName: string, params: Record<string, unknown>, derived: Record<string, unknown> = {}) {
  return {
    tool_name: toolName,
    tool_name_normalized: toolName.toLowerCase(),
    tool_params: params,
    agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
    call_depth: 0,
    trust_score: 0.9,
    derived: {
      verb: "send",
      tool_kind: "other",
      param_values: [],
      param_values_lower: [],
      sql_normalized: "",
      sql_statements: [],
      // The facts this merge added — present on a current engine, absent on an older one.
      param_paths: {},
      destinations: { emails: [], urls: [], hosts: [], schemes: [] },
      data_classes: [],
      sql_tables: [],
      param_bytes: 0,
      ...derived
    }
  };
}

describe("scoping facts — the emitted policy decides what the operator wrote", () => {
  itOpa("passes the engine's own pre-push gate (opa check --v0-compatible --capabilities)", () => {
    const rego = compileOk(
      rulesGraph([
        { type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret"] },
        { type: "scalarFact", field: "param_paths.to", op: "notMatches", value: "(?i)^[^@]+@acme\\.com$" },
        { type: "numericFact", field: "param_bytes", op: "min", value: 1 }
      ])
    );
    const dir = mkdtempSync(join(tmpdir(), "nrvq-check-"));
    const policyPath = writeFixture(dir, "policy.rego", rego);
    const caps = join(REPO_ROOT, "norviq", "engine", "opa-capabilities.json");
    execFileSync("opa", ["check", "--v0-compatible", `--capabilities=${caps}`, policyPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  });

  itOpa("data_classes blocks a call carrying a credential and allows the same call without one", () => {
    const rego = compileOk(rulesGraph([{ type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret"] }]));
    // The live finding this encodes: send_email to an external address carrying a bare AWS key was
    // ALLOWED under the strict preset, while a card number in the same position blocked.
    expect(decide(rego, call("send_email", { body: "AKIAIOSFODNN7EXAMPLE" }, { data_classes: ["secret"] })).decision).toBe("block");
    expect(decide(rego, call("send_email", { body: "your refund is on its way" })).decision).toBe("allow");
  });

  itOpa("destinations.hosts scopes egress by the host the ENGINE extracted, not one named field", () => {
    const rego = compileOk(
      rulesGraph([{ type: "collectionFact", field: "destinations.hosts", op: "noneOf", values: ["api.internal.example.com"] }])
    );
    // A URL anywhere in the params reaches destinations.hosts, so moving it to a differently-named
    // field cannot dodge the rule the way a single-field `hostIn` is dodged.
    const external = call("http_post", { note: "see https://evil.example/x" }, { destinations: { emails: [], urls: ["https://evil.example/x"], hosts: ["evil.example"], schemes: ["https"] } });
    const internal = call("http_post", { url: "https://api.internal.example.com/v1" }, { destinations: { emails: [], urls: ["https://api.internal.example.com/v1"], hosts: ["api.internal.example.com"], schemes: ["https"] } });
    expect(decide(rego, external).decision).toBe("block");
    expect(decide(rego, internal).decision).toBe("allow");
  });

  itOpa("param_paths addresses ONE nested argument, which a flat field name cannot reach", () => {
    const rego = compileOk(rulesGraph([{ type: "scalarFact", field: "param_paths.filters.ids[0]", op: "equals", value: "C-91" }]));
    expect(decide(rego, call("read_rows", {}, { param_paths: { "filters.ids[0]": "C-91" } })).decision).toBe("block");
    expect(decide(rego, call("read_rows", {}, { param_paths: { "filters.ids[0]": "C-92" } })).decision).toBe("allow");
  });

  itOpa("a recipient rule is not satisfied by the same address sitting in the BODY", () => {
    // The precise reason param_paths exists: against a flat value list `to` and `body` are
    // indistinguishable, so "only mail acme.com" matched a call whose acme address was in the body of
    // a message going somewhere else entirely.
    const rego = compileOk(
      rulesGraph([{ type: "scalarFact", field: "param_paths.to", op: "notMatches", value: "^[^@]+@acme\\.com$" }])
    );
    const legit = call("send_email", {}, { param_paths: { to: "ops@acme.com", body: "hello" } });
    const smuggled = call("send_email", {}, { param_paths: { to: "collector@attacker.example", body: "ops@acme.com" } });
    expect(decide(rego, legit).decision).toBe("allow");
    expect(decide(rego, smuggled).decision).toBe("block");
  });

  itOpa("sql_tables subsetOf keeps a query inside the approved tables", () => {
    const rego = compileOk(rulesGraph([{ type: "collectionFact", field: "sql_tables", op: "anyOf", values: ["payments"] }]));
    expect(decide(rego, call("execute_sql", {}, { sql_tables: ["orders", "payments"] })).decision).toBe("block");
    expect(decide(rego, call("execute_sql", {}, { sql_tables: ["orders", "customers"] })).decision).toBe("allow");
  });

  itOpa("numeric bounds fire on the payload size", () => {
    const rego = compileOk(rulesGraph([{ type: "numericFact", field: "param_bytes", op: "min", value: 1024 }]));
    expect(decide(rego, call("send_email", {}, { param_bytes: 4096 })).decision).toBe("block");
    expect(decide(rego, call("send_email", {}, { param_bytes: 12 })).decision).toBe("allow");
  });

  itOpa("an MCP fact on a NON-MCP call fails its predicate instead of deleting the rule", () => {
    // A bare input.mcp.server would make the whole rule body undefined on a call that never went
    // through MCP — silently removing the rule rather than failing one clause. The guarded object.get
    // form (copied from schema.py) is what keeps that from happening.
    const rego = compileOk(rulesGraph([{ type: "scalarFact", field: "mcp.pin_status", op: "equals", value: "drift" }]));
    const nonMcp = call("send_email", {});
    expect(decide(rego, nonMcp).decision).toBe("allow"); // predicate false, rule intact
    const drifted = { ...call("send_email", {}), mcp: { server: "github", pin_status: "drift" } };
    expect(decide(rego, drifted).decision).toBe("block");
  });
});

describe("version skew — a scoping rule must not silently stop enforcing", () => {
  it("emits a capability guard only when the graph uses a fact this merge added", () => {
    const withNewFact = compileOk(rulesGraph([{ type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret"] }]));
    expect(withNewFact).toContain('blocks["bld_unsupported_engine"]');
    expect(withNewFact).toContain("not input.derived.data_classes");

    // A graph using only pre-merge facts must be byte-unchanged in this respect — no guard, no noise.
    const oldOnly = compileOk(rulesGraph([{ type: "toolIn", tools: ["execute_sql"] }]));
    expect(oldOnly).not.toContain("bld_unsupported_engine");
  });

  itOpa("the guard BLOCKS on an engine that does not publish the fact, and is inert on one that does", () => {
    const rego = compileOk(rulesGraph([{ type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret"] }]));

    // An OLD engine: `derived` exists but carries none of the new roots. Without the guard the block
    // condition is merely false and the policy silently enforces nothing — fail-OPEN.
    const oldEngine = {
      tool_name: "send_email",
      tool_params: { body: "AKIAIOSFODNN7EXAMPLE" },
      agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
      call_depth: 0,
      derived: { verb: "send", tool_kind: "other", param_values: [], param_values_lower: [], sql_normalized: "", sql_statements: [] }
    };
    const skewed = decide(rego, oldEngine);
    expect(skewed.decision).toBe("block");
    expect(skewed.rule_id).toBe("bld_unsupported_engine");

    // A CURRENT engine with nothing to report: the root is an empty array, which is DEFINED, so
    // `not input.derived.data_classes` is false and the guard stays out of the way.
    expect(decide(rego, call("send_email", { body: "hello" })).decision).toBe("allow");
  });
});

describe("budget and validation", () => {
  it("set operations are free against the 25-regex-op cap; only matches spends it", () => {
    const sets = compileGraph(
      rulesGraph([
        { type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret", "pci"] },
        { type: "collectionFact", field: "destinations.hosts", op: "noneOf", values: ["a.example", "b.example"] },
        { type: "scalarFact", field: "verb", op: "in", values: ["send", "write"] }
      ]),
      "analytics"
    );
    expect(sets.errors).toEqual([]);
    expect(sets.stats.regexOps).toBe(0);

    const withRegex = compileGraph(
      rulesGraph([{ type: "scalarFact", field: "param_paths.to", op: "matches", value: "^x$" }]),
      "analytics"
    );
    expect(withRegex.stats.regexOps).toBe(1);
  });

  it("rejects an empty value list, which would compile to a tautology", () => {
    // `noneOf []` is always true and `subsetOf []` means "the collection is empty" — either way the
    // rule reads as a restriction and enforces something the operator did not write.
    const res = compileGraph(rulesGraph([{ type: "collectionFact", field: "data_classes", op: "noneOf", values: [] }]), "analytics");
    expect(res.errors.map((e) => e.code)).toContain("empty_fact_values");
    expect(res.rego).toBe("");
  });

  it("rejects an unaddressable field rather than emitting a rule that never fires", () => {
    const res = compileGraph(rulesGraph([{ type: "scalarFact", field: "recipeint", op: "equals", value: "x" }]), "analytics");
    expect(res.errors.map((e) => e.code)).toContain("unknown_fact_field");
    expect(res.rego).toBe("");
  });

  it("rejects an unparseable pattern at author time", () => {
    const res = compileGraph(rulesGraph([{ type: "scalarFact", field: "param_paths.to", op: "matches", value: "([a-z" }]), "analytics");
    expect(res.errors.map((e) => e.code)).toContain("paramRegex_invalid");
  });

  it("an operator-supplied value cannot terminate the rego string and inject a rule", () => {
    const hostile = 'x" ; blocks["pwned"] { true } ; y := "';
    const res = compileGraph(rulesGraph([{ type: "scalarFact", field: "param_paths.to", op: "equals", value: hostile }]), "analytics");
    expect(res.errors).toEqual([]);
    expect(res.rego).not.toContain('blocks["pwned"]');
    expect(res.rego).toContain(JSON.stringify(hostile));
  });
});
