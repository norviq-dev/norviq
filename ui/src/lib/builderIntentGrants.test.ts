// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Phase 2d — per-tool parameter constraints on an intent allowlist.
//
// These tests do NOT assert on emitted rego TEXT. Text assertions prove the compiler produced the string
// someone expected; they cannot prove the resulting POLICY decides correctly, and this feature's entire
// value is the decisions. So each case compiles a graph and evaluates it with the REAL `opa` binary
// (the same 1.18 line the sidecar runs), asserting the allow/block verdict for concrete tool arguments.
//
// Skipped automatically when `opa` is not on PATH, so the suite stays green on a machine without it —
// but when it IS present these are the tests that would catch a policy that compiles and enforces the
// wrong thing.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import type { BuilderGraph, BuilderParamConstraint } from "./builderGraph";

function opaAvailable(): boolean {
  try {
    execFileSync("opa", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const HAS_OPA = opaAvailable();
const itOpa = HAS_OPA ? it : it.skip;

/** repo root, from ui/src/lib/ — used to reach the engine's own OPA capabilities file. */
const REPO_ROOT = join(__dirname, "..", "..", "..");

function intentGraph(tools: string[], grants?: Array<{ tool: string; constraints: BuilderParamConstraint[] }>): BuilderGraph {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "report-gen" },
    mode: "allowlist",
    rules: [],
    defaults: { decision: "block", reason: "default" },
    allowlist: {
      tools,
      refinements: { readonly: false, egress: false, scope: false, rate: false },
      ...(grants ? { grants } : {})
    }
  };
}

/** Run one `opa eval` and surface OPA's own stderr on failure — a swallowed rego_parse_error/rego_type_error
 *  turns every assertion here into an unexplained "Command failed", which is useless when the whole point
 *  is checking the emitted policy. */
function evalQuery(policyPath: string, inputPath: string, query: string): string {
  let out: string;
  try {
    // `--v0-compatible` is REQUIRED, not incidental: the sidecar is started
    // `opa run --server --v0-compatible` (helm/norviq/templates/api-deployment.yaml) and the engine
    // pre-checks with `opa check --v0-compatible` (norviq/engine/opa_client.py). Evaluating here under
    // OPA's v1 default would test a dialect this policy never runs in — every emitted body would fail
    // with "`if` keyword is required" and the fix would be to break the emitter.
    out = execFileSync("opa", ["eval", "--v0-compatible", "-d", policyPath, "-i", inputPath, "-f", "json", query], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string };
    throw new Error(`opa eval failed for ${query}\nstdout: ${err.stdout ?? ""}\nstderr: ${err.stderr ?? ""}`);
  }
  const parsed = JSON.parse(out);
  if (parsed?.errors?.length) throw new Error(`opa returned errors: ${JSON.stringify(parsed.errors, null, 2)}`);
  return parsed?.result?.[0]?.expressions?.[0]?.value ?? "<undefined>";
}

/** Evaluate the compiled policy for one tool call and return its decision. The compiled module declares
 *  `package norviq.intent.<token>`; the engine rewrites that at push time, but for evaluation we query
 *  the package the module actually declares. */
/** Write one fixture file into a freshly-minted temp dir and return its path.
 *
 *  THE SINGLE `writeFileSync` CALL SITE IN THIS FILE, deliberately. `security/detect-non-literal-fs-filename`
 *  is a fail-closed rule in ui/eslint.config.js, and it fires on every dynamic path — correctly, in general.
 *  Here the path is not attacker-influenced in any sense: `dir` comes from `mkdtempSync` (kernel-chosen,
 *  0700, unique per call) and `name` is a hard-coded literal at every call site. Funnelling all of them
 *  through one helper means the gate is suppressed ONCE, next to the reasoning, instead of five times
 *  where the reasoning would have to be repeated or (more likely) omitted.
 */
function writeFixture(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- mkdtemp dir + literal basename
  writeFileSync(path, body, "utf8");
  return path;
}

/** Compile-to-disk + evaluate one query against the emitted policy. `decide` and `ruleId` were
 *  byte-identical apart from the queried field, which is how they drifted into using two different
 *  package-line extractions (`?.[1]` with a throw vs a bare `!`). One implementation, one behaviour. */
function queryPolicy(rego: string, toolName: string, params: Record<string, unknown>, field: string): string {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-grants-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  const pkg = /^package\s+(\S+)/m.exec(rego)?.[1];
  if (!pkg) throw new Error("compiled rego has no package line");
  const input = {
    tool_name: toolName,
    tool_name_normalized: toolName.toLowerCase(),
    tool_params: params,
    agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
    call_depth: 0
  };
  const inputPath = writeFixture(dir, "input.json", JSON.stringify(input));
  return evalQuery(policyPath, inputPath, `data.${pkg}.${field}`);
}

function decide(rego: string, toolName: string, params: Record<string, unknown>): string {
  return queryPolicy(rego, toolName, params, "decision");
}

function ruleId(rego: string, toolName: string, params: Record<string, unknown>): string {
  return queryPolicy(rego, toolName, params, "rule_id");
}

describe("intent allowlist — per-tool parameter constraints", () => {
  it("compiles without errors and stays inside the server's rego budget", () => {
    const res = compileGraph(
      intentGraph(["execute_sql", "http_get"], [
        {
          tool: "execute_sql",
          constraints: [
            { kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" },
            { kind: "notMatches", field: "query", pattern: "(?i)(card_number|ssn|password)" },
            { kind: "maxNumber", field: "limit", max: 100 }
          ]
        },
        { tool: "http_get", constraints: [{ kind: "hostIn", field: "url", hosts: ["api.internal.example.com"] }] }
      ]),
      "analytics"
    );
    expect(res.errors).toEqual([]);
    expect(res.rego).not.toBe("");
    expect(res.stats.regexOps).toBeLessThanOrEqual(25); // the cap only the live API enforces
  });

  itOpa("passes the engine's OWN pre-push gate (opa check --v0-compatible --capabilities)", () => {
    // norviq/engine/opa_client.py validates every module with `opa check --v0-compatible
    // --capabilities=opa-capabilities.json` before pushing. A builtin outside that capability set compiles
    // fine locally and is REJECTED at push time — which surfaces as a 422 with the OLD rego still
    // enforcing (see memory: rego-preset-ship-constraints). Running the same gate here catches that now.
    const { rego } = compileGraph(
      intentGraph(["execute_sql", "http_get", "read_table", "delete_row"], [
        {
          tool: "execute_sql",
          constraints: [
            { kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" },
            { kind: "notMatches", field: "query", pattern: "(?i)card_number" },
            { kind: "maxNumber", field: "limit", max: 100 }
          ]
        },
        { tool: "http_get", constraints: [{ kind: "hostIn", field: "url", hosts: ["api.internal.example.com"] }] },
        { tool: "read_table", constraints: [{ kind: "oneOf", field: "table", values: ["users", "orders"] }] },
        { tool: "delete_row", constraints: [{ kind: "forbidden", field: "force" }] }
      ]),
      "analytics"
    );
    const dir = mkdtempSync(join(tmpdir(), "nrvq-check-"));
    const policyPath = writeFixture(dir, "policy.rego", rego);
    const caps = join(REPO_ROOT, "norviq", "engine", "opa-capabilities.json");
    // Throws (failing the test) if opa check rejects the module.
    execFileSync("opa", ["check", "--v0-compatible", `--capabilities=${caps}`, policyPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  });

  itOpa("scopes a tool by its ARGUMENTS, not just its name", () => {
    const { rego, errors } = compileGraph(
      intentGraph(["execute_sql"], [
        {
          tool: "execute_sql",
          constraints: [
            { kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" },
            { kind: "notMatches", field: "query", pattern: "(?i)(card_number|ssn)" }
          ]
        }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);

    // The whole point: same allowlisted tool, different arguments, different verdicts.
    expect(decide(rego, "execute_sql", { query: "SELECT id FROM users" })).toBe("allow");
    expect(decide(rego, "execute_sql", { query: "DROP TABLE users" })).toBe("block");
    expect(decide(rego, "execute_sql", { query: "SELECT card_number FROM payments" })).toBe("block");
    // A bare tool-name allowlist would have allowed all three.
  });

  itOpa("an ABSENT parameter denies rather than skipping the constraint", () => {
    const { rego } = compileGraph(
      intentGraph(["execute_sql"], [
        { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" }] }
      ]),
      "analytics"
    );
    // Omitting the constrained param must not be a way to bypass the constraint.
    expect(decide(rego, "execute_sql", {})).toBe("block");
  });

  itOpa("a NEGATED constraint is not satisfied by simply omitting the parameter", () => {
    const { rego } = compileGraph(
      intentGraph(["execute_sql"], [
        {
          tool: "execute_sql",
          constraints: [
            { kind: "required", field: "query" },
            { kind: "notMatches", field: "query", pattern: "(?i)drop" }
          ]
        }
      ]),
      "analytics"
    );
    expect(decide(rego, "execute_sql", { query: "SELECT 1" })).toBe("allow");
    expect(decide(rego, "execute_sql", { query: "DROP TABLE t" })).toBe("block");
    expect(decide(rego, "execute_sql", {})).toBe("block"); // `required` closes the omission path
  });

  itOpa("oneOf / noneOf scope a tool to specific resources", () => {
    const { rego } = compileGraph(
      intentGraph(["read_table"], [
        {
          tool: "read_table",
          constraints: [
            { kind: "oneOf", field: "table", values: ["users", "orders"] },
            { kind: "noneOf", field: "table", values: ["payments"] }
          ]
        }
      ]),
      "analytics"
    );
    expect(decide(rego, "read_table", { table: "users" })).toBe("allow");
    expect(decide(rego, "read_table", { table: "ORDERS" })).toBe("allow"); // case-insensitive
    expect(decide(rego, "read_table", { table: "payments" })).toBe("block");
    expect(decide(rego, "read_table", { table: "secrets" })).toBe("block");
  });

  itOpa("maxNumber bounds a numeric argument and rejects a non-numeric one", () => {
    const { rego } = compileGraph(
      intentGraph(["read_table"], [
        { tool: "read_table", constraints: [{ kind: "maxNumber", field: "limit", max: 100 }] }
      ]),
      "analytics"
    );
    expect(decide(rego, "read_table", { limit: 50 })).toBe("allow");
    expect(decide(rego, "read_table", { limit: 100 })).toBe("allow");
    expect(decide(rego, "read_table", { limit: 1000 })).toBe("block");
    expect(decide(rego, "read_table", { limit: "lots" })).toBe("block"); // wrong type must not pass
  });

  itOpa("hostIn is a real egress control, not a substring match", () => {
    const { rego } = compileGraph(
      intentGraph(["http_get"], [
        { tool: "http_get", constraints: [{ kind: "hostIn", field: "url", hosts: ["api.internal.example.com"] }] }
      ]),
      "analytics"
    );
    expect(decide(rego, "http_get", { url: "https://api.internal.example.com/v1/status" })).toBe("allow");
    expect(decide(rego, "http_get", { url: "https://api.internal.example.com:8443/v1" })).toBe("allow");
    expect(decide(rego, "http_get", { url: "https://evil.example.net/" })).toBe("block");
    // The three ways a naive substring or unescaped-dot check gets this wrong:
    expect(decide(rego, "http_get", { url: "https://evil.com/api.internal.example.com" })).toBe("block");
    expect(decide(rego, "http_get", { url: "https://api.internal.example.com@evil.com/" })).toBe("block");
    expect(decide(rego, "http_get", { url: "https://apiXinternalYexampleZcom/" })).toBe("block");
  });

  itOpa("forbidden asserts ABSENCE", () => {
    const { rego } = compileGraph(
      intentGraph(["delete_row"], [
        { tool: "delete_row", constraints: [{ kind: "forbidden", field: "force" }] }
      ]),
      "analytics"
    );
    expect(decide(rego, "delete_row", { table: "t" })).toBe("allow");
    expect(decide(rego, "delete_row", { table: "t", force: true })).toBe("block");
  });

  itOpa("an unconstrained allowlisted tool is unaffected by another tool's constraints", () => {
    const { rego } = compileGraph(
      intentGraph(["execute_sql", "search_kb"], [
        { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "(?i)^select" }] }
      ]),
      "analytics"
    );
    // search_kb carries no grant — it must behave exactly as it did before this feature existed.
    expect(decide(rego, "search_kb", { query: "anything at all" })).toBe("allow");
    expect(decide(rego, "search_kb", {})).toBe("allow");
    // ...and a non-allowlisted tool is still denied outright.
    expect(decide(rego, "send_email", {})).toBe("block");
  });

  itOpa("attributes a constraint block distinctly from a refinement block", () => {
    const { rego } = compileGraph(
      intentGraph(["execute_sql"], [
        { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "(?i)^select" }] }
      ]),
      "analytics"
    );
    // Allowlisted + constraint failed → constraint violation, NOT the generic refinement mismatch.
    expect(ruleId(rego, "execute_sql", { query: "DROP TABLE t" })).toBe("intent_constraint_violation");
    // Not allowlisted at all → the default deny.
    expect(ruleId(rego, "send_email", {})).toBe("intent_default_deny");
    // Allowed path keeps its own id.
    expect(ruleId(rego, "execute_sql", { query: "SELECT 1" })).toBe("intent_allow_report_gen");
  });

  itOpa("constraints compose with the class-wide refinements (both must hold)", () => {
    const graph = intentGraph(["http_get"], [
      { tool: "http_get", constraints: [{ kind: "hostIn", field: "url", hosts: ["api.internal.example.com"] }] }
    ]);
    graph.allowlist!.refinements = { readonly: true, egress: false, scope: false, rate: false };
    const { rego, errors } = compileGraph(graph, "analytics");
    expect(errors).toEqual([]);
    // http_get passes read-only (verb "http"? no — "get" is not the leading token, so this must BLOCK).
    // Asserting the composition explicitly: a constraint being satisfied cannot rescue a failed refinement.
    expect(decide(rego, "http_get", { url: "https://api.internal.example.com/v1" })).toBe("block");
    expect(ruleId(rego, "http_get", { url: "https://api.internal.example.com/v1" })).toBe("intent_refinement_mismatch");
  });
});

describe("intent grants — validation", () => {
  it("rejects a grant for a tool that is not on the allowlist", () => {
    const res = compileGraph(
      intentGraph(["search_kb"], [
        { tool: "execute_sql", constraints: [{ kind: "required", field: "query" }] }
      ]),
      "analytics"
    );
    expect(res.errors.map((e) => e.code)).toContain("grant_not_allowlisted");
    expect(res.rego).toBe(""); // an invalid graph must never yield enforceable rego
  });

  it("rejects duplicate grants for one tool rather than silently dropping one", () => {
    const res = compileGraph(
      intentGraph(["execute_sql"], [
        { tool: "execute_sql", constraints: [{ kind: "required", field: "query" }] },
        { tool: "execute_sql", constraints: [{ kind: "forbidden", field: "force" }] }
      ]),
      "analytics"
    );
    expect(res.errors.map((e) => e.code)).toContain("duplicate_grant");
  });

  it("rejects an unparseable regex at author time, not at push time", () => {
    const res = compileGraph(
      intentGraph(["execute_sql"], [
        { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "([unclosed" }] }
      ]),
      "analytics"
    );
    expect(res.errors.map((e) => e.code)).toContain("invalid_constraint");
  });

  it("rejects an empty grant (which would silently widen the tool back to unconstrained)", () => {
    const res = compileGraph(intentGraph(["execute_sql"], [{ tool: "execute_sql", constraints: [] }]), "analytics");
    expect(res.errors.map((e) => e.code)).toContain("invalid_grant");
  });
});

describe("intent grants — back-compat", () => {
  /** The embedded graph blob is a faithful serialization of the graph object, so `grants: []` and an
   *  absent `grants` key legitimately produce different blob lines. The back-compat claim is about the
   *  ENFORCED POLICY, so compare the rego with the blob/hash provenance lines stripped. */
  const bodyOf = (rego: string) =>
    rego
      .split("\n")
      .filter((l) => !l.startsWith("# nrvq-builder-graph/v1:") && !l.startsWith("# nrvq-builder-hash:"))
      .join("\n");

  it("an empty grants list enforces exactly what no grants key enforces", () => {
    const withoutKey = intentGraph(["execute_sql", "search_kb"]);
    const withEmpty = intentGraph(["execute_sql", "search_kb"]);
    (withEmpty.allowlist as { grants?: unknown }).grants = [];
    const a = compileGraph(withoutKey, "analytics");
    const b = compileGraph(withEmpty, "analytics");
    expect(b.errors).toEqual([]);
    expect(bodyOf(b.rego)).toBe(bodyOf(a.rego));
  });

  it("no constraint machinery leaks into a policy that has no constraints", () => {
    const { rego, errors } = compileGraph(intentGraph(["execute_sql", "search_kb"]), "analytics");
    expect(errors).toEqual([]);
    // A pre-2d graph must compile to what it always did — no accessors, no gate, no extra rule_id.
    expect(rego).not.toContain("constraints_ok");
    expect(rego).not.toContain("_p_str");
    expect(rego).not.toContain("intent_constraint_violation");
    expect(rego).not.toContain("Per-tool scope");
  });
});
