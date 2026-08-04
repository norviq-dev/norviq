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
import type { BuilderGraph, BuilderParamConstraint, BuilderGrantFact } from "./builderGraph";

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

function intentGraph(
  tools: string[],
  // `facts` as well as `constraints`: the grant editor's PRIMARY picker emits a param_paths FACT for
  // a declared argument, and the helper's type had no way to express that — so every test written
  // through it exercised only the constraint path, which is how a compiler gap survived on the other.
  grants?: Array<{ tool: string; constraints: BuilderParamConstraint[]; facts?: BuilderGrantFact[] }>
): BuilderGraph {
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


/** Evaluate a compiled module against a FULL input document (the grant-facts tests need to set
 *  `derived`, which the tool/params helper above synthesises rather than accepts). */
function decideDoc(rego: string, input: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-grantfacts-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  const pkg = /^package\s+(\S+)/m.exec(rego)![1];
  const inputPath = writeFixture(dir, "input.json", JSON.stringify(input));
  return evalQuery(policyPath, inputPath, `data.${pkg}.decision`);
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

describe("grant facts — narrowing by what the call CARRIES, not just by one argument", () => {
  // Constraints address `input.tool_params[field]`: ONE flat named parameter. That cannot say the
  // things deny-by-default actually needs — "must not carry a credential", "the recipient must be
  // in-domain", "only these tables" — because those are facts about the whole call. Grants carry them
  // as `facts` now, which is what let cross_compiler/credential-egress.json gain a builder half.

  itOpa("a fact in a grant is a REQUIREMENT to allow, the inverse of the same fact in a rule", () => {
    // The sense is genuinely invertible and worth pinning: {data_classes noneOf [secret]} here means
    // "allowed only if it carries no secret"; the identical condition in rules mode means "BLOCK when
    // it carries no secret". Getting this backwards would allow exactly the calls it should refuse.
    const { rego, errors } = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [
            {
              tool: "send_email",
              constraints: [],
              facts: [{ type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] }]
            }
          ]
        }
      },
      "analytics"
    );
    expect(errors).toEqual([]);
    // `tool_name_normalized` is REQUIRED now, and that is the point: the grant gate keys on the
    // evasion-normalized name so a homoglyph cannot be admitted by the allowlist and then skip its
    // constraints. The engine always supplies it (_build_input -> skeleton(tool_name)), so a test
    // input without one was testing a document the evaluator never produces.
    const clean = { tool_name: "send_email", tool_name_normalized: "send_email", tool_params: { body: "hi" },
      agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
      call_depth: 0, derived: { data_classes: [] } };
    const dirty = { ...clean, tool_params: { body: "AKIAIOSFODNN7EXAMPLE" }, derived: { data_classes: ["secret"] } };
    expect(decideDoc(rego, clean)).toBe("allow");
    expect(decideDoc(rego, dirty)).toBe("block");
  });

  it("a grant carrying ONLY facts is valid — requiring a constraint would drop the narrowing", () => {
    const res = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [{ tool: "send_email", constraints: [],
            facts: [{ type: "collectionFact", field: "destinations.emails", op: "subsetOf", values: ["ops@acme.com"] }] }]
        }
      },
      "analytics"
    );
    expect(res.errors).toEqual([]);
    expect(res.rego).toContain("destinations");
  });

  it("the header states the scope a facts-only grant enforces, instead of a bare empty line", () => {
    // The header comment is what a reviewer reads in the catalog and in git; the embedded graph blob is
    // base64 and not human-legible. Rendering only `constraints` printed `#   send_email: ` for a
    // facts-only grant — a policy documenting itself as narrowed by nothing while enforcing two
    // predicates below it. The "(1 constrained tool)" count on the line above was already correct,
    // which is precisely what made the empty line read as authoritative rather than as a bug.
    const { rego, errors } = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [
            {
              tool: "send_email",
              constraints: [],
              facts: [
                { type: "collectionFact", field: "data_classes", op: "noneOf", values: ["secret"] },
                { type: "numericFact", field: "trust_score", op: "min", value: 0.7 }
              ]
            }
          ]
        }
      },
      "analytics"
    );
    expect(errors).toEqual([]);
    const line = rego.split("\n").find((l) => l.startsWith("#   send_email:"));
    expect(line, "a constrained tool must get a summary line at all").toBeDefined();
    expect(line).toContain("data_classes excludes {secret}");
    expect(line).toContain("trust_score >= 0.7");
  });

  it("renders a NEGATED fact as negated, rather than printing the inner fact unqualified", () => {
    // A `not`-wrapped fact has no row form in BuilderSheet, so this comment is the only place an
    // operator ever sees it. Printing the inner fact without the negation would state the exact
    // opposite of what the compiled rule enforces.
    const { rego, errors } = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [
            {
              tool: "send_email",
              constraints: [],
              facts: [{ type: "not", inner: { type: "collectionFact", field: "sql_tables", op: "anyOf", values: ["payouts"] } }]
            }
          ]
        }
      },
      "analytics"
    );
    expect(errors).toEqual([]);
    const line = rego.split("\n").find((l) => l.startsWith("#   send_email:"));
    expect(line).toContain("NOT (sql_tables intersects {payouts})");
  });

  it("refuses a rules-only condition inside a grant, which could only ever WIDEN it", () => {
    // A grant exists to narrow an already-allowed tool. A detector or trust threshold is not a fact
    // about the call's arguments, and admitting one here would let an allowlist entry be widened by
    // something the allowlist never authorised.
    const res = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [{ tool: "send_email", constraints: [],
            facts: [{ type: "detector", detector: "sql_injection" } as never] }]
        }
      },
      "analytics"
    );
    expect(res.errors.map((e) => e.code)).toContain("invalid_grant");
    expect(res.rego).toBe("");
  });

  it("still rejects a grant that narrows nothing at all", () => {
    const res = compileGraph(
      {
        ...intentGraph(["send_email"]),
        allowlist: {
          tools: ["send_email"],
          refinements: { readonly: false, egress: false, scope: false, rate: false },
          grants: [{ tool: "send_email", constraints: [], facts: [] }]
        }
      },
      "analytics"
    );
    expect(res.errors.map((e) => e.code)).toContain("invalid_grant");
  });
});

describe("evasion: the allowlist and the grant gate must agree on what 'the tool' is", () => {
  itOpa("a homoglyph name cannot be admitted by the allowlist and then skip its constraints", () => {
    // `in_allowlist` matches `allow_skeletons[input.tool_name_normalized]` DELIBERATELY, so homoglyph,
    // fullwidth and case tricks cannot smuggle a tool past the allow. The grant gate used to key on the
    // RAW `lower(input.tool_name)`, so a Cyrillic-e `еxеcute_sql` skeletoned to `execute_sql`, WAS
    // admitted, and then missed `_constrained` entirely — `constraints_ok { not _constrained[...] }`
    // held and every per-tool constraint was skipped. Demonstrated with `DROP TABLE orders`, which
    // violates the grant's ^select constraint: it evaluated to `allow`.
    const { rego, errors } = compileGraph(
      intentGraph(["execute_sql"], [
        { tool: "execute_sql", constraints: [{ kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);

    const call = (rawName: string, query: string) => ({
      tool_name: rawName,
      // What the engine computes: skeleton() folds the confusables back to ASCII.
      tool_name_normalized: "execute_sql",
      tool_params: { query },
      agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
      call_depth: 0
    });

    const HOMOGLYPH = "\u0435x\u0435cute_sql"; // Cyrillic U+0435 in place of both ASCII 'e'
    expect(HOMOGLYPH).not.toBe("execute_sql");

    // The honest tool, used the way the grant permits.
    expect(decideDoc(rego, call("execute_sql", "SELECT id FROM orders"))).toBe("allow");
    // The honest tool, forbidden argument — blocked, as before.
    expect(decideDoc(rego, call("execute_sql", "DROP TABLE orders"))).toBe("block");
    // The EVASION: admitted by the allowlist via its skeleton, so it must still face the constraint.
    expect(decideDoc(rego, call(HOMOGLYPH, "DROP TABLE orders"))).toBe("block");
    // ...and must still be allowed when it obeys it, or the fix would just be a blanket denial.
    expect(decideDoc(rego, call(HOMOGLYPH, "SELECT id FROM orders"))).toBe("allow");
  });

  itOpa("...and the MIRROR IMAGE: a non-ASCII allowlist ENTRY still binds its constraint", () => {
    // The first fix for the homoglyph bypass re-keyed the grant gate from the raw name onto the
    // normalized one — and opened this. `in_allowlist` matches on TWO forms:
    //     in_allowlist { allow_names[lower(input.tool_name)] }
    //     in_allowlist { allow_skeletons[input.tool_name_normalized] }
    // so a gate covering only one leaves the other as a hole, whichever one it picks. Here the
    // operator's own entry is Cyrillic: the builder's TS skeleton does not fold cross-script
    // confusables (a documented gap in skeleton.ts) while the ENGINE's does, so `_constrained` held
    // "еxеcute_sql" and the engine sent "execute_sql" — the raw branch admitted the call and the
    // constraint was skipped. `DROP TABLE orders` was ALLOWED against a grant requiring ^select.
    const CYRILLIC = "\u0435x\u0435cute_sql";
    const { rego, errors } = compileGraph(
      intentGraph([CYRILLIC], [
        { tool: CYRILLIC, constraints: [{ kind: "matches", field: "query", pattern: "(?i)^\\s*select\\b" }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);
    const call2 = (query: string) => ({
      tool_name: CYRILLIC,
      tool_name_normalized: "execute_sql", // what the ENGINE computes — deliberately != the TS skeleton
      tool_params: { query },
      agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
      call_depth: 0
    });
    expect(decideDoc(rego, call2("DROP TABLE orders"))).toBe("block");
    expect(decideDoc(rego, call2("SELECT id FROM orders"))).toBe("allow");
  });
  itOpa("a NEGATED constraint is not satisfied by a value it cannot READ", () => {
    // THE BUG THIS PINS. `_p_str` returns a "\u0000" sentinel for an absent or wrong-typed param.
    // For a POSITIVE kind that is exactly right — the sentinel matches nothing, so the constraint
    // fails and the call is denied. Under `not` it INVERTS: "the sentinel does not match your
    // pattern" reads as "your constraint is satisfied", and the grant holds.
    //
    // Measured against real opa before the fix: `{"columns": ["card_number","ssn"]}` -> allow, while
    // the string `"card_number, ssn"` -> block. The UI's own placeholder for `notMatches` advertises
    // exactly the column-list shape ("e.g. (?i)(card_number|ssn) — never these columns"), so the
    // vacuous case was the one the product taught operators to write.
    //
    // The sibling test above already covers OMISSION; these are the wrong-TYPE shapes, which no test
    // reached because every fixture in this file passed strings.
    const { rego, errors } = compileGraph(
      intentGraph(["read_table"], [
        {
          tool: "read_table",
          constraints: [
            { kind: "oneOf", field: "table", values: ["users", "orders"] },
            { kind: "notMatches", field: "columns", pattern: "(?i)(card_number|ssn)" }
          ]
        }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);

    // The shapes that always behaved.
    expect(decide(rego, "read_table", { table: "users", columns: "card_number, ssn" })).toBe("block");
    expect(decide(rego, "read_table", { table: "users", columns: "id, created_at" })).toBe("allow");

    // The shapes that used to evaporate the constraint entirely: the forbidden text is CARRIED, just
    // not at the top level, so the constraint must still fail.
    expect(decide(rego, "read_table", { table: "users", columns: ["card_number", "ssn"] })).toBe("block");
    expect(decide(rego, "read_table", { table: "users", columns: { a: "card_number" } })).toBe("block");
    // ...and the argument omitted: the panel promises "a parameter that isn't supplied fails its line".
    expect(decide(rego, "read_table", { table: "users" })).toBe("block");

    // REWRITTEN ASSERTION — this line read `columns: 42 -> "block"` and that is no longer the correct
    // answer. `42` was denied only as collateral of the first repair, which required a TOP-LEVEL STRING
    // (`_has_str`) and so made a `notMatches` grant UNSATISFIABLE for every object, list and number:
    // measured, `body: {"user":"alice"}`, `body: ["a","b"]` and `body: 42` all flipped allow -> BLOCK,
    // denying the tool 100% of the time whatever it carried. The constraint the operator wrote is about
    // CONTENT — "these columns must never appear" — and the number 42 contains no column name. It is
    // the tool's declared schema (the MCP firewall's `_schema_violations`), not a content pattern, that
    // decides whether `columns` may be a number at all.
    expect(decide(rego, "read_table", { table: "users", columns: 42 })).toBe("allow");
  });

  itOpa("a NEGATED constraint stays SATISFIABLE for the shapes it does not forbid", () => {
    // The over-block the `_has_str` repair introduced, pinned in the direction it broke. A clause that
    // can never hold is not a narrow policy, it is an outage: the tool is denied regardless of content,
    // including for the very shape this kind's own placeholder advertises.
    const { rego, errors } = compileGraph(
      intentGraph(["http_post"], [
        { tool: "http_post", constraints: [{ kind: "notMatches", field: "body", pattern: "(?i)password" }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);

    // Clean, in every shape a real tool takes: allowed.
    expect(decide(rego, "http_post", { url: "u", body: "hello" })).toBe("allow");
    expect(decide(rego, "http_post", { url: "u", body: { user: "alice" } })).toBe("allow");
    expect(decide(rego, "http_post", { url: "u", body: ["a", "b"] })).toBe("allow");
    expect(decide(rego, "http_post", { url: "u", body: 42 })).toBe("allow");

    // Carrying the forbidden text, in every shape: denied — including the nested and list forms that
    // were the original bypass. Widening WHERE the clause reads is what closes those; it must not also
    // widen WHICH calls it refuses.
    expect(decide(rego, "http_post", { url: "u", body: "the password is hunter2" })).toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: { content: "the password is hunter2" } })).toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: ["the password is hunter2"] })).toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: { a: { b: ["the password is hunter2"] } } })).toBe("block");

    // Omitted still denies — the documented half, and the one the panel states in words.
    expect(decide(rego, "http_post", { url: "u" })).toBe("block");
  });

  // THE WALK MUST NOT BE ESCAPABLE BY RE-TYPING THE VALUE. Widening the negated kinds from "the
  // top-level string" to "every string beneath the parameter" closed the array/nested bypass and left
  // a narrower one open one JSON type away: a walk filtered by `is_string` cannot see a number, so the
  // identical characters sent unquoted became invisible to the clause whose whole job is to refuse
  // them. Measured with `is_string`: `body: "4111111"` blocked, `body: 4111111` ALLOWED.
  //
  // This is not the same question as `columns: 42` (asserted `allow` above and still correct): 42 does
  // not contain a forbidden column NAME. Here the digits ARE the forbidden content, and the only thing
  // that changed between the blocked call and the allowed one is a pair of quotes.
  itOpa("a NEGATED constraint is not escaped by sending the forbidden value as a NUMBER", () => {
    const { rego, errors } = compileGraph(
      intentGraph(["http_post"], [
        { tool: "http_post", constraints: [{ kind: "notMatches", field: "body", pattern: "4[0-9]{6}" }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);
    expect(decide(rego, "http_post", { url: "u", body: "4111111" }), "string").toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: 4111111 }), "number").toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: [4111111] }), "number in a list").toBe("block");
    expect(decide(rego, "http_post", { url: "u", body: { card: 4111111 } }), "number nested").toBe("block");
    // ...and the widening still does not cost a clean call: these carry no matching digits at all.
    expect(decide(rego, "http_post", { url: "u", body: 12 }), "clean number").toBe("allow");
    expect(decide(rego, "http_post", { url: "u", body: "hello" }), "clean string").toBe("allow");
  });

  // Sharper for `noneOf` than for `notMatches`, because the operator typed the denied value out by
  // hand: `noneOf account ["12345"]` blocked `"12345"` and ALLOWED `12345`.
  itOpa("a NEGATED set constraint is not escaped by sending the denied value as a NUMBER", () => {
    const { rego, errors } = compileGraph(
      intentGraph(["read_table"], [
        { tool: "read_table", constraints: [{ kind: "noneOf", field: "account", values: ["12345", "root"] }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);
    expect(decide(rego, "read_table", { account: "12345" }), "string").toBe("block");
    expect(decide(rego, "read_table", { account: 12345 }), "number").toBe("block");
    expect(decide(rego, "read_table", { account: [12345] }), "number in a list").toBe("block");
    // A value that is genuinely not on the list still passes, in either type.
    expect(decide(rego, "read_table", { account: "99999" }), "clean string").toBe("allow");
    expect(decide(rego, "read_table", { account: 99999 }), "clean number").toBe("allow");
    // A boolean renders as text too, and "true" is not on this list.
    expect(decide(rego, "read_table", { account: true }), "boolean").toBe("allow");
  });

  itOpa("a NEGATED set constraint (noneOf) is not satisfied by a value it cannot READ either", () => {
    const { rego, errors } = compileGraph(
      intentGraph(["read_table"], [
        { tool: "read_table", constraints: [{ kind: "noneOf", field: "table", values: ["payments"] }] }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);
    expect(decide(rego, "read_table", { table: "orders" })).toBe("allow");
    expect(decide(rego, "read_table", { table: "payments" })).toBe("block");
    // A LIST containing the denied value used to sail straight through.
    expect(decide(rego, "read_table", { table: ["payments"] })).toBe("block");
    // ...and the mirror image, which the `_has_str` repair got wrong: a list that carries NONE of the
    // denied values is not a violation, and denying it made the clause unsatisfiable for list-typed
    // arguments. `noneOf` says "not these", not "must be a bare string".
    expect(decide(rego, "read_table", { table: ["orders", "users"] })).toBe("allow");
    expect(decide(rego, "read_table", { table: { name: "orders" } })).toBe("allow");
    // Omission still denies.
    expect(decide(rego, "read_table", {})).toBe("block");
  });
});

describe("param_paths facts — the guard the PYTHON compiler had and this one did not", () => {
  /**
   * The audit's critical finding. `_has_str` landed on `constraintExpr`, but the grant editor's
   * PRIMARY picker routes a declared argument to a param_paths FACT, which compiles through a
   * different path — and that path defaulted an absent path to "" with no guard at all.
   *
   * So the two compilers disagreed on the same authored intent: Python blocked, this one allowed.
   * Measured against real opa, `param_paths.columns notMatches "(?i)(card_number|ssn)"`:
   *
   *     {"columns": "card_number, ssn"}        block   block     (the only agreeing case)
   *     {"columns": ["card_number","ssn"]}     block   ALLOW  <- the array _walk_paths always produces
   *     {"columns": {"list":"card_number"}}    block   ALLOW
   *     columns omitted                        block   ALLOW
   *
   * The cross-compiler parity fixture missed it because it covers a POSITIVE `matches` only, and
   * expresses the builder half as a tool_params CONSTRAINT rather than a param_paths FACT.
   */
  const factGraph = (op: "notMatches" | "matches", value: string) =>
    intentGraph(["read_table"], [
      { tool: "read_table", constraints: [], facts: [{ type: "scalarFact", field: "param_paths.columns", op, value }] }
    ]);

  // Same shape the passing grant-facts tests above use — the compiled policy guards on
  // `input.agent.agent_class`, so an agent_class that does not match the graph's scope falls to
  // default-block and every assertion becomes a tautology about the default.
  // `"omit"`, NOT `undefined`, and that is the whole reason the version-skew test below was reported
  // as an unexplained compiler gap for a whole commit. The signature was
  // `(paths, ambiguous: string[] | undefined = [])` with `if (ambiguous !== undefined)` inside — but a
  // JS default parameter fires on an EXPLICITLY passed `undefined` too, so `doc({...}, undefined)`
  // bound `ambiguous = []` and published `param_paths_ambiguous: []`. The fixture that was supposed to
  // model an engine too old to publish the fact modelled a CURRENT engine publishing an empty list, the
  // guard correctly allowed the honest call, and the test failed while the compiler was right. A
  // literal sentinel cannot be swallowed by a default the way `undefined` can.
  const doc = (paths: Record<string, string>, ambiguous: string[] | "omit" = []) => {
    const derived: Record<string, unknown> = { param_paths: paths };
    if (ambiguous !== "omit") derived.param_paths_ambiguous = ambiguous;
    return {
      tool_name: "read_table",
      tool_name_normalized: "read_table",
      tool_params: {},
      agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
      call_depth: 0,
      derived
    };
  };

  itOpa("a negated fact is not satisfied by a path the engine never derived", () => {
    const { rego, errors } = compileGraph(factGraph("notMatches", "(?i)(card_number|ssn)"), "analytics");
    expect(errors).toEqual([]);
    // The shape that always worked.
    expect(decideDoc(rego, doc({ columns: "card_number, ssn" }))).toBe("block");
    expect(decideDoc(rego, doc({ columns: "id, created_at" }))).toBe("allow");
    // An ARRAY argument — what _walk_paths produces for every list. `columns` itself is absent.
    expect(decideDoc(rego, doc({ "columns[0]": "card_number", "columns[1]": "ssn" }))).toBe("block");
    // A nested object, and the argument omitted entirely.
    expect(decideDoc(rego, doc({ "columns.list": "card_number" }))).toBe("block");
    expect(decideDoc(rego, doc({ table: "users" }))).toBe("block");
  });

  itOpa("a POSITIVE fact over a FORGED path does not hold either", () => {
    // Equally wrong: it reads the value the attacker minted and reports compliance.
    const { rego } = compileGraph(factGraph("matches", "^id$"), "analytics");
    expect(decideDoc(rego, doc({ columns: "id" }))).toBe("allow");
    expect(decideDoc(rego, doc({ columns: "id" }, ["columns"]))).toBe("block");
  });

  // WAS `itOpa.skip`, described as an open compiler gap ("something upstream in the allowlist grant
  // assembly still admits the call"). It was not a compiler gap. The FIXTURE could not express skew:
  // `doc(paths, ambiguous = [])` swallowed the explicit `undefined` this test passed, so the input
  // document carried `param_paths_ambiguous: []` and described a current engine. See the note on
  // `doc` above. The compiler fails closed here and always did — measured, with the fixture repaired.
  itOpa("an engine that does not publish the ambiguity list fails CLOSED", () => {
    const { rego } = compileGraph(factGraph("matches", "^id$"), "analytics");
    expect(decideDoc(rego, doc({ columns: "id" }, "omit"))).toBe("block");
  });

  // Every operator, not just the one the un-skipped test above happens to use: version skew must deny
  // whichever comparison the operator wrote, or "this engine cannot answer the question" is spelled
  // the same as "the answer was compliant" for the operators nobody wrote a case for.
  itOpa("version skew denies for EVERY scalar operator over a param_paths field", () => {
    const facts: Array<[string, BuilderGrantFact]> = [
      ["equals", { type: "scalarFact", field: "param_paths.columns", op: "equals", value: "id" }],
      ["in", { type: "scalarFact", field: "param_paths.columns", op: "in", values: ["id", "name"] }],
      ["matches", { type: "scalarFact", field: "param_paths.columns", op: "matches", value: "^id$" }],
      ["notMatches", { type: "scalarFact", field: "param_paths.columns", op: "notMatches", value: "(?i)ssn" }],
      [
        "NOT(matches)",
        { type: "not", inner: { type: "scalarFact", field: "param_paths.columns", op: "matches", value: "^ssn$" } }
      ]
    ];
    for (const [name, fact] of facts) {
      const { rego, errors } = compileGraph(
        intentGraph(["read_table"], [{ tool: "read_table", constraints: [], facts: [fact] }]),
        "analytics"
      );
      expect(errors, name).toEqual([]);
      // The honest call on a CURRENT engine is allowed — otherwise "denies on skew" would be
      // indistinguishable from "denies always", and a blanket denial proves nothing about skew.
      expect(decideDoc(rego, doc({ columns: "id" })), `${name} current`).toBe("allow");
      expect(decideDoc(rego, doc({ columns: "id" }, "omit")), `${name} skew`).toBe("block");
    }
  });

  // THE GUARD HAS TO SURVIVE A `not`. `withGuards` folds the guards and the predicate into one
  // `count([1 | guards; pred]) == 1`, which is FALSE when a guard fails — correct while it stands
  // alone, and exactly backwards once the compiler prefixes it with `not`: `not count(...) == 1` is
  // TRUE precisely when the path could not be read or was minted by the caller. Measured before the
  // fix, grant fact `NOT (param_paths.columns matches "^ssn$")` on an allowlisted `read_table`:
  // forged path ALLOW, path never derived ALLOW. A caller satisfied the grant by making the path
  // unreadable. `not` is a legal grant-fact shape (BuilderGrantFact admits a `not` wrapper), so this
  // is the same bypass the four plain operators were fixed for, reached one wrapper away.
  itOpa("a NOT-wrapped fact is not satisfied by a path the caller made unreadable", () => {
    const { rego, errors } = compileGraph(
      intentGraph(["read_table"], [
        {
          tool: "read_table",
          constraints: [],
          facts: [
            { type: "not", inner: { type: "scalarFact", field: "param_paths.columns", op: "matches", value: "^ssn$" } }
          ]
        }
      ]),
      "analytics"
    );
    expect(errors).toEqual([]);
    // Honest, compliant: `columns` is derived, is not ambiguous, and is not "ssn".
    expect(decideDoc(rego, doc({ columns: "id" }))).toBe("allow");
    // Honest, violating.
    expect(decideDoc(rego, doc({ columns: "ssn" }))).toBe("block");
    // FORGED — the engine names `columns` as caller-mintable, so no clause may trust it.
    expect(decideDoc(rego, doc({ columns: "id" }, ["columns"]))).toBe("block");
    // NEVER DERIVED — the array/nested/omitted shapes all land here.
    expect(decideDoc(rego, doc({ "columns[0]": "id" }))).toBe("block");
    expect(decideDoc(rego, doc({ table: "users" }))).toBe("block");
  });

  // Finding 17: the grant editor files `param_paths.<arg>` fact rows under an "Argument" heading whose
  // hint promises "A call that omits it fails this line", and the panel header says omitting an
  // argument cannot be used to skip a constraint. That promise is enforcement, so it is pinned here
  // rather than only asserted in copy — for the plain operators AND through the `not` wrapper.
  itOpa("the panel's omission promise holds for every param_paths fact row it prints", () => {
    const rows: Array<[string, BuilderGrantFact]> = [
      ["notMatches", { type: "scalarFact", field: "param_paths.columns", op: "notMatches", value: "(?i)(card_number|ssn)" }],
      ["matches", { type: "scalarFact", field: "param_paths.columns", op: "matches", value: "^id$" }],
      ["equals", { type: "scalarFact", field: "param_paths.columns", op: "equals", value: "id" }],
      ["in", { type: "scalarFact", field: "param_paths.columns", op: "in", values: ["id"] }],
      [
        "NOT(matches)",
        { type: "not", inner: { type: "scalarFact", field: "param_paths.columns", op: "matches", value: "^ssn$" } }
      ]
    ];
    for (const [name, fact] of rows) {
      const { rego, errors } = compileGraph(
        intentGraph(["read_table"], [{ tool: "read_table", constraints: [], facts: [fact] }]),
        "analytics"
      );
      expect(errors, name).toEqual([]);
      // `read_table({"table": "users"})` — `columns` omitted entirely.
      expect(decideDoc(rego, doc({ table: "users" })), `${name} omitted`).toBe("block");
    }
  });
});

// A RULES-MODE test, in the grants file, on purpose. `compileConditionLine` is shared by both sites,
// and the fix that made a `not`-wrapped grant fact fail closed (the test directly above) was applied
// to that shared emitter — where it silently inverted the OTHER site. The regression belongs next to
// the change that caused it, or the next person to fix one side breaks the other again.
describe("the same clause compiled at the OTHER site: a negated param_paths BLOCK rule", () => {
  /** Tighten-only graph, default ALLOW, one block rule whose single condition is `conditions[0][0]`. */
  const blockRuleGraph = (): BuilderGraph => ({
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "report-gen" },
    mode: "rules",
    rules: [
      {
        id: "r1",
        ruleId: "r_external_url",
        decision: "block",
        reason: "url is not an internal host",
        conditions: [
          [
            {
              type: "not",
              inner: { type: "scalarFact", field: "param_paths.url", op: "matches", value: "^https://internal\\." }
            }
          ]
        ]
      }
    ],
    defaults: { decision: "allow", reason: "default" }
  });

  const ruleDoc = (derived: Record<string, unknown>) => ({
    tool_name: "http_get",
    tool_name_normalized: "http_get",
    tool_params: { url: "x" },
    agent: {
      spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen",
      namespace: "analytics",
      agent_class: "report-gen"
    },
    call_depth: 0,
    derived
  });

  // "Block any call whose url is not an internal host" — the ordinary way to write an allowlist-shaped
  // restriction as a tighten-only rule, and the shape where the guard's placement decides everything.
  //
  // A grant body holding means ALLOW, so an unanswerable clause there must be FALSE (withhold the
  // allow). A block body holding means DENY, so an unanswerable clause here must be TRUE (fire the
  // block). Hoisting the guards outside the negation — correct for the grant — flipped this site:
  // measured, `count([1 | guards; not pred]) == 1` returned ALLOW for both untrustworthy documents
  // below, where `not count([1 | guards; pred]) == 1` returns block.
  //
  // The forged row is the one that makes this a bypass rather than a nicety: `param_paths_ambiguous`
  // is derived from the CALLER's own argument keys, so a caller who wants out of this rule only has to
  // send a key containing `.`/`[`/`]`. Under the hoisted shape the guard he tripped acquitted him.
  itOpa("fails CLOSED when the path is forged or was never derived", () => {
    const { rego, errors } = compileGraph(blockRuleGraph(), "analytics");
    expect(errors).toEqual([]);

    // Honest calls first — otherwise "blocks on an untrustworthy path" is indistinguishable from
    // "blocks everything", and a rule that blocks everything proves nothing about the guard.
    expect(
      decideDoc(rego, ruleDoc({ param_paths: { url: "https://internal.corp/x" }, param_paths_ambiguous: [] })),
      "honest internal"
    ).toBe("allow");
    expect(
      decideDoc(rego, ruleDoc({ param_paths: { url: "https://evil.example/x" }, param_paths_ambiguous: [] })),
      "honest external"
    ).toBe("block");

    // FORGED: the engine names `url` as caller-mintable, so the rule cannot conclude the url is
    // internal — and "cannot conclude" must not be spelled the same as "is internal".
    expect(
      decideDoc(rego, ruleDoc({ param_paths: { url: "https://internal.corp/x" }, param_paths_ambiguous: ["url"] })),
      "forged"
    ).toBe("block");

    // NEVER DERIVED: `{"url": {"href": "…"}}` derives `url.href`, a different key. The rule cannot read
    // the url it was written about.
    expect(
      decideDoc(rego, ruleDoc({ param_paths: { "url.href": "https://evil.example/x" }, param_paths_ambiguous: [] })),
      "never derived"
    ).toBe("block");

    // VERSION SKEW: no ambiguity list at all. Covered by `bld_unsupported_engine` rather than by the
    // clause, but asserted here so a change to either one cannot open it unnoticed.
    expect(decideDoc(rego, ruleDoc({ param_paths: { url: "https://evil.example/x" } })), "skew").toBe("block");
  });
});
