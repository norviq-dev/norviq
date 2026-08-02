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
});
