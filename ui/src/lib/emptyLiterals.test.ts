// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The console's generators at the input that leaves a collection EMPTY — the counterpart of
// tests/engine/test_empty_literals.py for the server's generators.
//
// OPA 1.21 types a bare `{}`, `set()` or `[]` as having no members, so reading from one is
// `rego_type_error: undefined ref` and the module fails to compile; the engine then blocks every call
// the policy governs as `evaluator_error`. The builder emitted `escalates[id] { id := [][_] }` for
// every decision set a graph did not use (nearly every rules-mode policy), `allow_names := {}` for an
// allowlist that denies everything, and the composer `composer_keywords := set()` for a cleared keyword
// box. These run the engine's own pre-push gate (`opa check --v0-compatible --capabilities`) and then
// DECIDE, with whatever `opa` is on PATH — CI's is the pinned one. The text guard runs without opa.

import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import type { BuilderDecision, BuilderGraph } from "./builderGraph";
import { composerRego } from "./composerRego";

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
const CAPS = join(REPO_ROOT, "norviq", "engine", "opa-capabilities.json");

/** Single writeFileSync call site — see builderIntentGrants.test.ts for why this is funnelled. */
function writeFixture(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- mkdtemp dir + literal basename
  writeFileSync(path, body, "utf8");
  return path;
}

function prePushGate(rego: string): void {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-empty-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  execFileSync("opa", ["check", "--v0-compatible", `--capabilities=${CAPS}`, policyPath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function decide(rego: string, input: Record<string, unknown>): { decision: string; rule_id: string } {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-empty-"));
  const policyPath = writeFixture(dir, "policy.rego", rego);
  const inputPath = writeFixture(dir, "input.json", JSON.stringify(input));
  const pkg = /^package\s+(\S+)/m.exec(rego)?.[1];
  if (!pkg) throw new Error("rego has no package line");
  const read = (field: string): string => {
    const out = execFileSync(
      "opa",
      ["eval", "--v0-compatible", "-d", policyPath, "-i", inputPath, "-f", "json", `data.${pkg}.${field}`],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    return JSON.parse(out)?.result?.[0]?.expressions?.[0]?.value ?? "<undefined>";
  };
  return { decision: read("decision"), rule_id: read("rule_id") };
}

function call(toolName: string, params: Record<string, unknown> = {}) {
  return {
    tool_name: toolName,
    tool_name_normalized: toolName.toLowerCase(),
    tool_params: params,
    agent: { spiffe_id: "spiffe://norviq/ns/analytics/sa/report-gen", namespace: "analytics", agent_class: "report-gen" },
    call_depth: 0,
    trust_score: 0.9,
    derived: { verb: "read" }
  };
}

/** A rules-mode graph whose only rule uses `decision` — so the other two decision sets are unused. */
function oneSetGraph(decision: BuilderDecision): BuilderGraph {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "report-gen" },
    mode: "rules",
    rules: [
      {
        id: "r1",
        ruleId: "r_drop",
        decision,
        reason: "named a dropped table",
        conditions: [[{ type: "toolIn", tools: ["drop_table"] }]]
      }
    ],
    defaults: { decision: "allow", reason: "default" }
  };
}

const EMPTY_ALLOWLIST: BuilderGraph = {
  schemaVersion: 1,
  scope: { kind: "class", agentClass: "report-gen" },
  mode: "allowlist",
  rules: [],
  defaults: { decision: "allow", reason: "n/a" },
  allowlist: { tools: [], refinements: { readonly: true, egress: true, scope: true, rate: true } }
};

function compiled(graph: BuilderGraph): string {
  const res = compileGraph(graph, "analytics");
  expect(res.errors).toEqual([]);
  return res.rego;
}

// Mirrors the Python guard: a bare empty literal assigned or iterated in place.
const BARE_EMPTY = /(?:^|\s)(?::=|=)\s*(?:\{\}|\[\]|set\(\))\s*$|\[\]\[_\]|set\(\)\[_\]|\bset\(\)/;

function bareEmptyLines(rego: string): string[] {
  return rego
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#") && BARE_EMPTY.test(line))
    .map((line) => line.trim());
}

const CASES: Array<[string, () => string]> = [
  ["builder: block rule only (escalates + audits unused)", () => compiled(oneSetGraph("block"))],
  ["builder: escalate rule only (blocks + audits unused)", () => compiled(oneSetGraph("escalate"))],
  ["builder: audit rule only (blocks + escalates unused)", () => compiled(oneSetGraph("audit"))],
  ["builder: allowlist with no tools, every refinement", () => compiled(EMPTY_ALLOWLIST)],
  ["composer: keyword box cleared", () => composerRego("report-gen", "block", [])]
];

describe("empty collections — every console generator's output compiles on the pinned opa", () => {
  it.each(CASES)("%s writes no bare empty literal", (_name, build) => {
    expect(bareEmptyLines(build())).toEqual([]);
  });

  itOpa.each(CASES)("%s passes the engine's pre-push gate", (_name, build) => {
    prePushGate(build());
  });

  itOpa.each([["block"], ["escalate"], ["audit"]] as Array<[BuilderDecision]>)(
    "a %s-only rules policy still decides: its rule fires, and an unrelated call is the default allow",
    (decision) => {
      const rego = compiled(oneSetGraph(decision));
      expect(decide(rego, call("drop_table"))).toEqual({ decision, rule_id: "r_drop" });
      expect(decide(rego, call("get_report")).decision).toBe("allow");
    }
  );

  itOpa("an allowlist with no tools is the default deny — a policy decision, not an engine error", () => {
    expect(decide(compiled(EMPTY_ALLOWLIST), call("get_report"))).toEqual({
      decision: "block",
      rule_id: "intent_default_deny"
    });
  });

  itOpa("a composer policy with no keywords matches nothing", () => {
    const rego = composerRego("report-gen", "block", []);
    expect(decide(rego, call("rm_secret_token", { q: "secret" })).decision).toBe("allow");
  });
});
