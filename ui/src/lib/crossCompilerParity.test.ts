// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Cross-compiler parity — the TYPESCRIPT half.
//
// Two compilers now emit Rego for overlapping intent semantics: this one (builderCompile.ts) and the
// server's norviq/engine/intent/compiler.py. Neither derives from the other and each has its own
// passing suite, which is exactly how two implementations of one idea drift apart unnoticed.
//
// tests/fixtures/cross_compiler/*.json states each policy TWICE — once as a declared intent, once as
// a BuilderGraph — with the calls to evaluate and the decision both must reach. This file asserts the
// graph half; tests/engine/test_cross_compiler_parity.py asserts the intent half against the SAME
// fixtures and the SAME expected decisions.
//
// Decisions are compared, never emitted text. The intent compiler emits _predicates/_failed for its
// near-miss explainer and the builder emits allow_names plus refinement helpers, so the modules
// legitimately differ in shape — a text assertion would pin an irrelevance and miss the only thing
// that matters.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import type { BuilderGraph } from "./builderGraph";

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
const FIXTURE_DIR = join(REPO_ROOT, "tests", "fixtures", "cross_compiler");

type Fixture = {
  name: string;
  why: string;
  graph: BuilderGraph | null;
  gap?: string;
  cases: { note: string; input: Record<string, unknown>; expect: "allow" | "block" }[];
};

function loadFixtures(): Fixture[] {
  // Both reads are against a path built from __dirname at module load — no input reaches either, and
  // the filenames come from the directory listing itself. Enumerating the directory (rather than
  // hardcoding a list) is the point: a fixture added by either side of the parity contract is picked
  // up by both consumers automatically, so the two cannot drift by one forgetting to register it.
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- repo-relative dir from __dirname
  return readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort()
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- basenames from the listing above
    .map((f) => JSON.parse(readFileSync(join(FIXTURE_DIR, f), "utf8")) as Fixture);
}

/** Single writeFileSync call site — see builderIntentGrants.test.ts for why this is funnelled. */
function writeFixtureFile(dir: string, name: string, body: string): string {
  const path = join(dir, name);
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- mkdtemp dir + literal basename
  writeFileSync(path, body, "utf8");
  return path;
}

function decide(rego: string, input: Record<string, unknown>): string {
  const dir = mkdtempSync(join(tmpdir(), "nrvq-parity-"));
  const policyPath = writeFixtureFile(dir, "policy.rego", rego);
  const pkg = /^package\s+(\S+)/m.exec(rego)?.[1];
  if (!pkg) throw new Error("compiled rego has no package line");
  const inputPath = writeFixtureFile(dir, "input.json", JSON.stringify(input));
  const out = execFileSync(
    "opa",
    ["eval", "--v0-compatible", "-d", policyPath, "-i", inputPath, "-f", "json", `data.${pkg}.decision`],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  const parsed = JSON.parse(out);
  if (parsed?.errors?.length) throw new Error(`opa errors: ${JSON.stringify(parsed.errors)}`);
  return parsed?.result?.[0]?.expressions?.[0]?.value ?? "<undefined>";
}

const fixtures = loadFixtures();

describe("cross-compiler parity — the builder half", () => {
  it("finds the shared fixtures", () => {
    // A parity guard with no fixtures passes vacuously, which is worse than not having one. This also
    // fails loudly if the fixture directory is ever moved out from under one of the two consumers.
    expect(fixtures.length).toBeGreaterThan(0);
    // ...and each must actually assert something. A fixture with `cases: []` compiles on both halves
    // and asserts zero decisions, so the contract can be silently emptied while both suites stay green.
    for (const fx of fixtures) {
      expect(fx.cases?.length, `${fx.name}: has no cases, so it proves nothing`).toBeGreaterThan(0);
    }
  });

  for (const fx of fixtures) {
    if (!fx.graph) {
      it(`${fx.name}: records why the builder cannot express it yet`, () => {
        // Not a skip. The intent side still asserts this fixture, and the recorded gap is what stops
        // "the builder can't say this" from quietly becoming permanent.
        expect(fx.gap, `${fx.name}: graph is null but no gap explains why`).toBeTruthy();
      });
      continue;
    }
    itOpa(`${fx.name}: reaches the same decision the intent compiler does`, () => {
      const res = compileGraph(fx.graph as BuilderGraph, "analytics");
      expect(res.errors, `${fx.name} failed to compile`).toEqual([]);
      for (const c of fx.cases) {
        expect(decide(res.rego, c.input), `${fx.name} / ${c.note}`).toBe(c.expect);
      }
    });
  }
});
