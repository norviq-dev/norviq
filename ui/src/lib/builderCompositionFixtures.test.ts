// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The engine composes a TIGHTEN-ONLY module as an overlay (norviq/engine/composition.py): it can make a
// decision stricter and never looser, whatever its priority. It recognises such a module from what the
// two generators here write — the builder's rules mode with an allow default, and the New Policy
// composer. tests/engine/test_tighten_only_composition.py evaluates the modules in
// tests/fixtures/builder_composition/ through the real engine, and tests/api/test_dryrun_replay.py
// replays recorded calls against the allowlist one. This file keeps those modules equal to what the
// generators emit today, so neither test can pass against rego the console no longer writes.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { compileGraph } from "./builderCompile";
import type { BuilderGraph } from "./builderGraph";
import { composerRego } from "./composerRego";

const FIXTURE_DIR = join(__dirname, "..", "..", "..", "tests", "fixtures", "builder_composition");

type Fixture = {
  name: string;
  tighten_only: boolean;
  targetNamespace?: string;
  graph?: BuilderGraph;
  composer?: { agentClass: string; mode: string; keywords: string[] };
  rego: string;
};

function fixtures(): Fixture[] {
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- repo-relative dir from __dirname
  return readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort()
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- basenames from the listing above
    .map((f) => JSON.parse(readFileSync(join(FIXTURE_DIR, f), "utf8")) as Fixture);
}

describe("builder composition fixtures", () => {
  it("exist, and cover both answers", () => {
    const all = fixtures();
    expect(all.some((f) => f.tighten_only)).toBe(true);
    expect(all.some((f) => !f.tighten_only)).toBe(true);
  });

  it("an allowlist's header does not call it tighten-only; the engine resolves it by priority", () => {
    const allowlists = fixtures().filter((f) => f.graph?.mode === "allowlist");
    expect(allowlists.length).toBeGreaterThan(0);
    for (const fx of allowlists) {
      const { rego } = compileGraph(fx.graph as BuilderGraph, fx.targetNamespace ?? "");
      expect(rego).not.toMatch(/DEFAULT-DENY, TIGHTEN-ONLY/);
      expect(rego).toMatch(/# NOT TIGHTEN-ONLY: this policy decides for its scope\./);
    }
  });

  for (const fx of fixtures()) {
    it(`${fx.name}: the stored rego is what the generator emits today`, () => {
      if (fx.graph) {
        const out = compileGraph(fx.graph, fx.targetNamespace ?? "");
        expect(out.errors).toEqual([]);
        expect(out.rego).toBe(fx.rego);
      } else if (fx.composer) {
        expect(composerRego(fx.composer.agentClass, fx.composer.mode, fx.composer.keywords)).toBe(fx.rego);
      } else {
        throw new Error(`${fx.name}: names neither a graph nor a composer input`);
      }
    });
  }
});
