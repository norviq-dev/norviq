// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * What a declared schema may and may not promise about `param_paths`.
 *
 * The property under test throughout is NOT "does it enumerate the schema" — it is that every path the
 * walker marks `addressable` would actually produce a runtime key. The evaluator emits keys for string
 * leaves only, so a numeric path offered here compiles to a predicate comparing against `""`, which can
 * never be true: a permanent block inside an allowlist grant, a rule that never fires in rules mode.
 */

import { describe, it, expect } from "vitest";
import { schemaPaths, addressablePaths } from "./toolSchema";

const byPath = (schema: unknown) => Object.fromEntries(schemaPaths(schema).map((p) => [p.path, p]));

describe("schemaPaths — what the evaluator will actually key", () => {
  it("offers string leaves, at the top level and nested", () => {
    const paths = addressablePaths({
      type: "object",
      properties: {
        to: { type: "string" },
        filters: { type: "object", properties: { customer: { type: "string" } } }
      }
    }).map((p) => p.path);
    expect(paths).toEqual(["to", "filters.customer"]);
  });

  it("REFUSES numeric and boolean leaves, because no key is ever emitted for them", () => {
    // evaluator.py:852 `if isinstance(value, str)`. A count/enabled argument produces no param_paths
    // entry at all, so `object.get(..., "")` compares against "" forever.
    const p = byPath({
      type: "object",
      properties: { count: { type: "integer" }, ratio: { type: "number" }, enabled: { type: "boolean" } }
    });
    for (const key of ["count", "ratio", "enabled"]) {
      expect(p[key].addressable, `${key} must not be offered`).toBe(false);
      expect(p[key].note).toMatch(/only text/i);
    }
  });

  it("reports the unusable ones rather than hiding them", () => {
    // Silently omitting an argument teaches the operator it does not exist — the capability-fragment
    // mistake in reverse.
    const all = schemaPaths({ type: "object", properties: { count: { type: "integer" } } });
    expect(all.map((x) => x.path)).toEqual(["count"]);
  });

  it("refuses arrays, because the runtime key carries a concrete index a schema cannot know", () => {
    const p = byPath({ type: "object", properties: { ids: { type: "array", items: { type: "string" } } } });
    expect(p["ids"].addressable).toBe(false);
    expect(p["ids"].note).toMatch(/indexed at runtime/i);
  });

  it("refuses a name the policy field charset cannot hold, even though a runtime key would exist", () => {
    // The evaluator builds `user email` happily; `_PARAM_PATH_RE` rejects the field on both compilers,
    // so the condition could be authored and never saved.
    const p = byPath({ type: "object", properties: { "user email": { type: "string" }, "a/b": { type: "string" } } });
    expect(p["user email"].addressable).toBe(false);
    expect(p["a/b"].addressable).toBe(false);
    expect(p["user email"].note).toMatch(/characters a policy field cannot contain/i);
  });

  it("refuses $ref and union arms rather than guessing an arm", () => {
    const p = byPath({
      type: "object",
      properties: {
        payload: { $ref: "#/definitions/Thing" },
        either: { oneOf: [{ type: "string" }, { type: "integer" }] }
      }
    });
    expect(p["payload"].addressable).toBe(false);
    expect(p["either"].addressable).toBe(false);
    expect(p["either"].note).toMatch(/reference or union/i);
  });

  it("treats a nullable string as a string", () => {
    const p = byPath({ type: "object", properties: { note: { type: ["string", "null"] } } });
    expect(p["note"].addressable).toBe(true);
    expect(p["note"].type).toBe("string");
  });

  it("offers an undeclared type WITH the caveat, rather than hiding a real text argument", () => {
    const p = byPath({ type: "object", properties: { blob: {} } });
    expect(p["blob"].addressable).toBe(true);
    expect(p["blob"].note).toMatch(/no declared type/i);
  });

  it("carries string enums through for the value picker, and drops non-string members", () => {
    const p = byPath({
      type: "object",
      properties: {
        region: { type: "string", enum: ["us-east", "eu-west"] },
        mixed: { type: "string", enum: [1, 2] }
      }
    });
    expect(p["region"].enumValues).toEqual(["us-east", "eu-west"]);
    expect(p["mixed"].enumValues).toBeUndefined();
  });

  it("marks required properties", () => {
    const p = byPath({ type: "object", required: ["to"], properties: { to: { type: "string" }, cc: { type: "string" } } });
    expect(p["to"].required).toBe(true);
    expect(p["cc"].required).toBe(false);
  });

  it("survives junk without throwing — the schema is server-controlled text", () => {
    for (const junk of [null, undefined, 42, "nope", [], { properties: null }, { properties: [] }]) {
      expect(() => schemaPaths(junk)).not.toThrow();
      expect(schemaPaths(junk)).toEqual([]);
    }
  });

  it("bounds depth and breadth the way the evaluator does", () => {
    // Deeper than _MAX_PATH_DEPTH cannot appear at runtime whatever the schema claims, and the schema
    // is attacker-adjacent, so the walk is bounded for its own sake too.
    let deep: Record<string, unknown> = { type: "string" };
    for (let i = 0; i < 40; i++) deep = { type: "object", properties: { [`l${i}`]: deep } };
    expect(() => schemaPaths(deep)).not.toThrow();
    expect(schemaPaths(deep).length).toBeLessThanOrEqual(256);

    const wide = {
      type: "object",
      properties: Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`p${i}`, { type: "string" }]))
    };
    expect(schemaPaths(wide).length).toBeLessThanOrEqual(256);
  });

  it("does not offer the object itself, only its leaves", () => {
    const paths = schemaPaths({
      type: "object",
      properties: { filters: { type: "object", properties: { customer: { type: "string" } } } }
    }).map((p) => p.path);
    expect(paths).toEqual(["filters.customer"]);
  });
});
