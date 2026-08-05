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
import { schemaPaths, addressablePaths, schemaIsReadable } from "./toolSchema";

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

  it("carries a property's own description, on addressable AND non-addressable rows alike", () => {
    // The design renders a description under each argument. It matters MOST on a disabled row: that is
    // exactly when an operator is reading the list looking for an alternative to the one they cannot use.
    const p = byPath({
      type: "object",
      properties: {
        to: { type: "string", description: "recipient email" },
        retries: { type: "integer", description: "how many times to retry" }
      }
    });
    expect(p["to"].description).toBe("recipient email");
    expect(p["retries"].addressable).toBe(false);
    expect(p["retries"].description, "a disabled row still needs its description").toBe("how many times to retry");
  });

  it("treats a blank or non-string description as absent", () => {
    const p = byPath({
      type: "object",
      properties: { a: { type: "string", description: "   " }, b: { type: "string", description: 42 } }
    });
    expect(p["a"].description).toBeUndefined();
    expect(p["b"].description).toBeUndefined();
  });

  it("does not invent a description where the schema declares none", () => {
    // Guards against a renderer that would otherwise show a stale value from a sibling.
    const p = byPath({ type: "object", properties: { to: { type: "string" } } });
    expect(p["to"].description).toBeUndefined();
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

/**
 * An object the walk cannot see into used to disappear entirely — from the tree AND from the "n of m"
 * count, under the sentence "Unusable ones are shown, never hidden."
 *
 * That is not a cosmetic omission. The evaluator walks the PAYLOAD, not the schema, so a free-form
 * object really does produce `param_paths.options.mode` at runtime. An operator reading "1 of 1" and one
 * addressable `query` row concludes the tool takes one argument and that scoping it constrains the call,
 * while everything under `options` stays unconstrained. Reporting it disabled, with the reason, is the
 * same rule the numeric and array branches already follow.
 */
describe("schemaPaths — an object it cannot read must not vanish", () => {
  const FREE_FORM = {
    type: "object",
    properties: {
      query: { type: "string" },
      options: { type: "object", additionalProperties: { type: "string" } }
    }
  };

  it("reports a free-form object property, and says why nothing under it can be scoped", () => {
    const p = byPath(FREE_FORM);
    expect(Object.keys(p)).toEqual(["query", "options"]);
    expect(p["options"].type).toBe("object");
    expect(p["options"].addressable).toBe(false);
    expect(p["options"].note).toMatch(/appear only at runtime/i);
  });

  it("keeps it out of the addressable set, so no picker offers a path that cannot work", () => {
    expect(addressablePaths(FREE_FORM).map((x) => x.path)).toEqual(["query"]);
  });

  it("makes the declared-argument count honest — 1 of 2, not 1 of 1", () => {
    // Tools.tsx renders `${addressable} of ${all}` off exactly these two numbers.
    const all = schemaPaths(FREE_FORM);
    expect(`${all.filter((x) => x.addressable).length} of ${all.length}`).toBe("1 of 2");
  });

  it("covers an object that declares an empty property bag the same way", () => {
    const p = byPath({ type: "object", properties: { meta: { type: "object", properties: {} } } });
    expect(p["meta"].addressable).toBe(false);
    expect(p["meta"].note).toMatch(/names no properties/i);
  });

  it("still emits leaves only when the object HAS readable children", () => {
    // The contract the compiler depends on, and ArgumentTree's synthesised branches with it.
    const paths = schemaPaths({
      type: "object",
      properties: { filters: { type: "object", properties: { customer: { type: "string" }, count: { type: "integer" } } } }
    }).map((x) => x.path);
    expect(paths).toEqual(["filters.customer", "filters.count"]);
  });

  it("names the deepest unreadable object by its full dotted path", () => {
    const paths = schemaPaths({
      type: "object",
      properties: { a: { type: "object", properties: { b: { type: "object", additionalProperties: true } } } }
    });
    expect(paths.map((x) => x.path)).toEqual(["a.b"]);
    expect(paths[0].addressable).toBe(false);
  });

  it("carries required and description onto the reported object row", () => {
    const p = byPath({
      type: "object",
      required: ["options"],
      properties: { options: { type: "object", description: "arbitrary passthrough", additionalProperties: true } }
    });
    expect(p["options"].required).toBe(true);
    expect(p["options"].description).toBe("arbitrary passthrough");
  });

  it("does not claim an object is empty when it was the DEPTH bound that stopped the walk", () => {
    // Two different facts, two different sentences: "the schema names nothing here" and "we stopped
    // looking". Reusing the first for the second would be the same false-measurement mistake.
    let deep: Record<string, unknown> = { type: "object", properties: { leaf: { type: "string" } } };
    for (let i = 0; i < 14; i++) deep = { type: "object", properties: { [`l${i}`]: deep } };
    const rows = schemaPaths(deep);
    expect(rows).toHaveLength(1);
    expect(rows[0].addressable).toBe(false);
    expect(rows[0].note).toMatch(/deeper than the evaluator walks/i);
    expect(rows[0].note).not.toMatch(/names no properties/i);
    expect(rows[0].path.split(".")).toHaveLength(13);
  });

  it("separates 'declares no arguments' from 'we could not read this definition'", () => {
    // Both yield zero paths; only the first is a fact about the tool. A renderer that prints the same
    // sentence for both — beside a Scopeable badge and a "0 of 0" — states a measurement it never made.
    expect(schemaIsReadable({ type: "object", properties: {} })).toBe(true);
    expect(schemaIsReadable({ type: "object", properties: { a: { type: "string" } } })).toBe(true);

    for (const unreadable of [
      { type: "object", additionalProperties: { type: "string" } },
      { type: "object" },
      { type: "object", properties: [] },
      { type: "object", properties: null },
      null,
      undefined,
      42,
      "nope",
      []
    ]) {
      expect(schemaIsReadable(unreadable), JSON.stringify(unreadable) + " names nothing we can read").toBe(false);
      expect(schemaPaths(unreadable)).toEqual([]);
    }
  });

  it("stays inside the breadth bound while reporting them", () => {
    const wide = {
      type: "object",
      properties: Object.fromEntries(Array.from({ length: 600 }, (_, i) => [`p${i}`, { type: "object" }]))
    };
    expect(schemaPaths(wide).length).toBe(256);
  });
});

/**
 * Reporting only the objects that yielded NOTHING is one property away from reporting nothing at all.
 *
 * `{options: {type: "object", additionalProperties: true}}` is caught. Give that same object a single
 * readable property and the recursion emits a row, the "did the walk produce anything" check passes, the
 * caveat disappears, and the count reads a confident "1 of 1" — for a schema that says in its own text
 * that it accepts keys it has not named. The evaluator walks the PAYLOAD, so `options.anything` is a
 * real `param_paths` key at runtime; an operator who scopes `options.mode` has been shown a
 * complete-looking list of what constraining this argument covers.
 *
 * The partial case needs the caveat MORE than the empty one, not less: an empty object at least looks
 * empty.
 */
describe("schemaPaths — an object that names some keys and accepts others", () => {
  const PARTLY_OPEN = {
    type: "object",
    properties: {
      query: { type: "string" },
      options: {
        type: "object",
        properties: { mode: { type: "string" } },
        additionalProperties: { type: "string" }
      }
    }
  };

  it("reports the object itself even though its children came through", () => {
    const paths = schemaPaths(PARTLY_OPEN);
    expect(paths.map((p) => p.path)).toEqual(["query", "options", "options.mode"]);
    expect(paths[1].addressable).toBe(false);
    expect(paths[1].type).toBe("object");
    expect(paths[1].note).toMatch(/accepts properties it does not name/i);
  });

  it("puts the parent BEFORE its children, which is what keeps ArgumentTree a tree", () => {
    // `toTreeRows` synthesises a branch the first time it sees a dotted path and pushes every spec row
    // unconditionally, so a parent arriving after its own child is a second row under a duplicate React
    // key instead of the branch the child hangs from.
    const paths = schemaPaths(PARTLY_OPEN).map((p) => p.path);
    // Both indices asserted present first: `indexOf` returns -1 for a row that is not there at all, and
    // -1 < 1 would let this pass on the very code it exists to catch.
    expect(paths).toContain("options");
    expect(paths).toContain("options.mode");
    expect(paths.indexOf("options")).toBeLessThan(paths.indexOf("options.mode"));
  });

  it("makes the count say 2 of 3 — the readable child is not the whole story", () => {
    const all = schemaPaths(PARTLY_OPEN);
    expect(`${all.filter((p) => p.addressable).length} of ${all.length}`).toBe("2 of 3");
    expect(addressablePaths(PARTLY_OPEN).map((p) => p.path)).toEqual(["query", "options.mode"]);
  });

  it("treats patternProperties the same way, since it is the same statement", () => {
    const p = byPath({
      type: "object",
      properties: {
        headers: { type: "object", properties: { auth: { type: "string" } }, patternProperties: { "^x-": { type: "string" } } }
      }
    });
    expect(p["headers"].addressable).toBe(false);
    expect(p["headers"].note).toMatch(/does not name/i);
  });

  it("stays silent about an object that is merely UNSPECIFIED, so the caveat keeps its meaning", () => {
    // JSON Schema says an absent `additionalProperties` is unconstrained, so a caveat on every object
    // would put one on `filters` too and mean nothing. The line is an explicit statement by the schema.
    const closed = { type: "object", properties: { filters: { type: "object", properties: { customer: { type: "string" } } } } };
    expect(schemaPaths(closed).map((p) => p.path)).toEqual(["filters.customer"]);

    const denied = {
      type: "object",
      properties: { filters: { type: "object", properties: { customer: { type: "string" } }, additionalProperties: false } }
    };
    expect(schemaPaths(denied).map((p) => p.path)).toEqual(["filters.customer"]);
  });

  it("cannot push the caveat past the breadth bound", () => {
    // The caveat row is emitted BEFORE the recursion rather than after it, which puts a `push` on a path
    // the `out.length >= MAX_PATHS` guard does not sit directly in front of. The schema is
    // server-controlled text, so the bound has to hold on that path too.
    const wide = {
      type: "object",
      properties: Object.fromEntries(
        Array.from({ length: 600 }, (_, i) => [
          `p${i}`,
          { type: "object", properties: { a: { type: "string" } }, additionalProperties: true }
        ])
      )
    };
    expect(schemaPaths(wide)).toHaveLength(256);
  });

  it("reports the depth bound as the depth bound, not as additionalProperties", () => {
    // Two facts compete on this row and only one of them is the operative one. Sat exactly ON the bound
    // (the open object lands on the 13th segment, so its own walk is refused), the reason nothing is
    // under it is that we stopped looking — reporting "it also accepts unnamed properties" there would
    // name a real caveat as the cause of a limit we imposed ourselves.
    let deep: Record<string, unknown> = {
      type: "object",
      properties: { leaf: { type: "string" } },
      additionalProperties: true
    };
    for (let i = 0; i < 13; i++) deep = { type: "object", properties: { [`l${i}`]: deep } };
    const rows = schemaPaths(deep);
    expect(rows).toHaveLength(1);
    expect(rows[0].path.split(".")).toHaveLength(13);
    expect(rows[0].note).toMatch(/deeper than the evaluator walks/i);
    expect(rows[0].note).not.toMatch(/does not name/i);
  });
});

/**
 * A node carrying `properties` but no `type` was read as an untyped scalar — and offered as ADDRESSABLE.
 *
 * Two failures in one. The declared children (`filters.customer`) never reached the tree or the count,
 * and `param_paths.filters` was offered as a usable condition under "matches only if the value arrives
 * as text". It never arrives as text: the evaluator keys string leaves, so an object parent produces no
 * key and the compiled predicate compares against `""` forever — a permanent block inside an allowlist
 * grant, and in rules mode a rule that can never fire, which is the fail-open this module exists to
 * refuse. Hand-written MCP schemas omit `type` constantly.
 */
describe("schemaPaths — object-only keywords ARE the schema saying 'object'", () => {
  it("walks into a properties bag that never declared a type", () => {
    const paths = schemaPaths({
      type: "object",
      properties: { filters: { properties: { customer: { type: "string" }, count: { type: "integer" } } } }
    });
    expect(paths.map((p) => p.path)).toEqual(["filters.customer", "filters.count"]);
    expect(paths[0].addressable).toBe(true);
  });

  it("never offers an untyped object parent as an addressable path", () => {
    for (const shape of [
      { properties: { customer: { type: "string" } } },
      { additionalProperties: { type: "string" } },
      { patternProperties: { "^x-": { type: "string" } } }
    ]) {
      const rows = schemaPaths({ type: "object", properties: { blob: shape } });
      expect(rows.find((r) => r.path === "blob")?.addressable ?? false, JSON.stringify(shape)).toBe(false);
    }
  });

  it("still believes a declared type over the inference", () => {
    // A schema that says `string` and also carries a stray `properties` is taken at its word — the
    // inference only fills a gap, it never overrules.
    const p = byPath({ type: "object", properties: { name: { type: "string", properties: { junk: { type: "string" } } } } });
    expect(p["name"].addressable).toBe(true);
    expect(p["name"].type).toBe("string");
    expect(Object.keys(p)).toEqual(["name"]);
  });

  it("leaves a genuinely empty schema alone, so the caveat is not pinned on every untyped argument", () => {
    // `{}` says nothing at all — no object keyword, no type. It stays the "no declared type" offer.
    const p = byPath({ type: "object", properties: { blob: {} } });
    expect(p["blob"].addressable).toBe(true);
    expect(p["blob"].note).toMatch(/no declared type/i);
  });
});
