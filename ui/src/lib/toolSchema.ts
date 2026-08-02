// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Turning a tool's declared JSON Schema into the set of arguments a policy can actually address.
 *
 * WHY THIS IS NOT A JSON SCHEMA LIBRARY. We are not validating documents; we are answering one narrow
 * question — "which `param_paths.<path>` keys will exist at runtime, and what may an operator say about
 * them?" — and the answer is governed by the EVALUATOR's behaviour, not by the spec. `_walk_paths`
 * (norviq/engine/evaluator.py:823-854) emits a key only for STRING leaves:
 *
 *     if isinstance(value, str) and prefix:
 *         out[prefix] = value[: self._MAX_PATH_VALUE_LEN]
 *
 * So a property declared `integer`, `number` or `boolean` produces NO key at all. Both compilers emit
 * `object.get(input.derived.param_paths, "<path>", "")`, which then evaluates against `""` — meaning an
 * `equals` on a numeric argument is not merely unlikely to match, it can never match. Inside an
 * allowlist grant that is a permanent block on the tool; in rules mode it is a rule that never fires.
 * Offering such a path would be shipping a control that silently cannot work, which is precisely what
 * BuilderSheet's condition palette refused to do when it left these condition types out entirely.
 *
 * Hence: every property is REPORTED, but only the ones that can work are `addressable`. Hiding the rest
 * would repeat the capability-fragment mistake from the other direction — a picker that quietly omits an
 * argument teaches the operator it does not exist.
 *
 * Bounds mirror the evaluator's own (`_MAX_PATH_DEPTH`, `_MAX_PATHS`), because a path deeper or later
 * than the evaluator will walk cannot appear at runtime no matter what the schema says. The schema is
 * server-controlled text, so the walk is bounded for its own sake too.
 */

import { PARAM_PATH_SUFFIX_RE } from "./builderCompile";

/** Mirrors evaluator.py `_MAX_PATH_DEPTH`. */
const MAX_DEPTH = 12;
/** Mirrors evaluator.py `_MAX_PATHS`. */
const MAX_PATHS = 256;

export interface SchemaPath {
  /** Dotted path WITHOUT the `param_paths.` prefix, e.g. `filters.customer`. */
  path: string;
  /** Declared JSON Schema type, or `"unknown"` when the schema does not say. */
  type: string;
  /** Whether `param_paths.<path>` can match anything at runtime. */
  addressable: boolean;
  /** Why it cannot be used, or a caveat when it can. Always shown — never silently applied. */
  note?: string;
  /** Declared `enum`, when the property has one. Feeds the value picker. */
  enumValues?: string[];
  /** Whether the parent object lists this property in `required`. */
  required: boolean;
}

function declaredType(node: Record<string, unknown>): string {
  const t = node.type;
  if (typeof t === "string") return t;
  // `["string", "null"]` is the common nullable idiom — the string arm is what matters to us.
  if (Array.isArray(t)) {
    const named = t.filter((x): x is string => typeof x === "string" && x !== "null");
    if (named.includes("string")) return "string";
    if (named.length > 0) return named[0];
  }
  return "unknown";
}

function enumOf(node: Record<string, unknown>): string[] | undefined {
  const raw = node.enum;
  if (!Array.isArray(raw) || raw.length === 0) return undefined;
  // Only string members are usable: the value ends up in a rego set literal compared against a
  // param_paths value, which is always a string.
  const values = raw.filter((v): v is string => typeof v === "string");
  return values.length > 0 ? values : undefined;
}

/**
 * Every argument path a tool's `inputSchema` declares, in the order an operator would read them.
 *
 * Unresolvable constructs (`$ref`, `oneOf`, `anyOf`, `allOf`) are reported as non-addressable rather than
 * guessed at: picking one arm of a union would name an argument the tool may not actually take.
 */
export function schemaPaths(schema: unknown): SchemaPath[] {
  const out: SchemaPath[] = [];
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return out;

  const walk = (node: Record<string, unknown>, prefix: string, depth: number): void => {
    if (out.length >= MAX_PATHS || depth > MAX_DEPTH) return;
    const properties = node.properties;
    if (!properties || typeof properties !== "object" || Array.isArray(properties)) return;
    const required = new Set(
      Array.isArray(node.required) ? node.required.filter((r): r is string => typeof r === "string") : []
    );

    for (const [key, rawChild] of Object.entries(properties as Record<string, unknown>)) {
      if (out.length >= MAX_PATHS) return;
      if (!rawChild || typeof rawChild !== "object" || Array.isArray(rawChild)) continue;
      const child = rawChild as Record<string, unknown>;
      const path = prefix ? `${prefix}.${key}` : key;
      const isRequired = required.has(key);

      // The charset gate runs before anything else: the evaluator will happily build a key for an
      // argument named "user email", but `_PARAM_PATH_RE` rejects the field on both compilers, so the
      // condition could never be saved. Better to say so than to emit an unsaveable option.
      if (!PARAM_PATH_SUFFIX_RE.test(path)) {
        out.push({
          path,
          type: declaredType(child),
          addressable: false,
          note: "argument name uses characters a policy field cannot contain",
          required: isRequired
        });
        continue;
      }

      if (child.$ref !== undefined || child.oneOf !== undefined || child.anyOf !== undefined || child.allOf !== undefined) {
        out.push({
          path,
          type: declaredType(child),
          addressable: false,
          note: "shape depends on a reference or union the builder cannot resolve",
          required: isRequired
        });
        continue;
      }

      const type = declaredType(child);

      if (type === "object") {
        // Not addressable itself — only its string leaves are — but its children are, so recurse.
        walk(child, path, depth + 1);
        continue;
      }

      if (type === "array") {
        out.push({
          path,
          type,
          addressable: false,
          // The evaluator indexes concretely: {"ids": ["C-91"]} becomes `ids[0]`. A schema says the
          // argument is a list but never how long, so no index derived here would be trustworthy.
          note: "list arguments are indexed at runtime (…[0], …[1]) — scope by a seen path, or use “any parameter value”",
          required: isRequired
        });
        continue;
      }

      if (type === "string") {
        out.push({ path, type, addressable: true, enumValues: enumOf(child), required: isRequired });
        continue;
      }

      if (type === "unknown") {
        // We genuinely do not know. Offering it with the caveat beats hiding a real text argument,
        // and beats claiming it will work.
        out.push({
          path,
          type,
          addressable: true,
          note: "no declared type — matches only if the value arrives as text",
          enumValues: enumOf(child),
          required: isRequired
        });
        continue;
      }

      out.push({
        path,
        type,
        addressable: false,
        note: `${type} arguments never appear in param_paths — only text does`,
        required: isRequired
      });
    }
  };

  walk(schema as Record<string, unknown>, "", 0);
  return out;
}

/** The addressable subset, which is what a picker offers as selectable. */
export function addressablePaths(schema: unknown): SchemaPath[] {
  return schemaPaths(schema).filter((p) => p.addressable);
}
