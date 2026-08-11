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
  /**
   * Declared JSON Schema type, or `"unknown"` when the schema does not say.
   *
   * One inference, and only one: a node carrying an object-only keyword (`properties`,
   * `additionalProperties`, `patternProperties`) is reported as `"object"` even with no `type`, because
   * those keywords ARE the schema saying so. See `looksLikeObject` for why reading it as an untyped
   * scalar instead was a fail-open.
   */
  type: string;
  /** Whether `param_paths.<path>` can match anything at runtime. */
  addressable: boolean;
  /** Why it cannot be used, or a caveat when it can. Always shown — never silently applied. */
  note?: string;
  /** Declared `enum`, when the property has one. Feeds the value picker. */
  enumValues?: string[];
  /** Whether the parent object lists this property in `required`. */
  required: boolean;
  /**
   * The property's own `description`, when it declares one.
   *
   * ⚠️ ATTACKER-ADJACENT. This is server-authored text out of `approved_canonical` — the same
   * provenance as the tool-level description that `GET /api/v1/tools` withholds when the definition
   * scanner condemns it. The scanner explicitly reports findings against paths like
   * `inputSchema.properties.q.description`, so injection text lives here too.
   *
   * The endpoint ships `input_schema` whole (it has to — paths, types and enums all come from it) and
   * only nulls the tool-level `description`. So the withholding decision has to be honoured by whoever
   * RENDERS this: when a tool's `description_withheld` is true, do not display these either. See
   * `ArgumentTree`'s `suppressDescriptions` prop.
   */
  description?: string;
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

/** A property's own `description`, when it declares a non-empty string one. */
function descriptionOf(node: Record<string, unknown>): string | undefined {
  const d = node.description;
  return typeof d === "string" && d.trim() !== "" ? d : undefined;
}

/** How many properties this node NAMES, in a `properties` bag shaped the way the walk can read. */
function namedPropertyCount(node: Record<string, unknown>): number {
  const properties = node.properties;
  return !!properties && typeof properties === "object" && !Array.isArray(properties)
    ? Object.keys(properties as Record<string, unknown>).length
    : 0;
}

/**
 * Does this node say, in so many words, that it carries keys it does not name?
 *
 * Strictly, JSON Schema treats an absent `additionalProperties` as unconstrained, so EVERY object is
 * open and every one of them would earn a caveat — which would put one on `filters` and drown the case
 * that matters. The line is drawn at an EXPLICIT statement: `additionalProperties` present and not
 * `false`, or a non-empty `patternProperties` bag. Those are the server saying "expect keys I have not
 * listed", and each such key becomes a real `param_paths.<parent>.<key>` at runtime that no declared
 * path covers.
 */
function declaresUnnamedProperties(node: Record<string, unknown>): boolean {
  const extra = node.additionalProperties;
  if (extra !== undefined && extra !== false) return true;
  const patterns = node.patternProperties;
  return (
    !!patterns &&
    typeof patterns === "object" &&
    !Array.isArray(patterns) &&
    Object.keys(patterns as Record<string, unknown>).length > 0
  );
}

/**
 * Is this an object, whatever it did or did not put in `type`?
 *
 * `properties`, `additionalProperties` and `patternProperties` are object-only keywords, so a node
 * carrying one IS an object even when `type` is missing — and hand-written MCP schemas omit `type`
 * constantly. Reading `{filters: {properties: {customer: {type: "string"}}}}` as an untyped scalar was
 * wrong twice over: `filters.customer` never appeared in the tree or the count, and `filters` itself was
 * offered as ADDRESSABLE under "matches only if the value arrives as text". It never arrives as text —
 * the evaluator keys string leaves — so that path compares against `""` forever: a permanent block
 * inside an allowlist grant and, in rules mode, a rule that silently never fires. A declared `type` is
 * still believed over the inference; this only fills the gap where the schema said nothing.
 */
function looksLikeObject(node: Record<string, unknown>, type: string): boolean {
  if (type === "object") return true;
  if (type !== "unknown") return false;
  return namedPropertyCount(node) > 0 || declaresUnnamedProperties(node);
}

/** Deeper than the evaluator will ever walk — the dominant fact whenever it applies. */
function depthNote(): string {
  return `nested deeper than the evaluator walks (${MAX_DEPTH} levels) — no path under it can appear in param_paths`;
}

/**
 * Why an object property yielded no paths — the sentence shown on its own (non-addressable) row.
 *
 * Every branch says the same operative thing in different words: sub-paths under here WILL exist at
 * runtime and this schema cannot name them, so scoping the tool's other arguments leaves this one
 * unconstrained. Saying "it declares no arguments" or showing nothing at all would be a measurement
 * claim we have not earned.
 */
function objectSilenceNote(node: Record<string, unknown>, childDepth: number): string {
  if (childDepth > MAX_DEPTH) return depthNote();
  if (namedPropertyCount(node) > 0) {
    return "the schema names properties here but none in a form this can read — sub-paths appear at runtime and cannot be scoped from the schema";
  }
  return "free-form object — the schema names no properties, so its sub-paths appear only at runtime and scoping this tool's other arguments leaves them unconstrained";
}

/**
 * The note for an object that names SOME properties and declares it accepts more.
 *
 * This is the hole in reporting only the objects that yielded nothing: add one readable property to a
 * free-form object and it stops yielding nothing, so the row disappears again and the count reads a
 * confident "1 of 1". `{options: {type: "object", properties: {mode: {type: "string"}},
 * additionalProperties: true}}` really does produce `param_paths.options.anything` at runtime, and an
 * operator who scopes `options.mode` has been shown a complete-looking list of what constraining this
 * argument covers. The partial case needs the caveat more than the empty one, not less — an empty
 * object at least looks empty.
 */
function objectOpenNote(childDepth: number): string {
  if (childDepth > MAX_DEPTH) return depthNote();
  return "the schema also accepts properties it does not name (additionalProperties) — those appear only at runtime, so scoping the ones listed under it leaves the rest unconstrained";
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
      // Carried on EVERY outcome, addressable or not: an operator deciding whether an argument is the
      // one they mean needs its description most when the row is disabled and they are looking for an
      // alternative. See the field's doc comment for why rendering it is gated on the tool's
      // `description_withheld`.
      const description = descriptionOf(child);

      // The charset gate runs before anything else: the evaluator will happily build a key for an
      // argument named "user email", but `_PARAM_PATH_RE` rejects the field on both compilers, so the
      // condition could never be saved. Better to say so than to emit an unsaveable option.
      if (!PARAM_PATH_SUFFIX_RE.test(path)) {
        out.push({
          path,
          type: declaredType(child),
          addressable: false,
          note: "argument name uses characters a policy field cannot contain",
          required: isRequired,
          description
        });
        continue;
      }

      if (child.$ref !== undefined || child.oneOf !== undefined || child.anyOf !== undefined || child.allOf !== undefined) {
        out.push({
          path,
          type: declaredType(child),
          addressable: false,
          note: "shape depends on a reference or union the builder cannot resolve",
          required: isRequired,
          description
        });
        continue;
      }

      const type = declaredType(child);

      if (looksLikeObject(child, type)) {
        // Names some properties AND says it accepts unnamed ones. The recursion WILL emit rows, so the
        // before/after check below can never fire — the caveat has to be pushed on the way in. Pushed
        // BEFORE the recursion on purpose: `ArgumentTree.toTreeRows` synthesises a branch node the
        // first time it sees a dotted path, so a parent row arriving after its own children would be a
        // duplicate row under a duplicate React key rather than the branch they hang from.
        if (declaresUnnamedProperties(child) && namedPropertyCount(child) > 0) {
          out.push({
            path,
            type: "object",
            addressable: false,
            note: objectOpenNote(depth + 1),
            required: isRequired,
            description
          });
          walk(child, path, depth + 1);
          continue;
        }

        // Not addressable itself — only its string leaves are — but its children are, so recurse.
        const before = out.length;
        walk(child, path, depth + 1);
        if (out.length > before) continue;

        // The recursion produced nothing, so the object would otherwise VANISH — from the tree and from
        // the "n of m" count above it. That is the one thing this module promises never to do, and the
        // silence is not harmless: the evaluator walks the PAYLOAD, not the schema, so
        // `{options: {type: "object", additionalProperties: {type: "string"}}}` really does produce
        // `param_paths.options.mode` at runtime. Dropping the row tells an operator the tool takes one
        // argument and that scoping it constrains the whole call, while `options.*` stays wide open.
        out.push({
          path,
          type: "object",
          addressable: false,
          note: objectSilenceNote(child, depth + 1),
          required: isRequired,
          description
        });
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
          required: isRequired,
          description
        });
        continue;
      }

      if (type === "string") {
        out.push({ path, type, addressable: true, enumValues: enumOf(child), required: isRequired, description });
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
          required: isRequired,
          description
        });
        continue;
      }

      out.push({
        path,
        type,
        addressable: false,
        note: `${type} arguments never appear in param_paths — only text does`,
        required: isRequired,
        description
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

/**
 * Did the TOP-LEVEL definition tell us anything we could read?
 *
 * `schemaPaths` returns `[]` for two situations that must not read the same on screen:
 *
 *   1. `{type: "object", properties: {}}` — the tool positively declares no arguments. "This tool
 *      declares no arguments" is true of it.
 *   2. `{type: "object", additionalProperties: {type: "string"}}` — the definition is free-form, or the
 *      `properties` key is missing or is not an object. We measured nothing. Saying "declares no
 *      arguments" there is a claim about the tool made from a schema we could not read, and it sits
 *      beside a "Scopeable" badge and a "0 of 0" count that repeat it.
 *
 * The nested version of this is handled inside `schemaPaths` (the object property is emitted as a
 * non-addressable row with the reason on it). The top level has no row to hang the reason from, so the
 * distinction has to be made by whoever renders the empty state — `ArgumentTree`'s `emptyLabel`,
 * `Tools.argCount`, and the badge next to it. This is that predicate; it exists so those three read the
 * schema the same way instead of each growing its own idea of "empty".
 */
export function schemaIsReadable(schema: unknown): boolean {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return false;
  const properties = (schema as Record<string, unknown>).properties;
  return !!properties && typeof properties === "object" && !Array.isArray(properties);
}
