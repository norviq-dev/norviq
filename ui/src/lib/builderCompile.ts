// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Visual Policy Builder — graph → rego compiler (client-side TS, the composerRego.ts idiom
// generalized to a multi-rule, multi-condition graph). Deterministic: sorted keyword/tool sets,
// stable rule ordering (graph order), stable helper/detector ordering (builderTemplates.ts's fixed
// HELPER_ORDER/DETECTOR_ORDER), so the same graph always compiles to the byte-identical rego string
// (stable diffs in the existing version history — plan §2).
//
// Every user-supplied literal (class name in the guard, rule_id, reason, keywords, tool names) is
// passed through JSON.stringify before being placed inside a rego STRING literal — the
// composerRego.ts idiom — so graph content can never inject rego syntax. The one place a literal is
// interpolated OUTSIDE a JSON.stringify'd string is the descriptive header COMMENT line; that value
// is newline-stripped first (comments run to end-of-physical-line in rego, so an embedded newline
// could otherwise "break out" of the comment into live code).
//
// Emission shape (fixed, matches plan §2 + comprehensive.rego's own shape):
//   header comment (incl. embedded graph blob + body hash) → default triple → helper/predicate
//   blocks (each emitted once, deduped) → partial-set triggers (one block per OR row, same rule_id
//   for every row of one rule) → reasons map → the verbatim resolver template.
//
// NO round-trip: the embedded `# nrvq-builder-graph/v1:` blob is base64(JSON.stringify(graph)),
// plain (no gzip, per the spike scope) — enough to reconstruct the graph exactly on reopen; hand
// edits to the rego are detected by re-hashing the body (`# nrvq-builder-hash:`) via
// `detachmentStatusOf()` below.
//
// PRODUCTIONIZATION FOLLOW-UP (out of scope for this spike): today the graph's only home is this
// base64 blob riding along inside the rego source's header comment. A real product would also persist
// the graph as structured data — e.g. a `graph_json` column on the policies table — so the backend
// can index/query/migrate it without round-tripping through rego text, and so detachment can be
// server-verified instead of only client-verified. That's a separate backend PR against
// norviq/api/routers/policies.py + the policies table migration, not this UI-only spike.

import type {
  BuilderAllowlist,
  BuilderAllowlistGrant,
  BuilderAllowlistRefinements,
  BuilderCondition,
  BuilderCollectionFactField,
  BuilderNumericFactField,
  BuilderParamConstraint,
  BuilderConditionParamRegex,
  BuilderConditionScalarFact,
  BuilderDetector,
  BuilderGrantFact,
  BuilderGraph,
  BuilderKeywordTarget,
  BuilderMode,
  BuilderRule,
  BuilderScope
} from "./builderGraph";
import { normalizeKeywords, sanitizeClassToken } from "./composerRego";
import { DETECTOR_BLOCKS, DETECTOR_HELPERS, DETECTOR_ORDER, DETECTOR_PREDICATE, HELPER_BLOCKS, HELPER_ORDER, type HelperKey } from "./builderTemplates";
import { fragmentsFor, listCapabilitySourceVerbPairs, verbsForSource, type CapabilityVerb, type CapabilitySourceKey } from "./capabilitySources";
import { skeleton } from "./skeleton";
import { isReservedScope } from "./reservedScope";

// --- server-side budget caps (norviq/api/routers/policies.py validate_rego_source L590) ---
// The builder enforces the SAME caps client-side so a graph that would be rejected by the write
// gate is never even offered to the user as "ready to save" — the server gate is still the backstop.
export const BUDGET_MAX_BYTES = 65536;
export const BUDGET_MAX_LINES = 500;
export const BUDGET_MAX_REGEX_OPS = 25;

export type BuilderErrorCode =
  | "empty_rule_id"
  | "empty_reason"
  | "duplicate_rule_id"
  | "reserved_default_rule_id"
  | "empty_conditions"
  | "empty_keyword_list"
  | "empty_tool_list"
  | "threshold_out_of_range"
  | "invalid_source_verb"
  | "paramRegex_invalid"
  | "not_double_negation"
  | "invalid_allowlist"
  | "empty_allowlist_tool"
  /** Per-tool constraint problems (Phase 2d). `grant_not_allowlisted` and `duplicate_grant` are called
   *  out separately from the generic `invalid_grant` because both describe a policy that would be QUIETLY
   *  MORE PERMISSIVE than what the operator wrote — the failure mode worth naming precisely. */
  | "invalid_grant"
  | "grant_not_allowlisted"
  | "duplicate_grant"
  | "invalid_constraint"
  | "reserved_scope"
  /** A condition whose `type` this build does not recognise — only reachable from a rehydrated or
   *  hand-edited embedded graph, never from the UI. See validateCondition's trailing `else`. */
  | "unknown_condition"
  /** A scope whose tier this build does not recognise, or whose identifier is not a string — same
   *  provenance as `unknown_condition` (a rehydrated blob, never the UI). Needed as an ERROR because
   *  `scopeIdentifier`'s exhaustiveness fallback returns the scope OBJECT for an unknown tier, which
   *  `commentSafe` then throws on: a TypeError escaping `compileGraph` breaks the {rego, errors}
   *  contract the sheet needs in order to say "this policy cannot be opened in the builder". */
  | "unknown_scope"
  /** Scoping-fact problems. `empty_fact_values` is its own code because an empty list is not a no-op:
   *  `noneOf []` and `subsetOf []` are TAUTOLOGIES, so the rule reads as a restriction and enforces
   *  nothing — the same class of quiet over-permissiveness as `grant_not_allowlisted` above. */
  | "unknown_fact_field"
  | "empty_fact_values"
  | "fact_count_invalid"
  | "budget_exceeded_bytes"
  | "budget_exceeded_lines"
  | "budget_exceeded_regex_ops";

export interface BuilderError {
  code: BuilderErrorCode;
  message: string;
  ruleIndex?: number;
  rowIndex?: number;
  conditionIndex?: number;
}

export interface CompileStats {
  bytes: number;
  lines: number;
  regexOps: number;
}

export interface CompileResult {
  rego: string;
  stats: CompileStats;
  errors: BuilderError[];
}

// --- deterministic byte-level helpers (base64 / fnv1a), environment-agnostic (Node + browser) ---

/** UTF-8-safe base64 encode. Uses global TextEncoder + btoa (both present in Node 18+ and browsers). */
export function toBase64(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

/** Inverse of toBase64. */
export function fromBase64(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** 32-bit FNV-1a, hex-encoded (8 lowercase hex digits, zero-padded). Deterministic, no dependency. */
export function fnv1aHex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/** Strip newlines so a raw value is safe to interpolate into a single `#` comment line. */
function commentSafe(s: string): string {
  return (s || "").replace(/[\r\n]+/g, " ");
}

/** De-dupe + sort tool names. Case-sensitive (tool names are exact identifiers, unlike keywords). */
function normalizeTools(tools: string[]): string[] {
  return [...new Set((tools || []).map((t) => t.trim()).filter(Boolean))].sort();
}

/** Trim/dedupe/sort fact values. Sorted so the emitted rego is deterministic — a diff in `policies`
 *  must mean a real change, not set-iteration order. NOT lower-cased: unlike tool names, these are
 *  compared against engine-extracted values that are already normalised where it matters
 *  (`destinations.emails` is lower-cased by the extractor, `data_classes` is a closed vocabulary),
 *  and folding case here would quietly break a case-sensitive `param_paths` comparison. */
function normalizeFactValues(values: string[] | undefined): string[] {
  return [...new Set((values || []).map((v) => String(v).trim()).filter(Boolean))].sort();
}

function jsonArray(values: string[]): string {
  return `[${values.map((v) => JSON.stringify(v)).join(", ")}]`;
}

function jsonSet(values: string[]): string {
  return `{${values.map((v) => JSON.stringify(v)).join(", ")}}`;
}

// --- stats ---

const REGEX_BUILTIN = /regex\.(match|replace|find_n|find_all_string_submatch_n|split|globs_match|template_match)\s*\(/g;

/**
 * Does this clause spend the server's 25-regex-op budget?
 *
 * DERIVED FROM THE ENCODING, NEVER THE LABEL. The two are not the same question, and the gap is not
 * intuitive: `hostIn` reads like set membership and emits `regex.match` on an anchored alternation,
 * while `destinations.hosts anyOf` reads like a pattern and compiles to a free set comprehension. An
 * operator budgeting by how a clause SOUNDS gets it backwards in both directions.
 *
 * Kept beside the emitters so the two move together, and pinned by a test that compiles one graph per
 * clause kind and checks this against `computeStats().regexOps` — so a change to an emitter fails
 * here rather than quietly making the hint wrong.
 */
export function constraintCostsRegexOp(c: BuilderParamConstraint): boolean {
  return c.kind === "matches" || c.kind === "notMatches" || c.kind === "hostIn";
}

export function factCostsRegexOp(f: BuilderGrantFact): boolean {
  if (f.type === "not") return factCostsRegexOp(f.inner);
  return f.type === "scalarFact" && (f.op === "matches" || f.op === "notMatches");
}

export function computeStats(rego: string): CompileStats {
  const bytes = new TextEncoder().encode(rego).length;
  const lines = rego.split("\n").filter((l) => l.trim().length > 0).length;
  const regexOps = (rego.match(REGEX_BUILTIN) || []).length;
  return { bytes, lines, regexOps };
}

// --- the builder's own keyword-match helpers (NOT extracted from comprehensive.rego — this is the
// builder's own idiom, generalizing composerRego.ts's single global `_kw_hit` to arbitrary
// per-condition keyword sets via a parameterized function). Emitted at most once, only if the graph
// has at least one keyword condition. ---
// `bld_kw_hit_params` matches parameter NAMES as well as VALUES, at any depth.
//
// It used to scan only top-level VALUES (`input.tool_params[k]`), never the keys. So the rule an operator
// most naturally writes for this condition — "block any call carrying a parameter called password /
// api_key / secret" — silently never fired: `{"api_key": "AKIA123"}` was ALLOWED, because the term appears
// in the key and the value is an opaque token. Verified on a live cluster before the fix: param-name hits
// allowed, param-value hits blocked. The UI calls this "Keyword in tool params" and says nothing about
// which half, so there was no way to discover the limit short of testing for it.
//
// That is the dangerous direction for a security control: a MISS, not a false block. The operator believes
// the class of parameter is covered and it is not.
//
// `walk` also fixes the nesting gap the value-only form had — `{"auth": {"api_key": "x"}}` was invisible
// too — and matches how the detector templates already traverse params. Two rule bodies rather than one
// because rego partial rules OR together: first body matches any string VALUE, second matches any key
// SEGMENT of the path. `bld_kw_hit` already guards `is_string`, so non-string values and numeric array
// indices in the path are skipped rather than erroring.
const KEYWORD_HELPER_BLOCK = `bld_kw_hit(text, terms) {
    is_string(text)
    term := terms[_]
    contains(lower(text), term)
}
bld_kw_hit_tool(terms) {
    bld_kw_hit(input.tool_name, terms)
}
bld_kw_hit_params(terms) {
    walk(input.tool_params, [_, bld_kw_v])
    bld_kw_hit(bld_kw_v, terms)
}
bld_kw_hit_params(terms) {
    walk(input.tool_params, [bld_kw_path, _])
    bld_kw_hit(bld_kw_path[_], terms)
}
bld_kw_hit_both(terms) {
    bld_kw_hit_tool(terms)
}
bld_kw_hit_both(terms) {
    bld_kw_hit_params(terms)
}`;

// --- the verbatim resolver template (plan, adapted: no shell/sql shadow rule) ---
const RESOLVER_BLOCK = `block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }
decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }
rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }
reason = reasons[rule_id]`;

const DECISION_SET: Record<BuilderRule["decision"], "blocks" | "escalates" | "audits"> = {
  block: "blocks",
  escalate: "escalates",
  audit: "audits"
};

// --- scope / tier helpers (Phase 3) ----------------------------------------------------------------
//
// Three policy tiers share one graph shape (`BuilderGraph.scope` is now a discriminated union — see
// builderGraph.ts) but each compiles to a DIFFERENT rego guard, package token, and default rule_id,
// per the grounding in `norviq/api/routers/policies.py resolve_policy_key` (loader key shape) and
// `norviq/engine/evaluator.py _collect_candidates` (what's actually collected/enforced):
//   - class:     loader key `<class>`             — guard `input.agent.agent_class == "<class>"`
//   - namespace: loader key `namespace:<ns>`       — guard `input.agent.namespace == "<ns>"` (NOT
//                agent_class — the namespace-tier candidate is looked up unconditionally for every
//                call in that namespace, so an agent_class guard would just never fire)
//   - workload:  loader key `deployment:<name>`    — guard `input.agent.namespace == "<ns>"` (OPA's
//                input has no workload/deployment field at all, so this tier cannot self-guard on the
//                workload name; `<ns>` here is the TARGET namespace the caller is compiling/saving
//                into — supplied separately, since `BuilderScopeWorkload` itself carries no namespace).
// Every helper below is a pure function of `graph.scope` (+ `targetNamespace` where the tier needs it),
// so class-tier compiles are unaffected by any of this — `targetNamespace` is simply ignored.

/** The tier's own raw identifier, exactly as authored (agent class / namespace / workload name),
 *  untrimmed-caller's-responsibility (callers here always pass already-`.trim()`-ed graph state). */
export function scopeIdentifier(scope: BuilderScope): string {
  switch (scope.kind) {
    case "class":
      return scope.agentClass;
    case "namespace":
      return scope.namespace;
    case "workload":
      return scope.workloadName;
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/** Human phrase for header comments ("agent class" | "namespace" | "workload (deployment)"). */
function scopeLabel(scope: BuilderScope): string {
  switch (scope.kind) {
    case "class":
      return "agent class";
    case "namespace":
      return "namespace";
    case "workload":
      return "workload (deployment)";
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/** Phrase used inside emitted rego STRING literals (reasons) — bare identifier for class tier
 *  (unchanged, byte-for-byte back-compat with every pre-Phase-3 reason string), tier-labeled for the
 *  two new tiers so an operator reading the block reason knows which kind of scope fired. */
function scopeReasonPhrase(scope: BuilderScope): string {
  switch (scope.kind) {
    case "class":
      return scope.agentClass;
    case "namespace":
      return `namespace "${scope.namespace}"`;
    case "workload":
      return `workload "${scope.workloadName}"`;
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/** Package-name / default-rule-id token. Class tier is UNCHANGED (`sanitizeClassToken(agentClass)`,
 *  no prefix) — this is what makes an existing class-tier graph compile byte-identically to before.
 *  Namespace/workload get a distinct, collision-free, tier-prefixed token so e.g. a namespace called
 *  "foo" and a class called "foo" never share a package or a default rule_id. */
function scopeToken(scope: BuilderScope): string {
  switch (scope.kind) {
    case "class":
      return sanitizeClassToken(scope.agentClass);
    case "namespace":
      return `ns_${sanitizeClassToken(scope.namespace)}`;
    case "workload":
      return `wl_${sanitizeClassToken(scope.workloadName)}`;
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/** The single rego guard line every emitted rule/allow_intent body opens with — the one place tier
 *  dispatch actually changes the compiled LOGIC (everything else above is naming). `targetNamespace`
 *  is used ONLY for the workload tier (see this section's header comment); it's ignored for class and
 *  namespace tiers, which are fully self-contained in `scope`. */
function scopeGuardLine(scope: BuilderScope, targetNamespace: string): string {
  switch (scope.kind) {
    case "class":
      return `input.agent.agent_class == ${JSON.stringify(scope.agentClass)}`;
    case "namespace":
      return `input.agent.namespace == ${JSON.stringify(scope.namespace)}`;
    case "workload":
      return `input.agent.namespace == ${JSON.stringify(targetNamespace)}`;
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/**
 * The loader key Save must POST as `agent_class` for this scope/tier (mirrors the server's
 * `resolve_policy_key` exactly): the class tier posts the class name verbatim; namespace/workload post
 * the `namespace:<ns>` / `deployment:<name>` compound key the server's loader (and
 * `_collect_candidates`) expect. Exported for BuilderSheet's save path and its "will create" summary,
 * so the operator always sees the REAL key that gets written, not a guess.
 */
export function loaderKeyFor(scope: BuilderScope): string {
  switch (scope.kind) {
    case "class":
      return scope.agentClass.trim();
    case "namespace":
      return `namespace:${scope.namespace.trim()}`;
    case "workload":
      return `deployment:${scope.workloadName.trim()}`;
    default: {
      const _exhaustive: never = scope;
      return _exhaustive;
    }
  }
}

/**
 * Reserved-scope guard (Item A, P1 fix): the server is asymmetric — it ACCEPTS `__baseline__` /
 * `__guardrail__` etc. as an agent_class on create (200) but REFUSES to delete them (422,
 * `_RESERVED_DELETE_CLASSES`), so a class typed into the builder can be saved and then never removed
 * through the product. It's also dead on arrival: these are loader/packs-router-owned scopes that no
 * real agent's `agent_class` ever equals, so the class-shaped guard the builder would emit matches
 * nothing. Refused here at COMPILE time (not just the UI field) so a graph that bypasses the UI can
 * never reach this shape either — reuses the same `isReservedScope` predicate the rest of the console
 * already uses for the catalog's delete-guard (`lib/reservedScope.ts`), so "reserved" means the same
 * thing everywhere in this app. Also refuses a `:` in a class identifier (would collide with the
 * namespace:/deployment: loader-key scheme) and `__cluster__` as whichever field is this tier's own
 * "target namespace" (namespace tier: `scope.namespace` itself; class/workload tier: the separately
 * supplied `targetNamespace`, since those tiers' scope object carries no namespace field of its own).
 */
function validateScope(scope: BuilderScope, targetNamespace: string): BuilderError[] {
  // A graph rehydrated from the embedded base64 blob arrives through `JSON.parse` as `unknown`, so
  // neither the tier discriminant nor its identifier is guaranteed to be what the type claims. The
  // chain below used to be if/else-if with NO trailing else: an unrecognised tier produced zero errors,
  // compilation proceeded, and `scopeIdentifier`'s `never` fallback handed the scope OBJECT to
  // `commentSafe` — a TypeError thrown out of `compileGraph` rather than an error returned from it.
  const raw = scope as { kind?: unknown; agentClass?: unknown; namespace?: unknown; workloadName?: unknown } | null;
  const identifier =
    raw?.kind === "class"
      ? raw.agentClass
      : raw?.kind === "namespace"
        ? raw.namespace
        : raw?.kind === "workload"
          ? raw.workloadName
          : undefined;
  if (typeof identifier !== "string") {
    return [
      {
        code: "unknown_scope",
        message: `Unrecognised policy scope: expected tier "class", "namespace" or "workload" carrying a string identifier, got tier ${JSON.stringify(raw?.kind ?? null)}`
      }
    ];
  }
  const errors: BuilderError[] = [];
  if (scope.kind === "class") {
    const cls = scope.agentClass.trim();
    if (cls !== "" && isReservedScope(cls, null)) {
      errors.push({
        code: "reserved_scope",
        message: `"${cls}" is a reserved/managed scope owned by the loader/packs router (not a real agent class) — it can be created but the server refuses to ever delete it, and it matches no real agent's agent_class (this rule would never fire). Use the Namespace tier instead for a namespace-wide baseline.`
      });
    }
    if (cls.includes(":")) {
      errors.push({
        code: "reserved_scope",
        message: `Agent class "${cls}" cannot contain ":" — that would collide with the namespace:/deployment: loader-key scheme the Namespace/Workload tiers use. Pick the Namespace or Workload tier instead if you meant one of those.`
      });
    }
    if (targetNamespace.trim() === "__cluster__") {
      errors.push({
        code: "reserved_scope",
        message: `"__cluster__" is the reserved cluster-wide baseline namespace and cannot be used as this policy's target namespace.`
      });
    }
  } else if (scope.kind === "namespace") {
    const ns = scope.namespace.trim();
    if (ns !== "" && isReservedScope(null, ns)) {
      errors.push({
        code: "reserved_scope",
        message: `"${ns}" is the reserved cluster-wide baseline namespace and cannot be used as a policy target namespace.`
      });
    }
  } else if (scope.kind === "workload") {
    if (targetNamespace.trim() === "__cluster__") {
      errors.push({
        code: "reserved_scope",
        message: `"__cluster__" is the reserved cluster-wide baseline namespace and cannot be used as this policy's target namespace.`
      });
    }
  }
  return errors;
}

// --- validation ---

interface ConditionPos {
  ruleIndex: number;
  ruleId: string;
  rowIndex: number;
  conditionIndex: number;
}

/**
 * Validate one condition (possibly `not`-wrapped, one level deep — deeper nesting is itself the
 * `not_double_negation` error and is not recursed into further, so a doubly-negated graph reports
 * exactly that one error rather than a confusing cascade). Position (rule/row/condition index) is the
 * OUTER condition's position throughout, even when validating an inner wrapped condition, since that's
 * the position the author sees in the UI (there is no separate "inner condition index" in the graph
 * shape — a `not` wraps in place, it doesn't add a row/condition slot).
 */
function validateCondition(cond: BuilderCondition, pos: ConditionPos, errors: BuilderError[]): void {
  const { ruleIndex, ruleId, rowIndex, conditionIndex } = pos;
  if (cond.type === "keyword") {
    const kw = normalizeKeywords(cond.keywords);
    if (kw.length === 0) {
      errors.push({
        code: "empty_keyword_list",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: keyword list is empty`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "toolIn") {
    const tools = normalizeTools(cond.tools);
    if (tools.length === 0) {
      errors.push({
        code: "empty_tool_list",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: tool list is empty`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "trustBelow") {
    if (!(cond.threshold > 0 && cond.threshold <= 1)) {
      errors.push({
        code: "threshold_out_of_range",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: threshold ${cond.threshold} is out of range (0, 1]`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "sourceVerb") {
    const verbs = verbsForSource(cond.source);
    if (verbs.length === 0 || !verbs.includes(cond.verb)) {
      errors.push({
        code: "invalid_source_verb",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: source "${cond.source}" does not expose verb "${cond.verb}" in the capability mirror`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "scalarFact") {
    const known = cond.field.startsWith(PARAM_PATH_PREFIX)
      ? /^param_paths\.[\w.[\]$-]{1,256}$/.test(cond.field) // mirrors schema.py's _PARAM_PATH_RE
      : Object.prototype.hasOwnProperty.call(SCALAR_FIELD_EXPR, cond.field);
    if (!known) {
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${cond.field}" is not an addressable scalar fact (expected one of ${Object.keys(SCALAR_FIELD_EXPR).join(", ")}, or param_paths.<path>)`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
    if (cond.op === "in" && normalizeFactValues(cond.values).length === 0) {
      errors.push({
        code: "empty_fact_values",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "in" needs at least one value`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
    if (![["equals", "in", "matches", "notMatches"]].flat().includes(cond.op as string)) {
      // Without this an unrecognised operator falls through compileConditionLine's inner switch to
      // `return ""`, so the condition is emitted as a BLANK LINE inside the rule body and simply
      // vanishes — compileGraph reports zero errors and the policy silently enforces less than it says.
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${String(cond.op)}" is not a scalar operator (expected one of ${["equals", "in", "matches", "notMatches"].join(", ")})`,
        ruleIndex, rowIndex, conditionIndex
      });
    }
    if (cond.op === "matches" || cond.op === "notMatches") {
      // A BLANK pattern is a valid regex that matches EVERYTHING, so `matches ""` always fires and
      // `notMatches ""` never does — a rule that reads as a restriction and enforces the opposite of
      // what it says, or nothing at all. Rejected rather than emitted.
      if ((cond.value ?? "").trim() === "") {
        errors.push({
          code: "paramRegex_invalid",
          message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: ${cond.op} needs a pattern — an empty one matches every value`,
          ruleIndex, rowIndex, conditionIndex
        });
      }
      // Fail at AUTHOR time, exactly as paramRegex does — an unparseable pattern otherwise surfaces as
      // a 422 long after saving, with the previous policy still enforcing.
      if (!isValidRe2Pattern(cond.value ?? "")) {
        errors.push({
          code: "paramRegex_invalid",
          message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: pattern ${JSON.stringify(cond.value ?? "")} does not compile as a regular expression`,
          ruleIndex,
          rowIndex,
          conditionIndex
        });
      }
    }
  } else if (cond.type === "collectionFact") {
    if (!Object.prototype.hasOwnProperty.call(COLLECTION_FIELD_EXPR, cond.field)) {
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${cond.field}" is not an addressable collection fact`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
    if (![["subsetOf", "noneOf", "anyOf", "maxCount"]].flat().includes(cond.op as string)) {
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${String(cond.op)}" is not a collection operator (expected one of ${["subsetOf", "noneOf", "anyOf", "maxCount"].join(", ")})`,
        ruleIndex, rowIndex, conditionIndex
      });
    }
    if (cond.op === "maxCount") {
      if (!Number.isInteger(cond.count) || (cond.count ?? -1) < 0) {
        errors.push({
          code: "fact_count_invalid",
          message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: maxCount must be a non-negative integer`,
          ruleIndex,
          rowIndex,
          conditionIndex
        });
      }
    } else if (normalizeFactValues(cond.values).length === 0) {
      // An empty list would silently become a tautology (`subsetOf []` = "the collection is empty",
      // `noneOf []` = always true) — a rule that reads as a restriction and enforces nothing.
      errors.push({
        code: "empty_fact_values",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${cond.op}" needs at least one value`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "numericFact") {
    if (!Object.prototype.hasOwnProperty.call(NUMERIC_FIELD_EXPR, cond.field)) {
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${cond.field}" is not an addressable numeric fact`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
    if (![["max", "min"]].flat().includes(cond.op as string)) {
      errors.push({
        code: "unknown_fact_field",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: "${String(cond.op)}" is not a numeric operator (expected max or min)`,
        ruleIndex, rowIndex, conditionIndex
      });
    }
    if (typeof cond.value !== "number" || Number.isNaN(cond.value)) {
      errors.push({
        code: "fact_count_invalid",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: ${cond.op} needs a number`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "paramRegex") {
    if (cond.field.trim() === "") {
      errors.push({
        code: "paramRegex_invalid",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: paramRegex field is empty`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
    try {
      // The constructed RegExp is a VALIDITY PROBE and is discarded immediately — it is never executed
      // against any input here, so this is not the ReDoS vector detect-non-literal-regexp guards against.
      // The pattern's only runtime home is the emitted rego, where OPA evaluates it with RE2 (linear
      // time, no catastrophic backtracking) under the compiler's 25-regex-op budget.
      // eslint-disable-next-line no-new, security/detect-non-literal-regexp -- validity check only, discarded
      new RegExp(cond.pattern);
    } catch {
      errors.push({
        code: "paramRegex_invalid",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: pattern ${JSON.stringify(
          cond.pattern
        )} does not compile as a regular expression`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    }
  } else if (cond.type === "not") {
    // Double negation is not only `not` wrapping a `not` NODE. `compileConditionLine` prefixes `not `
    // onto whatever the inner condition emitted, and two inner forms ALREADY emit a `not `-prefixed
    // expression — `scalarFact/notMatches` and any future operator that compiles to a negation. Wrapping
    // one produced `not not regex.match(...)`, a rego parse error, with compileGraph reporting zero
    // errors: invalid rego declared valid, which is exactly the class of bug PR #96 fixed once already.
    // Checking the emitted SHAPE rather than only the node type is what makes this total.
    const innerNegates =
      cond.inner.type === "not" ||
      (cond.inner.type === "scalarFact" && cond.inner.op === "notMatches");
    if (innerNegates) {
      errors.push({
        code: "not_double_negation",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: NOT cannot wrap something already negative (${
          cond.inner.type === "not" ? "another NOT" : 'a "does not match" condition — drop the NOT and use "matches" instead'
        })`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    } else {
      validateCondition(cond.inner, pos, errors);
    }
  } else if (cond.type === "detector") {
    // Nothing to validate: `detector` is a closed union with no free-form payload, so a well-typed
    // detector condition is always valid. Listed explicitly rather than falling through, because the
    // trailing `else` below now treats anything unrecognised as an error — and silently reclassifying
    // every detector as "unknown" is exactly the regression that would cause.
  } else {
    // UNKNOWN condition type. Unreachable from this UI — but the graph is rehydrated by JSON.parsing the
    // base64 blob in the compiled rego's header comment, so at runtime a condition is whatever that blob
    // said, merely CAST to BuilderCondition. A hand-edited comment, or a policy authored by a builder
    // version that knows a condition type this one does not, lands here.
    //
    // Without this branch nothing rejects it. The emitter's `default:` arm is a TypeScript `never`
    // exhaustiveness check, which at RUNTIME returns the object itself and interpolates into the rule
    // body as the literal text `[object Object]`. compileGraph only blanks `rego` when `errors` is
    // non-empty, so the result was invalid rego reported as VALID: the operator sees a clean policy,
    // hits Save, and gets an opaque 422 from the write gate rather than a message saying what is wrong.
    // The server failing closed is not the same as the shape being unrepresentable here.
    const unknownType = (cond as { type?: unknown }).type;
    errors.push({
      code: "unknown_condition",
      message:
        `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: unrecognised ` +
        `condition type ${JSON.stringify(unknownType ?? null)}. This graph was probably written by a ` +
        `different version of the builder, or its embedded graph comment was hand-edited. Rebuild the ` +
        `rule, or use Advanced (raw rego).`,
      ruleIndex,
      rowIndex,
      conditionIndex
    });
  }
}

/** The graph's effective mode: an absent or unrecognized `mode` value (e.g. a graph object literal
 *  written before this field existed, or a corrupted/foreign blob decoded via `extractEmbeddedGraph`,
 *  which returns `unknown`) is always treated as "rules" — the pre-Phase-2c behavior — so back-compat
 *  is a property of this one function, not something every call site has to reason about separately. */
function modeOf(graph: BuilderGraph): BuilderMode {
  return graph.mode === "allowlist" ? "allowlist" : "rules";
}

/**
 * Validate an "allowlist"-mode graph's `allowlist` field. Defensive against a malformed shape (not just
 * a type mismatch TypeScript would catch) for the same reason `validateCondition`'s `not` handling is
 * defensive: a graph decoded from the embedded base64 blob comes back as `unknown` cast to `BuilderGraph`
 * (see `extractEmbeddedGraph`), so nothing at runtime guarantees `graph.allowlist` actually has the shape
 * the type declares. `invalid_allowlist` covers every structural problem (missing entirely, `tools` not
 * an array, `refinements` missing/not-an-object, a non-string tool entry); `empty_allowlist_tool` covers
 * the narrower case of a well-typed but blank (whitespace-only) individual tool string — a distinct error
 * so the UI can tell "you gave me garbage" from "you left one chip blank" for a text-input-driven tool
 * list. An OVERALL empty `tools` array (zero entries) is NOT an error — it is a valid, intentional
 * "deny everything for this class" allowlist (mirrors `generate_intent_rego`'s own support for that case);
 * only an individual blank ENTRY inside a non-empty array is rejected.
 */
function validateAllowlistGraph(graph: BuilderGraph): BuilderError[] {
  const errors: BuilderError[] = [];
  const allowlist = graph.allowlist as BuilderAllowlist | null | undefined;
  const malformed =
    !allowlist ||
    typeof allowlist !== "object" ||
    Array.isArray(allowlist) ||
    !Array.isArray(allowlist.tools) ||
    !allowlist.refinements ||
    typeof allowlist.refinements !== "object" ||
    Array.isArray(allowlist.refinements);
  if (malformed) {
    errors.push({
      code: "invalid_allowlist",
      message: 'Intent allowlist mode requires an "allowlist" object with a "tools" array and a "refinements" object'
    });
    return errors;
  }
  allowlist!.tools.forEach((raw, i) => {
    if (typeof raw !== "string") {
      errors.push({ code: "invalid_allowlist", message: `Allowlist tool at index ${i} is not a string` });
      return;
    }
    if (raw.trim() === "") {
      errors.push({ code: "empty_allowlist_tool", message: `Allowlist tool at index ${i} is empty after trim` });
    }
    // A tool name carrying a newline or control character is never legitimate, and it is not a
    // cosmetic problem: the allowlist is echoed into a HEADER COMMENT, so a `\n` terminates the
    // comment at a legal top-level position and everything after it compiles AS REGO. A name of
    // `ok\n\ndecision = "allow" { true }\n#` produced a module that opa loads, that
    // validate_rego_source ACCEPTS, and that evaluates an unlisted tool to `allow` — the default-deny
    // allowlist completely defeated.
    //
    // Reachable by an attacker, not only by a careless operator: /intents/propose derives its tool
    // names from OBSERVED TRAFFIC, so a compromised agent chooses the string that reaches this field
    // via the handoff.
    if (typeof raw === "string" && /[\u0000-\u001f\u007f]/.test(raw)) {
      errors.push({
        code: "invalid_allowlist",
        message: `Allowlist tool at index ${i} contains a control character or newline — a tool name cannot contain one, and it would break out of the generated policy's header comment`
      });
    }
  });
  errors.push(...validateGrants(allowlist!));
  return errors;
}

/** Field names are emitted as rego STRING keys (`input.tool_params["<field>"]`), never as identifiers, so
 *  the only real requirement is non-empty. Kept deliberately permissive about the character set — tool
 *  params in the wild are `snake_case`, `camelCase`, and occasionally dotted — while still rejecting the
 *  blank/whitespace case that would compile to a lookup nothing can satisfy. */
function invalidField(field: unknown): boolean {
  return typeof field !== "string" || field.trim() === "";
}

/**
 * Validate the optional per-tool `grants` (Phase 2d).
 *
 * Two rules carry real weight beyond shape-checking:
 *  - a grant whose tool is NOT on the allowlist is an ERROR, not an implicit allow. A grant NARROWS an
 *    existing permission; letting it also grant one would make the allowlist stop being the single
 *    answer to "what may this class call".
 *  - a duplicate grant for one tool is an ERROR rather than last-one-wins, because silently discarding
 *    half of an operator's constraints produces a policy that is quietly more permissive than what they
 *    wrote — the worst failure mode this feature can have.
 */
function validateGrants(allowlist: BuilderAllowlist): BuilderError[] {
  const errors: BuilderError[] = [];
  const rawGrants = (allowlist as { grants?: unknown }).grants;
  if (rawGrants === undefined || rawGrants === null) return errors; // absent is the pre-2d shape — fine
  if (!Array.isArray(rawGrants)) {
    errors.push({ code: "invalid_grant", message: 'Allowlist "grants" must be an array when present' });
    return errors;
  }
  const allowed = new Set(
    allowlist.tools.filter((t): t is string => typeof t === "string").map((t) => t.trim().toLowerCase())
  );
  const seen = new Set<string>();
  rawGrants.forEach((rawGrant, gi) => {
    if (!rawGrant || typeof rawGrant !== "object" || Array.isArray(rawGrant)) {
      errors.push({ code: "invalid_grant", message: `Grant at index ${gi} is not an object` });
      return;
    }
    const grant = rawGrant as BuilderAllowlistGrant;
    if (invalidField(grant.tool)) {
      errors.push({ code: "invalid_grant", message: `Grant at index ${gi} has no tool name` });
      return;
    }
    const tool = grant.tool.trim().toLowerCase();
    if (!allowed.has(tool)) {
      errors.push({
        code: "grant_not_allowlisted",
        message: `Grant for "${grant.tool}" constrains a tool that is not on the allowlist — add it to the allowed tools, or remove the constraints`
      });
    }
    if (seen.has(tool)) {
      errors.push({
        code: "duplicate_grant",
        message: `More than one set of constraints for "${grant.tool}" — merge them into a single entry (all constraints on a tool must hold together)`
      });
    }
    seen.add(tool);
    const grantConstraints = Array.isArray(grant.constraints) ? grant.constraints : [];
    const grantFacts = Array.isArray(grant.facts) ? grant.facts : [];
    if (grantConstraints.length === 0 && grantFacts.length === 0) {
      errors.push({
        code: "invalid_grant",
        message: `Grant for "${grant.tool}" narrows nothing — remove it, or add a constraint or a scoping fact (an empty grant would silently widen the tool back to unconstrained)`
      });
      return;
    }
    grantConstraints.forEach((c, ci) => errors.push(...validateConstraint(c, `${grant.tool}[${ci}]`)));
    // Facts are validated by the SAME function rules-mode conditions use, so a fact cannot be legal in
    // one place and illegal in the other. The synthetic position just names the grant in the message.
    grantFacts.forEach((f, fi) => {
      const factErrors: BuilderError[] = [];
      validateCondition(f as BuilderCondition, { ruleIndex: 0, ruleId: `grant:${grant.tool}`, rowIndex: 0, conditionIndex: fi }, factErrors);
      errors.push(...factErrors);
      // A grant may only NARROW an already-allowed tool. Admitting a content detector or a trust
      // threshold here would let an allowlist entry be widened by something that is not a fact about
      // the call's arguments — the opposite of what a grant is for.
      const kind = (f as BuilderCondition).type === "not" ? ((f as { inner: BuilderCondition }).inner || {}).type : (f as BuilderCondition).type;
      if (!["scalarFact", "collectionFact", "numericFact"].includes(String(kind))) {
        errors.push({
          code: "invalid_grant",
          message: `Grant for "${grant.tool}" fact ${fi}: only scoping facts (scalarFact/collectionFact/numericFact, optionally negated) may narrow a grant — "${String(kind)}" belongs in a rules-mode rule`
        });
      }
    });
  });
  return errors;
}

/**
 * Author-time validity check for a pattern that will be evaluated by OPA, i.e. by Go's RE2 — NOT by the
 * browser's regex engine.
 *
 * The difference matters in one very common case: RE2 supports INLINE FLAGS (`(?i)` for
 * case-insensitive, and `(?s)`/`(?m)`), and JavaScript's `RegExp` does not — `new RegExp("(?i)^select")`
 * throws. Validating naively with `new RegExp` therefore rejected `(?i)…` patterns that OPA accepts and
 * enforces perfectly well, and case-insensitivity is the single most common thing an operator wants when
 * matching a SQL statement or a URL. So a leading inline-flag group is translated to the equivalent JS
 * flags for the purposes of the check rather than treated as a syntax error.
 *
 * This stays a best-effort check in the other direction: RE2 is not a superset of JS regex (no
 * backreferences, no lookaround), so a pattern using those passes here and is rejected later by OPA. That
 * asymmetry is acceptable — the check exists to catch typos at author time, and the server's own rego
 * validation is the backstop — but it is the reason this is not claimed to be an exact RE2 parser.
 */
/** Constructs JavaScript's RegExp accepts that RE2 — and therefore OPA — does not.
 *
 *  This is the asymmetry that matters, and it is the DANGEROUS direction. A lookahead or backreference
 *  compiles fine under `new RegExp`, so the validity probe passed it through; OPA then does not raise
 *  an error on `regex.match` with an unsupported pattern, it makes the call UNDEFINED. In a
 *  `notMatches` constraint that becomes `not <undefined>`, which is TRUE — so the constraint is
 *  satisfied and the call is ALLOWED. Verified: a grant refusing bodies matching `(?=.*secret)`
 *  allowed a body containing "secret".
 *
 *  Deliberately a syntactic screen, not an RE2 parser: it rejects the constructs RE2 documents as
 *  unsupported. A pattern that slips past is still caught by the server's own rego validation at push
 *  time — the point here is to catch it at AUTHOR time, before it silently stops enforcing.
 */
const RE2_UNSUPPORTED: [RegExp, string][] = [
  [/\((\?=|\?!)/, "lookahead ((?= or (?!)"],
  [/\(\?<[=!]/, "lookbehind ((?<= or (?<!)"],
  [/\\[1-9]/, "backreference (\\1)"],
  [/\\k<[^>]+>/, "named backreference (\\k<name>)"],
  [/\(\?</, "named capture group ((?<name>) — RE2 uses (?P<name>)"]
];

/** The RE2 construct this pattern uses that OPA cannot evaluate, or "" if none. */
export function re2Unsupported(pattern: string): string {
  for (const [probe, label] of RE2_UNSUPPORTED) if (probe.test(pattern)) return label;
  return "";
}

function isValidRe2Pattern(pattern: string): boolean {
  if (re2Unsupported(pattern)) return false;
  const inline = /^\(\?([ims]+)\)/.exec(pattern);
  const body = inline ? pattern.slice(inline[0].length) : pattern;
  // Keep only the inline flags JS also spells the same way; `s` and `m` map directly, `i` maps directly.
  const flags = inline ? [...new Set(inline[1].split(""))].join("") : "";
  try {
    // Same VALIDITY PROBE as the paramRegex check above: the RegExp is constructed to learn whether
    // the pattern parses, then discarded without ever being executed against input — so this is not
    // the ReDoS vector detect-non-literal-regexp guards against. The pattern's only runtime home is
    // the emitted rego, where OPA evaluates it with RE2 (linear time, no backtracking).
    // eslint-disable-next-line security/detect-non-literal-regexp -- validity check only, discarded
    new RegExp(body, flags);
    return true;
  } catch {
    return false;
  }
}

/** Validate ONE parameter constraint. `pattern` is compiled with `new RegExp` here — the same
 *  fail-at-author-time guarantee `paramRegex` already gives in rules mode — so an unparseable pattern is
 *  a builder error rather than a policy that OPA rejects at push time (which surfaces as a 422 the
 *  operator sees long after saving, with the OLD rego still enforcing). */
function validateConstraint(c: unknown, where: string): BuilderError[] {
  const errors: BuilderError[] = [];
  const bad = (message: string) => errors.push({ code: "invalid_constraint", message: `${where}: ${message}` });
  if (!c || typeof c !== "object" || Array.isArray(c)) {
    bad("constraint is not an object");
    return errors;
  }
  const con = c as BuilderParamConstraint;
  if (invalidField((con as { field?: unknown }).field)) {
    bad("constraint has no parameter name");
    return errors;
  }
  switch (con.kind) {
    case "matches":
    case "notMatches": {
      if (typeof con.pattern !== "string" || con.pattern === "") {
        bad("pattern is empty");
        break;
      }
      if (!isValidRe2Pattern(con.pattern)) bad(`"${con.pattern}" is not a valid regular expression`);
      break;
    }
    case "oneOf":
    case "noneOf": {
      const values = (con as { values?: unknown }).values;
      if (!Array.isArray(values) || values.length === 0) {
        bad("needs at least one value");
        break;
      }
      if (values.some((v) => typeof v !== "string" || v.trim() === "")) bad("every value must be a non-empty string");
      break;
    }
    case "maxNumber": {
      if (typeof con.max !== "number" || !Number.isFinite(con.max)) bad("max must be a finite number");
      break;
    }
    case "hostIn": {
      const hosts = (con as { hosts?: unknown }).hosts;
      if (!Array.isArray(hosts) || hosts.length === 0) {
        bad("needs at least one host");
        break;
      }
      if (hosts.some((h) => typeof h !== "string" || h.trim() === "")) bad("every host must be a non-empty string");
      break;
    }
    case "required":
    case "forbidden":
      break;
    default:
      bad(`unknown constraint type "${String((con as { kind?: unknown }).kind)}"`);
  }
  return errors;
}

function validateRulesGraph(graph: BuilderGraph): BuilderError[] {
  const errors: BuilderError[] = [];
  const seenRuleIds = new Set<string>();
  // A user rule_id that collides with the compiler's OWN generated default rule_id
  // (`builder_default_<token>`, see buildBody below) would make `reasons[rule_id]` and the resolver's
  // rule_id selection ambiguous between the user's rule and the fallback — reject it at compile time,
  // same doctrine as duplicate_rule_id, rather than emitting rego where the two silently collide.
  // `scopeToken` is tier-aware (Phase 3): class tier is unchanged (`sanitizeClassToken(agentClass)`,
  // no prefix); namespace/workload get their own `ns_`/`wl_`-prefixed token, so e.g.
  // `builder_default_ns_default` (namespace tier) and `builder_default_wl_checkout` (workload tier).
  const defaultRuleId = `builder_default_${scopeToken(graph.scope)}`;

  graph.rules.forEach((rule, ruleIndex) => {
    if (rule.ruleId.trim() === "") {
      errors.push({ code: "empty_rule_id", message: `Rule ${ruleIndex}: rule_id is empty`, ruleIndex });
    } else if (rule.ruleId === defaultRuleId) {
      errors.push({
        code: "reserved_default_rule_id",
        message: `Rule ${ruleIndex}: rule_id "${rule.ruleId}" collides with the generated default rule_id — choose a different rule_id`,
        ruleIndex
      });
    } else if (seenRuleIds.has(rule.ruleId)) {
      errors.push({
        code: "duplicate_rule_id",
        message: `Rule ${ruleIndex}: rule_id "${rule.ruleId}" is already used by an earlier rule`,
        ruleIndex
      });
    } else {
      seenRuleIds.add(rule.ruleId);
    }

    if (rule.reason.trim() === "") {
      errors.push({ code: "empty_reason", message: `Rule ${ruleIndex}: reason is empty`, ruleIndex });
    }

    if (rule.conditions.length === 0) {
      errors.push({
        code: "empty_conditions",
        message: `Rule ${ruleIndex} ("${rule.ruleId}"): has zero condition rows`,
        ruleIndex
      });
    }

    rule.conditions.forEach((row, rowIndex) => {
      if (row.length === 0) {
        errors.push({
          code: "empty_conditions",
          message: `Rule ${ruleIndex} ("${rule.ruleId}"), row ${rowIndex}: has zero conditions`,
          ruleIndex,
          rowIndex
        });
      }
      row.forEach((cond, conditionIndex) => {
        validateCondition(cond, { ruleIndex, ruleId: rule.ruleId, rowIndex, conditionIndex }, errors);
      });
    });
  });

  return errors;
}

/** Dispatch to the mode-appropriate validator (unchanged from Phase 2c), PLUS the tier-independent
 *  `validateScope` reserved-scope check (Phase 3) that applies regardless of mode — a reserved class,
 *  a colon-bearing class, or `__cluster__` as a target namespace is rejected whether the graph is in
 *  "rules" or "allowlist" mode. "rules"-mode graphs (the default — every graph with no `mode` field,
 *  i.e. every pre-Phase-2c fixture/graph) go through the unchanged `validateRulesGraph`; "allowlist"-mode
 *  graphs are validated structurally instead, and `rules[]` is not inspected at all (it is ignored by
 *  the allowlist emitter too — see `buildFullRego`). */
function validateGraph(graph: BuilderGraph, targetNamespace: string): BuilderError[] {
  // Scope first, and short-circuit on a scope this build cannot interpret. Both mode validators derive
  // the policy's token from the scope identifier (`scopeToken` -> `sanitizeClassToken`), so running them
  // ahead of `validateScope` means THEY throw on a malformed scope before it can ever be reported.
  const scopeErrors = validateScope(graph.scope, targetNamespace);
  if (scopeErrors.some((e) => e.code === "unknown_scope")) return scopeErrors;
  const modeErrors = modeOf(graph) === "allowlist" ? validateAllowlistGraph(graph) : validateRulesGraph(graph);
  return [...scopeErrors, ...modeErrors];
}

// --- emission ---

/** The rego identifier for a sourceVerb condition's predicate — shared by the compiler (emitting the
 *  predicate block) and compileConditionLine (referencing it from a rule body). Source keys are all
 *  `[a-z0-9]+` already (capabilitySources.ts's CapabilitySourceKey union), so no sanitization is
 *  needed here the way sanitizeClassToken() is needed for free-text class names. */
function sourceVerbPredicateName(source: string, verb: string): string {
  return `bld_srcverb_${source}_${verb}`;
}

/**
 * Field -> rego expression, mirroring `norviq/engine/intent/schema.py`'s SCALAR_FIELDS /
 * COLLECTION_FIELDS / NUMERIC_FIELDS. Kept in the same order and with the same names so a divergence
 * is visible in a side-by-side diff.
 *
 * TWO DIFFERENT GUARD STYLES HERE, and the difference is load-bearing:
 *
 *  - `input.mcp.*` uses the nested `object.get(object.get(input, "mcp", {}), …, "")` form copied from
 *    schema.py. A call that never went through MCP legitimately carries no `input.mcp`, and a bare
 *    `input.mcp.server` would make the WHOLE rule body undefined rather than making one predicate
 *    false — silently deleting the rule instead of failing it. That is normal absence, not skew.
 *
 *  - The facts this merge ADDED to the engine (`param_paths`, `destinations`, `data_classes`,
 *    `sql_tables`, `param_bytes`) are referenced BARE, with no default. That is deliberate: on an
 *    engine too old to publish them the reference is undefined, the condition is false, and a
 *    rules-mode BLOCK therefore does not fire — which is FAIL-OPEN. Defaulting them to ""/[]/0 would
 *    paper over exactly that case and make the failure invisible. Instead the bare reference is paired
 *    with the capability guard emitted by `engineCapabilityGuards()`, which turns the same skew into a
 *    loud, attributable block. See NEW_FACT_ROOTS below.
 */
export const SCALAR_FIELD_EXPR: Record<string, string> = {
  verb: "input.derived.verb",
  tool_kind: "input.derived.tool_kind",
  sql_normalized: "input.derived.sql_normalized",
  direction: 'object.get(input, "direction", "call")',
  "mcp.server": 'object.get(object.get(input, "mcp", {}), "server", "")',
  "mcp.pin_status": 'object.get(object.get(input, "mcp", {}), "pin_status", "")',
  "mcp.scan_severity": 'object.get(object.get(input, "mcp", {}), "scan_severity", "")'
};

export const COLLECTION_FIELD_EXPR: Record<BuilderCollectionFactField, string> = {
  data_classes: "input.derived.data_classes",
  sql_tables: "input.derived.sql_tables",
  // Present on every engine that has `derived` at all — pre-merge facts, so no capability guard.
  sql_statements: "input.derived.sql_statements",
  param_values: "input.derived.param_values",
  "destinations.emails": 'input.derived.destinations.emails',
  "destinations.urls": 'input.derived.destinations.urls',
  "destinations.hosts": 'input.derived.destinations.hosts',
  "destinations.schemes": 'input.derived.destinations.schemes'
};

export const NUMERIC_FIELD_EXPR: Record<BuilderNumericFactField, string> = {
  param_bytes: "input.derived.param_bytes",
  call_depth: "input.call_depth",
  trust_score: "input.trust_score"
};

/** Prefix of a `param_paths.<dotted.path>` scalar field. */
export const PARAM_PATH_PREFIX = "param_paths.";

/**
 * The charset a `param_paths` suffix may use, mirroring `schema.py`'s `_PARAM_PATH_RE` (and the check in
 * `validateCondition`). Exported because the SCOPE EDITOR has to apply it when offering paths derived
 * from a tool's declared JSON Schema: the evaluator will happily build a runtime key for an argument
 * named `user email` or `x/y`, but both compilers reject the field, so offering it would produce a
 * condition that cannot be saved. Screening at offer time is the difference between "that argument
 * cannot be scoped here" and a validation error the operator has to reverse-engineer.
 */
export const PARAM_PATH_SUFFIX_RE = /^[\w.[\]$-]{1,256}$/;

/**
 * The `input.derived` roots this merge introduced. A graph referencing any of them cannot be
 * enforced by an engine that predates it — see `engineCapabilityGuards()`.
 */
const NEW_FACT_ROOTS = ["param_paths", "destinations", "data_classes", "sql_tables", "param_bytes"] as const;

/** The rego expression for a scalar field, including the dynamic `param_paths.<path>` form. */
/**
 * The derivability guard for a `param_paths.<path>` field, as a rego EXPRESSION.
 *
 * The Python intent compiler grew this in `_path_trusted_expr`; this compiler did not, and the two
 * therefore disagreed on every negated `param_paths` shape. Measured, same intent both sides:
 * `param_paths.columns notMatches "(?i)(card_number|ssn)"` against
 * `{"columns": ["card_number","ssn"]}` — Python blocked, this compiler ALLOWED, because
 * `scalarFieldExpr` defaults an absent path to `""`, the regex misses, and the negation is true.
 * The list form is not exotic: it is what `_walk_paths` produces for any array argument, and the
 * grant editor's primary picker routes a declared argument straight to a `param_paths` fact.
 *
 * Two halves, matching the Python side exactly:
 *   * the path was actually DERIVED (not defaulted to "");
 *   * the path was not MINTED by a caller key containing `.`/`[`/`]` (see `_walk_paths`).
 *
 * `param_paths_ambiguous` is read with `object.get(..., null)` and compared, NOT defaulted to `[]`:
 * defaulting it would make the anti-forgery half evaporate on an engine that predates the fact, which
 * is the same fail-open this guard exists to close. The root is also declared in `factRootsOf` so the
 * grant's availability lines require it.
 */
function paramPathGuards(field: string): string[] {
  if (!field.startsWith(PARAM_PATH_PREFIX)) return [];
  const path = JSON.stringify(field.slice(PARAM_PATH_PREFIX.length));
  return [
    // The path was actually derived — not defaulted to "" by `scalarFieldExpr`.
    `object.get(input.derived.param_paths, ${path}, null) != null`,
    // The engine publishes the ambiguity list at all. Checked explicitly rather than defaulted,
    // because `object.get(..., [])` on an older engine makes the next line vacuously true and the
    // anti-forgery half disappears — the same fail-open this guard exists to close.
    `object.get(input.derived, "param_paths_ambiguous", null) != null`,
    // ...and this path is not among the ones a caller could have minted. Inlined as a counted
    // comprehension rather than a helper rule: these expressions are emitted in both the grant and
    // the rules paths, which do not share a helper block.
    `count([1 | object.get(input.derived, "param_paths_ambiguous", [])[_] == ${path}]) == 0`
  ];
}

/**
 * Fold a predicate together with its guards into ONE boolean expression.
 *
 * A counted comprehension, because these become the value of a single line and rego has no
 * expression-level `and` — the same device `_guarded` uses on the Python side, for the same reason.
 * The clause still evaluates to false rather than becoming undefined, so a `not`-wrapper around it
 * behaves, and the near-miss explainer can still name it.
 */
function withGuards(expr: string, guards: string[]): string {
  if (guards.length === 0 || expr === "") return expr;
  return `count([1 | ${[...guards, expr].join("; ")}]) == 1`;
}
export function scalarFieldExpr(field: string): string {
  if (field.startsWith(PARAM_PATH_PREFIX)) {
    const path = field.slice(PARAM_PATH_PREFIX.length);
    // Guarded on the ROOT only: `param_paths` itself is bare (so an old engine leaves it undefined and
    // the capability guard fires), while the individual path is object.get'd because a call simply not
    // carrying that argument is ordinary, not a version problem.
    //
    // THE `""` DEFAULT IS NOT SAFE ON ITS OWN and this function must never be used alone. It reports
    // "the engine derived nothing here" with the same value it would report for an empty string, which
    // a negated comparison then reads as compliance. Every caller pairs it with `paramPathGuards()`
    // through `withGuards()` — including the `not` case in `compileConditionLine`, which has to
    // re-hoist the guards so the negation cannot invert them (see the comment there).
    return `object.get(input.derived.param_paths, ${JSON.stringify(path)}, "")`;
  }
  return SCALAR_FIELD_EXPR[field] ?? "";
}

/** Which NEW_FACT_ROOTS a single condition depends on (recursing through `not`). */
function factRootsOf(cond: BuilderCondition, out: Set<string>): void {
  if (cond.type === "not") return factRootsOf(cond.inner, out);
  if (cond.type === "scalarFact") {
    if (cond.field.startsWith(PARAM_PATH_PREFIX)) {
      out.add("param_paths");
      // Reading a path commits the rule to checking whether it was forged, so it depends on BOTH.
      out.add("param_paths_ambiguous");
    }
    return;
  }
  if (cond.type === "collectionFact") {
    if (cond.field.startsWith("destinations.")) out.add("destinations");
    else if (cond.field === "data_classes" || cond.field === "sql_tables") out.add(cond.field);
    return;
  }
  if (cond.type === "numericFact" && cond.field === "param_bytes") out.add("param_bytes");
}

/**
 * Capability guards for rules mode.
 *
 * THE PROBLEM. A tighten-only graph whose block condition reads `input.derived.data_classes` is
 * enforced by whatever engine the cluster is running. On an engine that predates these facts the
 * reference is undefined, the condition is false, and the block simply never fires — the policy reads
 * as active in the console and enforces nothing. Fail-OPEN, and silent, which is the combination that
 * actually hurts.
 *
 * WHY NOT A VERSION CHECK. `/api/v1/version` returns the package semver, which cannot answer this: a
 * dev build and a release build report the same string whether or not the engine publishes these
 * facts, and the policy may be pushed to a cluster other than the one the console is pointed at.
 *
 * WHAT THIS DOES. For each new fact root the graph actually uses, emit one body of a shared
 * `bld_unsupported_engine` block. `not input.derived.<root>` is true ONLY when the engine does not
 * publish that root at all — on a current engine the root is always defined (an empty object/array
 * when there is nothing to report, and `not {}` / `not []` is false, because in rego `not` is true
 * only for undefined or false). So this is inert everywhere except the exact skew case, where it
 * converts a silent non-enforcement into a block carrying its own explanation.
 *
 * ALLOWLIST MODE NEEDS A DIFFERENT SHAPE, not none — see `grantAvailabilityLines`. An earlier version
 * of this comment claimed allowlist mode was "fail-closed by construction" because a predicate that
 * cannot evaluate withholds an ALLOW. That is true only of predicates which PROPAGATE undefined. The
 * collection operators do not: `count([v | v := <absent>[_]; ...]) == 0` is TRUE, because a
 * comprehension over an undefined collection yields `[]` rather than becoming undefined. So a grant
 * fact meaning "allowed only if it carries no credential" silently became a no-op. The guard here is
 * the RULES-mode shape (fire a block); allowlist mode gets a conjunct that withholds the allow.
 */
function engineCapabilityGuards(graph: BuilderGraph): string {
  const roots = new Set<string>();
  graph.rules.forEach((rule) => rule.conditions.forEach((row) => row.forEach((c) => factRootsOf(c, roots))));
  if (roots.size === 0) return "";
  const bodies = [...roots].sort().map(
    (root) =>
      `# This policy scopes on input.derived.${root}, which this engine does not publish.\n` +
      `blocks["bld_unsupported_engine"] {\n    not input.derived.${root}\n}`
  );
  return bodies.join("\n\n");
}

/**
 * The BARE predicate for a scalar fact — the comparison itself, with no derivability guard folded in.
 *
 * Split out from `compileConditionLine` because the guard's PLACEMENT relative to a `not` decides
 * whether it protects anything (see the `not` case below): the caller has to be able to negate the
 * predicate and then wrap the guards around the result, which is impossible once the two are already
 * fused into one `count(...) == 1`.
 */
function scalarFactPredicate(cond: BuilderConditionScalarFact): string {
  const expr = scalarFieldExpr(cond.field);
  switch (cond.op) {
    case "equals":
      return `${expr} == ${JSON.stringify(cond.value ?? "")}`;
    case "in":
      // Set-literal membership. Free against the 25-regex-op budget, unlike a matches alternation.
      return `${jsonSet(normalizeFactValues(cond.values))}[${expr}]`;
    case "matches":
      return `regex.match(${JSON.stringify(cond.value ?? "")}, ${expr})`;
    case "notMatches":
      return `not regex.match(${JSON.stringify(cond.value ?? "")}, ${expr})`;
  }
  return "";
}

/**
 * WHAT A CLAUSE HOLDING MEANS AT THE SITE THAT EMITS IT — the only thing that decides which way a
 * `param_paths` guard must fail.
 *
 * The same condition text is compiled into two structurally opposite places:
 *
 *   "allow" — a `_grant_ok` body (allowlist mode). The body is a conjunction that must HOLD for the
 *             call to be permitted, under a default of block. A clause that cannot be answered must
 *             therefore be FALSE, so the allow is withheld.
 *   "deny"  — a `blocks[...]` / `escalates[...]` / `audits[...]` body (rules mode). The body is a
 *             conjunction that must HOLD for the call to be REFUSED, under a default of allow. A
 *             clause that cannot be answered must therefore be TRUE, so the block still fires.
 *
 * These are opposites, and no single expression satisfies both — which is exactly how a fix aimed at
 * one site silently opened a hole at the other. See the `not` case below for the measured decisions.
 */
type ClauseHolding = "allow" | "deny";

function compileConditionLine(
  cond: BuilderCondition,
  paramRegexIndices: Map<BuilderCondition, number>,
  holding: ClauseHolding
): string {
  switch (cond.type) {
    case "detector":
      return DETECTOR_PREDICATE[cond.detector];
    case "keyword": {
      const kw = normalizeKeywords(cond.keywords);
      const fn: Record<BuilderKeywordTarget, string> = {
        tool: "bld_kw_hit_tool",
        params: "bld_kw_hit_params",
        both: "bld_kw_hit_both"
      };
      return `${fn[cond.target]}(${jsonArray(kw)})`;
    }
    case "toolIn": {
      // Match the LOWER-CASED raw name OR the engine's normalized skeleton, which is what the server
      // generator compares against (threat_intent.py uses input.tool_name_normalized).
      //
      // This matched raw `input.tool_name` only, so an operator who picked the "Tool name is one of"
      // chip and listed send_email got a policy that blocked send_email and allowed Send_Email,
      // SEND_EMAIL, and the homoglyph sеnd_email — the exact bypasses tool_name_normalized exists to
      // close. The rule saved, validated and reported Active, so nothing on screen said otherwise.
      //
      // Set intersection keeps it one expression (a rule body is AND-only, and this needs OR).
      const tools = normalizeTools(cond.tools).map((t) => t.toLowerCase());
      return `count(({lower(input.tool_name), lower(input.tool_name_normalized)} & ${jsonSet(tools)})) > 0`;
    }
    case "trustBelow":
      // `input.trust_score`, NOT `input.agent.trust_score`. evaluator.py's _build_input puts
      // trust_score at the TOP LEVEL; `input.agent` holds only spiffe_id / namespace / agent_class.
      // The old path named a key no input builder ever sets, so the comparison was undefined and EVERY
      // low-trust block rule was dead — a shipped condition type that silently enforced nothing.
      // Verified against a real evaluator-shaped document: trust_score 0.1 against a 0.5 threshold
      // evaluated `allow`.
      return `input.trust_score < ${JSON.stringify(cond.threshold)}`;
    case "sourceVerb":
      return sourceVerbPredicateName(cond.source, cond.verb);
    case "paramRegex": {
      const idx = paramRegexIndices.get(cond) ?? 0;
      return `bld_paramregex_${idx}`;
    }
    case "scalarFact":
      // EVERY operator over a param_paths field, not just the negated ones. A positive operator over
      // a forged path is equally wrong — it reads the attacker's chosen value and reports compliance.
      return withGuards(scalarFactPredicate(cond), paramPathGuards(cond.field));
    case "collectionFact": {
      const expr = COLLECTION_FIELD_EXPR[cond.field];
      const values = normalizeFactValues(cond.values);
      switch (cond.op) {
        // v0 rego has no `every`, so each of these is a comprehension counted to zero/non-zero — the
        // same shape schema.py's compiler emits, for the same reason.
        case "subsetOf":
          return `count([v | v := ${expr}[_]; not ${jsonSet(values)}[v]]) == 0`;
        case "noneOf":
          return `count([v | v := ${expr}[_]; ${jsonSet(values)}[v]]) == 0`;
        case "anyOf":
          return `count([v | v := ${expr}[_]; ${jsonSet(values)}[v]]) > 0`;
        case "maxCount":
          return `count(${expr}) <= ${JSON.stringify(cond.count ?? 0)}`;
      }
      return "";
    }
    case "numericFact": {
      const expr = NUMERIC_FIELD_EXPR[cond.field];
      return cond.op === "max"
        ? `${expr} <= ${JSON.stringify(cond.value)}`
        : `${expr} >= ${JSON.stringify(cond.value)}`;
    }
    case "not": {
      // THE GUARD HAS TO SIT OUTSIDE THE NEGATION, or it becomes the bypass it exists to close.
      //
      // `withGuards` folds the guards and the predicate into one `count([1 | guards; pred]) == 1`. That
      // expression is FALSE — not undefined — whenever a guard fails, which is exactly right while it
      // stands alone: an underivable or forged path cannot satisfy the clause, so a grant withholds its
      // allow. Prefix it with `not`, however, and the same falsity INVERTS into "clause satisfied":
      // `not count([...]) == 1` is TRUE precisely when the path could not be read or was minted by the
      // caller. Measured against real opa, grant fact `NOT (param_paths.columns matches "^ssn$")` on an
      // allowlisted `read_table`: honest call allow (correct), `columns` in `param_paths_ambiguous`
      // ALLOW, `columns` never derived at all ALLOW. Both should deny — a caller who makes the path
      // unreadable satisfied the grant by making it unreadable. This is the same fail-open the four
      // scalar operators were fixed for; `not` is a legal grant-fact shape (BuilderGrantFact admits a
      // `not` wrapper around any plain fact) and it reached the same predicate by a different route.
      //
      // So for a `not`-wrapped scalar fact the guards are re-hoisted: negate the BARE predicate, then
      // wrap the guards around that. `count([1 | guards; not pred]) == 1` — false when the path is not
      // trustworthy, whichever way the operator wrote the comparison.
      //
      // ...AND ONLY WHERE A HOLDING CLAUSE MEANS "ALLOW". Hoisting is the fail-CLOSED shape for a grant
      // body and the fail-OPEN shape for a block rule, because the two sites read the same falsity in
      // opposite directions (see `ClauseHolding`). Applied unconditionally it fixed the grant bypass and
      // opened a new one in rules mode. Measured against real opa, tighten-only graph, block rule
      // `NOT (param_paths.url matches "^https://internal\\.")` — "refuse any call whose url is not
      // internal":
      //
      //     forged: `url` listed in param_paths_ambiguous   hoisted ALLOW   un-hoisted block
      //     never derived: caller sent {"url": {"href": …}}  hoisted ALLOW   un-hoisted block
      //     honest internal / honest external                allow / block   allow / block  (agree)
      //
      // The forged row is the one that matters: `param_paths_ambiguous` is populated from the CALLER's
      // own argument keys, so a caller who wants out of that block rule only has to send an argument key
      // containing `.`/`[`/`]` and the guard he tripped becomes his acquittal. Under "deny" holding the
      // guarded predicate keeps its `not` on the OUTSIDE — `not count([1 | guards; pred]) == 1` — which
      // is true whenever the path is underivable or forged, so the block fires and the untrustworthy
      // call is refused. That is the pre-existing shape; it is restored here rather than invented.
      const inner = cond.inner;
      if (holding === "allow" && inner.type === "scalarFact") {
        const guards = paramPathGuards(inner.field);
        if (guards.length > 0) return withGuards(`not ${scalarFactPredicate(inner)}`, guards);
      }
      // Every other condition type emits as a single bare rego expression (a predicate reference, a set
      // membership test, or a comparison) — prefixing it with `not ` is always a valid negation. Nesting
      // (not-of-not) is rejected at validate time (`not_double_negation`); if it slips through here
      // anyway (buildFullRego runs unconditionally, even on an invalid graph, so stats can be computed —
      // see compileGraph), the recursion just produces a syntactically-odd-but-non-crashing `not not
      // ...` line in rego that is DISCARDED because compileGraph blanks `rego` whenever errors is
      // non-empty.
      return `not ${compileConditionLine(cond.inner, paramRegexIndices, holding)}`;
    }
    default: {
      const _exhaustive: never = cond;
      return _exhaustive;
    }
  }
}

/**
 * Walk every condition in the graph, including both a `not` wrapper AND (recursively) its inner
 * condition — so a detector/keyword/sourceVerb/paramRegex used ONLY inside a `not` still gets its
 * predicate/helper block emitted (the rule body references it via `not <predicate>`, so the predicate
 * still needs to be defined). `visit` is called once per node encountered (the wrapper node itself, and
 * every inner node down the (validated-shallow, but tolerated-deep) `not` chain).
 */
function walkAllConditions(graph: BuilderGraph, visit: (cond: BuilderCondition) => void): void {
  const visitDeep = (cond: BuilderCondition): void => {
    visit(cond);
    if (cond.type === "not") visitDeep(cond.inner);
  };
  for (const rule of graph.rules) {
    for (const row of rule.conditions) {
      for (const cond of row) {
        visitDeep(cond);
      }
    }
  }
}

function collectUsedDetectors(graph: BuilderGraph): Set<BuilderDetector> {
  const used = new Set<BuilderDetector>();
  walkAllConditions(graph, (cond) => {
    if (cond.type === "detector") used.add(cond.detector);
  });
  return used;
}

function usesKeywordCondition(graph: BuilderGraph): boolean {
  let found = false;
  walkAllConditions(graph, (cond) => {
    if (cond.type === "keyword") found = true;
  });
  return found;
}

/** The distinct (source,verb) pairs the graph references (deduped — NOTs and duplicate uses collapse to
 *  one predicate block, unlike paramRegex which gets one predicate PER occurrence). Keyed as
 *  "source:verb" strings for Set dedup; the caller re-derives source/verb from listCapabilitySourceVerbPairs()'s
 *  fixed universe rather than parsing this key, so an unusual source string (containing a colon, say)
 *  can never cause a mis-parse. */
function collectUsedSourceVerbPairs(graph: BuilderGraph): Set<string> {
  const used = new Set<string>();
  walkAllConditions(graph, (cond) => {
    if (cond.type === "sourceVerb") used.add(`${cond.source}:${cond.verb}`);
  });
  return used;
}

/**
 * Every paramRegex condition in the graph, in first-encountered traversal order (rule, then row, then
 * condition, descending into `not`), each assigned a stable sequential index — `indices` maps the exact
 * condition OBJECT (by reference; safe because both this collection pass and the later rule-body-emitting
 * pass walk the SAME graph object within one compileGraph() call) to its index, and `ordered` is the same
 * conditions as a plain array for emitting the `bld_paramregex_<n>` blocks in index order. Unlike
 * sourceVerb, paramRegex predicates are NOT deduped by (field,pattern) content — every occurrence gets
 * its own numbered predicate, per the Phase 2b brief ("a stable per-condition index").
 */
function collectParamRegexIndices(graph: BuilderGraph): {
  indices: Map<BuilderCondition, number>;
  ordered: BuilderConditionParamRegex[];
} {
  const indices = new Map<BuilderCondition, number>();
  const ordered: BuilderConditionParamRegex[] = [];
  let next = 0;
  walkAllConditions(graph, (cond) => {
    if (cond.type === "paramRegex") {
      indices.set(cond, next);
      ordered.push(cond);
      next += 1;
    }
  });
  return { indices, ordered };
}

function sourceVerbBlock(source: CapabilitySourceKey, verb: CapabilityVerb): string {
  // Sorted for determinism (same graph -> byte-identical rego), independent of the mirror's own
  // declaration order in capabilitySources.ts.
  const fragments = (fragmentsFor(source, verb) ?? []).slice().sort();
  return `${sourceVerbPredicateName(source, verb)} {\n    frag := ${jsonSet(fragments)}[_]\n    contains(lower(input.tool_name), frag)\n}`;
}

/**
 * A param-regex trigger for TIGHTEN-ONLY (rules) mode — this predicate holding BLOCKS the call.
 *
 * Two bodies, because a block trigger that only inspects a top-level string is evaded by shape. The
 * original emitted `is_string(val)` and matched only that: a caller who moved the offending text into
 * an array or a nested object made the predicate false, and a false BLOCK trigger is an allow. The
 * rule read "block when `body` mentions a password" and did not block `{"body": {"content": "…
 * password …"}}`.
 *
 * The body walks the value, so any string ANYWHERE beneath the named parameter can trigger it.
 * Widening a BLOCK is always safe in the fail-closed direction — the worst case is a call refused
 * that a narrower reading would have permitted, which is the error this product prefers to make.
 *
 * WHAT THE MIRROR IMAGE ACTUALLY COVERS, because an earlier version of this comment overclaimed it
 * ("the allowlist-mode accessors are the mirror image and are fixed in `constraintExpr`") and a
 * reader took that as coverage of every allowlist-mode clause over a named argument. There are
 * THREE such clauses, not one, and they are fixed in three different places:
 *
 *   1. this predicate                  — rules mode, `paramRegex` over `input.tool_params[<arg>]`;
 *   2. `constraintExpr`                — allowlist mode, a per-field CONSTRAINT, also over
 *                                        `input.tool_params[<arg>]`; the negated kinds walk (above);
 *   3. `compileConditionLine`'s        — either mode, a `param_paths.<arg>` scalar FACT, over the
 *      `scalarFact` / `not` cases        ENGINE's flattened `input.derived.param_paths`.
 *
 * (3) does NOT walk and cannot: `param_paths` is already flattened, so `param_paths.body` names one
 * derived key and `{"body": {"content": "…"}}` derives `body.content` instead — a DIFFERENT key. It
 * is guarded rather than widened (`paramPathGuards`), which under allowlist mode's deny-by-default
 * withholds the allow. In RULES mode, where a clause holding is what fires the block, that same guard
 * makes an unreadable path fail to trigger — so a rules-mode block over `param_paths.<arg>` still does
 * not see a nested or list-shaped argument. `paramRegex` (1) is the condition type that does; the
 * builder offers both, and this is the difference between them.
 */
function paramRegexBlock(index: number, cond: BuilderConditionParamRegex): string {
  const field = JSON.stringify(cond.field);
  const pat = JSON.stringify(cond.pattern);
  return [
    `bld_paramregex_${index} {`,
    `    walk(input.tool_params[${field}], [_, leaf])`,
    `    is_string(leaf)`,
    `    regex.match(${pat}, leaf)`,
    `}`
  ].join("\n");
}

function buildBody(graph: BuilderGraph, targetNamespace: string): string {
  const scope = graph.scope;
  const token = scopeToken(scope);
  const defaultRuleId = `builder_default_${token}`;
  const guardLine = scopeGuardLine(scope, targetNamespace);

  const defaultTripleBlock = [
    `default decision = ${JSON.stringify(graph.defaults.decision)}`,
    `default rule_id = ${JSON.stringify(defaultRuleId)}`,
    `default reason = ${JSON.stringify(graph.defaults.reason)}`
  ].join("\n");

  const usedDetectors = collectUsedDetectors(graph);
  const usedHelperKeys: HelperKey[] = HELPER_ORDER.filter((key) =>
    DETECTOR_ORDER.some((d) => usedDetectors.has(d) && DETECTOR_HELPERS[d].includes(key))
  );

  const helperBlocks: string[] = usedHelperKeys.map((key) => HELPER_BLOCKS[key]);
  if (usesKeywordCondition(graph)) helperBlocks.push(KEYWORD_HELPER_BLOCK);
  const helperSection = helperBlocks.join("\n\n");

  const detectorBlocks = DETECTOR_ORDER.filter((d) => usedDetectors.has(d)).map((d) => DETECTOR_BLOCKS[d]);
  const detectorSection = detectorBlocks.join("\n\n");

  // sourceVerb predicates: canonical (source,verb) universe order (listCapabilitySourceVerbPairs, itself
  // CAPABILITY_SOURCE_ORDER x CAPABILITY_VERB_ORDER), filtered to pairs the graph actually uses — same
  // "fixed universe, filtered" doctrine as DETECTOR_ORDER/HELPER_ORDER above, so reordering rules in the
  // UI never reshuffles this section's own internal order.
  const usedSourceVerbPairs = collectUsedSourceVerbPairs(graph);
  const sourceVerbBlocks = listCapabilitySourceVerbPairs()
    .filter((p) => usedSourceVerbPairs.has(`${p.source}:${p.verb}`))
    .map((p) => sourceVerbBlock(p.source, p.verb));
  const sourceVerbSection = sourceVerbBlocks.join("\n\n");

  // paramRegex predicates: one per occurrence (not deduped), in first-encountered graph order.
  const { indices: paramRegexIndices, ordered: paramRegexOrdered } = collectParamRegexIndices(graph);
  const paramRegexBlocks = paramRegexOrdered.map((cond) => paramRegexBlock(paramRegexIndices.get(cond)!, cond));
  const paramRegexSection = paramRegexBlocks.join("\n\n");

  const ruleBlocks: string[] = [];
  graph.rules.forEach((rule) => {
    const setName = DECISION_SET[rule.decision];
    const rowBlocks = rule.conditions.map((row) => {
      const lines = [`${setName}[${JSON.stringify(rule.ruleId)}] {`, `    ${guardLine}`];
      // "deny": this body holding is what REFUSES the call, so an unanswerable clause must still fire.
      row.forEach((cond) => lines.push(`    ${compileConditionLine(cond, paramRegexIndices, "deny")}`));
      lines.push(`}`);
      return lines.join("\n");
    });
    if (rowBlocks.length > 0) ruleBlocks.push(rowBlocks.join("\n"));
  });
  // The resolver unconditionally references blocks[_]/escalates[_]/audits[_]. A partial-set name that
  // has NO defining rule anywhere in the module is an undefined identifier in rego, not an empty set —
  // OPA rejects `escalates[_]` as `rego_unsafe_var_error` if the graph has zero escalate rules (and
  // likewise for audits/blocks). So every decision set the graph does NOT use gets an explicit,
  // always-empty stub rule (`id := [][_]` iterates zero elements — safe, and never confused with the
  // server's `decision = "block" { false }` unreachable-rule reject, which only pattern-matches
  // `decision = "..."` bodies, not `blocks[id] { ... }` bodies).
  const usedDecisionSets = new Set(graph.rules.map((rule) => DECISION_SET[rule.decision]));
  // The capability guard defines `blocks[...]`, so `blocks` counts as USED even when every authored
  // rule escalates or audits — otherwise the stub below would emit a second, always-empty `blocks`
  // rule alongside it. Harmless in rego, but it makes the module read as if the guard were unreachable.
  const capabilityGuardSection = engineCapabilityGuards(graph);
  if (capabilityGuardSection) usedDecisionSets.add("blocks");
  (["blocks", "escalates", "audits"] as const)
    .filter((setName) => !usedDecisionSets.has(setName))
    .forEach((setName) => ruleBlocks.push(`${setName}[id] { id := [][_] }`));
  if (capabilityGuardSection) ruleBlocks.push(capabilityGuardSection);
  const ruleSection = ruleBlocks.join("\n\n");

  const reasonEntries = graph.rules.map((rule) => `    ${JSON.stringify(rule.ruleId)}: ${JSON.stringify(rule.reason)},`);
  reasonEntries.push(`    ${JSON.stringify(defaultRuleId)}: ${JSON.stringify(graph.defaults.reason)},`);
  // The capability guard blocks under a rule_id the `reasons` map did not contain, so
  // `reason = reasons[rule_id]` was undefined and fell through to `default reason` — the reason the
  // author wrote for the ALLOW default. A version-skew block therefore arrived in the audit log
  // explaining itself as the allow case, which is precisely the confusion the guard exists to remove:
  // the operator sees a block, reads an allow reason, and concludes the policy is broken.
  if (capabilityGuardSection) {
    reasonEntries.push(
      `    "bld_unsupported_engine": "This policy scopes on a fact this engine does not publish, so it cannot be enforced as written — blocked rather than silently allowed. Upgrade the engine, or remove the condition.",`
    );
  }
  const reasonsBlock = ["reasons = {", ...reasonEntries, "}"].join("\n");

  const sections = [
    defaultTripleBlock,
    helperSection,
    detectorSection,
    sourceVerbSection,
    paramRegexSection,
    ruleSection,
    reasonsBlock,
    RESOLVER_BLOCK
  ].filter(
    (s) => s.length > 0
  );
  return sections.join("\n\n") + "\n";
}

// --- Intent Allowlist emission (Phase 2c) --------------------------------------------------------
//
// Mirrors the server's `norviq/api/threat_intent.py generate_intent_rego` (READ-ONLY reference, never
// edited by this spike) to the shape the builder is allowed to own: package `norviq.intent.<token>` —
// the same documented namespace prefix the server's own generator uses (docs.norviq.dev/guides/writing-policies/),
// so the builder's allowlist policies are classified by the server exactly like any other intent policy
// (coverage.py's `_parse_agent_policy` → `kind="intent"` with allow_names/refinements parsed; threats.py's
// `_governing_policies` → counted as a chokepoint-governing defense). See the header comment this emits
// for the classification detail. Deliberately OMITTING the server's `learned_verbs` feature (admin-promoted verb overrides sourced from
// a server-side registry the browser has no access to — see skeleton.ts's analogous documented gap for
// the same "client mirror, not a full port" doctrine). Named-set assignments below use `=` (not the
// python generator's `:=`) to match THIS FILE's own idiom (`bld_sql_patterns = [...]` in buildBody above)
// — both are valid, semantically identical rego at the top level; this keeps every emitted set/list in
// one compiled module visually consistent regardless of which mode produced it.

const READONLY_VERBS = ["read", "get", "list", "search", "fetch", "describe", "query", "lookup", "view", "find", "scan", "count"];
const EGRESS_TOOL_NAMES = [
  "send_email", "send_sms", "send_message", "http_post", "http_request", "webhook", "post_webhook",
  "upload", "upload_file", "export", "export_data", "s3_put", "put_object", "publish", "smtp",
  "notify_external", "call_api", "fetch_url"
];

function readonlyHelperBlock(): string {
  return `read_verbs = ${jsonSet(READONLY_VERBS)}
tool_verb := split(lower(input.tool_name), "_")[0]
tool_verb_norm := split(lower(input.tool_name_normalized), "_")[0]
is_read { read_verbs[tool_verb] }
is_read { read_verbs[tool_verb_norm] }`;
}

// Kept BYTE-EQUIVALENT to the server generator's egress block (norviq/api/threat_intent.py
// generate_intent_rego). The builder used to emit only the first two lines — the pre-hardening,
// name-list-only form — so "No external egress" ticked in the Visual Policy Builder produced a policy
// that let `forward_ticket`, `slack_post_message`, `relay_case`, `dispatch_report` and
// `share_summary` straight through. The engine classifies every one of those as verb=send, and the
// server's version of the SAME toggle blocks them. Two compilers, one toggle, opposite decisions —
// and the Overview showed the identical `egress` refinement badge for both, so nothing on screen
// distinguished the policy that enforced from the one that did not.
//
// Three rules do the work beyond the literal list:
//   - derived.verb == "send" (the engine's own classification), exempted when the name LEADS with a
//     retrieval verb and no parameter names a destination — without that exemption a default-deny
//     allowlist refuses `get_mail`/`list_mail`, since the registry takes the worst verb over all
//     tokens and `mail` is a SEND token;
//   - unambiguous egress ACTION tokens matched as whole `_`-separated tokens, which is what catches
//     the vendor-named tools above;
//   - object.get for derived.verb so an engine predating the field keeps name-based behaviour.
const RETRIEVAL_LEAD_VERBS = [
  "get", "list", "read", "search", "describe", "lookup", "view", "find", "count", "download",
  "retrieve", "poll", "check", "inspect", "show", "query", "load", "browse", "preview",
];
const EGRESS_ACTION_TOKENS = [
  "send", "post", "upload", "publish", "forward", "relay", "dispatch", "share", "transmit",
  "deliver", "broadcast", "notify", "emit", "push", "webhook", "exfil", "exfiltrate", "leak",
  "smtp", "sms", "egress", "outbound",
];
const NAME_SPLIT_MAP =
  '{"A": "_a", "B": "_b", "C": "_c", "D": "_d", "E": "_e", "F": "_f", "G": "_g", "H": "_h", ' +
  '"I": "_i", "J": "_j", "K": "_k", "L": "_l", "M": "_m", "N": "_n", "O": "_o", "P": "_p", ' +
  '"Q": "_q", "R": "_r", "S": "_s", "T": "_t", "U": "_u", "V": "_v", "W": "_w", "X": "_x", ' +
  '"Y": "_y", "Z": "_z", "-": "_", ".": "_", ":": "_", "/": "_"}';

function egressHelperBlock(): string {
  return `egress_tools = ${jsonSet(EGRESS_TOOL_NAMES)}
is_egress { egress_tools[lower(input.tool_name)] }
is_egress { egress_tools[lower(input.tool_name_normalized)] }
name_split_map = ${NAME_SPLIT_MAP}
tool_name_tokens = [t | t := split(strings.replace_n(name_split_map, input.tool_name), "_")[_]; t != ""]
norm_name_tokens = [t | t := split(strings.replace_n(name_split_map, input.tool_name_normalized), "_")[_]; t != ""]
# Revokes the retrieval-lead exemption. 'to' was absent, which is the address field of every mail tool
# there is, so a retrieval-NAMED mail tool addressed by to= exfiltrated with the egress toggle ON.
destination_keys = {"destination", "recipient", "url", "endpoint", "webhook", "callback", "to", "cc", "bcc", "email", "email_address", "address", "phone", "channel", "target", "dest", "uri", "host", "remote", "peer", "chat_id", "conversation_id", "thread_id", "receiver", "send_to", "mailto"}
names_a_destination { walk(input.tool_params, [p, _]); k := p[count(p) - 1]; is_string(k); destination_keys[lower(k)] }
retrieval_lead_verbs = ${jsonSet(RETRIEVAL_LEAD_VERBS)}
is_retrieval_lead { retrieval_lead_verbs[tool_name_tokens[0]]; not names_a_destination }
is_egress { object.get(input.derived, "verb", "") == "send"; not is_retrieval_lead }
egress_action_tokens = ${jsonSet(EGRESS_ACTION_TOKENS)}
is_egress { egress_action_tokens[tool_name_tokens[_]] }
is_egress { egress_action_tokens[norm_name_tokens[_]] }`;
}

function scopeHelperBlock(): string {
  return `# in_scope: any namespace-bearing tool_params field must equal the agent's own namespace (no cross-tenant).
in_scope { not _cross_namespace }
_cross_namespace {
    some k
    ns := input.tool_params[k]
    is_string(ns)
    _looks_like_namespace_key(k)
    ns != input.agent.namespace
}
_looks_like_namespace_key(k) { lower(k) == "namespace" }
_looks_like_namespace_key(k) { lower(k) == "ns" }
_looks_like_namespace_key(k) { lower(k) == "tenant" }`;
}

function rateHelperBlock(): string {
  return `# rate_within: advisory only — a stateless policy cannot count calls/min; the real limiter is the throttle layer.
rate_within { input.call_depth <= 8 }`;
}

/** Defensive re-derivation of the allowlist's cleaned tool list — used by both the header comment and
 *  the body emitter. Tolerates a malformed `allowlist` (see `validateAllowlistGraph`'s doc comment for
 *  why: `buildFullRego` runs unconditionally, even on an invalid graph, so stats can be computed) by
 *  falling back to an empty list rather than throwing. */
function cleanAllowlistTools(allowlist: BuilderAllowlist | null | undefined): string[] {
  const rawTools = allowlist && Array.isArray(allowlist.tools) ? allowlist.tools : [];
  return rawTools.filter((t): t is string => typeof t === "string").map((t) => t.trim()).filter((t) => t !== "");
}

function cleanAllowlistRefinements(allowlist: BuilderAllowlist | null | undefined): Partial<BuilderAllowlistRefinements> {
  return allowlist && allowlist.refinements && typeof allowlist.refinements === "object" && !Array.isArray(allowlist.refinements)
    ? allowlist.refinements
    : {};
}

const REFINEMENT_ORDER: (keyof BuilderAllowlistRefinements)[] = ["readonly", "egress", "scope", "rate"];

/** Defensive re-derivation of the per-tool grants, tolerant of a malformed blob for the same reason as
 *  `cleanAllowlistTools`: `buildFullRego` runs even on an invalid graph so stats can be computed. Keeps
 *  only well-formed grants with at least one constraint, deduped by tool (first wins here — the DUPLICATE
 *  itself is already a hard validation error, so this path only matters for the stats-on-invalid-graph
 *  case), and sorted so output is deterministic. */
function cleanAllowlistGrants(allowlist: BuilderAllowlist | null | undefined): BuilderAllowlistGrant[] {
  const raw = allowlist && Array.isArray((allowlist as { grants?: unknown }).grants)
    ? ((allowlist as { grants?: unknown }).grants as unknown[])
    : [];
  const byTool = new Map<string, BuilderAllowlistGrant>();
  for (const g of raw) {
    if (!g || typeof g !== "object" || Array.isArray(g)) continue;
    const grant = g as BuilderAllowlistGrant;
    if (typeof grant.tool !== "string" || grant.tool.trim() === "") continue;
    const constraints = Array.isArray(grant.constraints) ? grant.constraints : [];
    const facts = Array.isArray(grant.facts) ? grant.facts : [];
    // A grant is well-formed if it narrows the tool SOMEHOW — by a per-field constraint, by a scoping
    // fact, or both. Requiring `constraints` specifically would silently drop a facts-only grant, and a
    // dropped narrowing is a policy that admits more than its author wrote.
    if (constraints.length === 0 && facts.length === 0) continue;
    const tool = grant.tool.trim().toLowerCase();
    if (!byTool.has(tool)) byTool.set(tool, { tool, constraints, ...(facts.length ? { facts } : {}) });
  }
  return [...byTool.values()].sort((a, b) => a.tool.localeCompare(b.tool));
}

/** Escape a literal for safe inclusion in a rego regex. Used by `hostIn`, whose hosts are operator-typed
 *  literals spliced into an alternation — an unescaped `.` there would turn `api.example.com` into a
 *  pattern matching `apiXexample.com`, i.e. a HOST ALLOWLIST THAT MATCHES HOSTS IT SHOULD NOT. */
function regexEscapeLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Compile ONE constraint to a rego expression line (indented, no trailing semicolon).
 *
 * Every variant except `forbidden` is a POSITIVE assertion over a well-typed value, so an absent or
 * wrong-typed parameter fails the constraint and the call is denied. That direction is deliberate: the
 * alternative (treat "field missing" as "constraint not applicable") would let a caller bypass every
 * constraint by simply omitting the parameter.
 */
function constraintExpr(c: BuilderParamConstraint): string {
  const f = JSON.stringify(c.field);
  switch (c.kind) {
    case "matches":
      return `    regex.match(${JSON.stringify(c.pattern)}, _p_str(${f}))`;
    case "notMatches":
      // PRESENCE, then a scan of every string BENEATH the parameter — not `_has_str` + `_p_str`.
      //
      // The bug this closes first: `_p_str` returns a never-matching sentinel for an absent or
      // wrong-typed param, which can never satisfy a POSITIVE constraint (right, by design) but under
      // `not` inverts into "constraint satisfied". Measured, `notMatches columns
      // "(?i)(card_number|ssn)"` ALLOWED `{"columns": ["card_number","ssn"]}` while blocking the
      // string `"card_number, ssn"` — and the column-list shape is the one this kind's own
      // placeholder advertises, so the vacuous case was the advertised one.
      //
      // The FIRST repair was `_has_str(f)` — require a TOP-LEVEL STRING. That closed the bypass by
      // making the clause unsatisfiable for every non-string, which is a different defect: measured
      // against real opa, `body: {"user":"alice"}`, `body: ["a","b"]` and `body: 42` all went
      // allow -> BLOCK. For any argument a tool takes as an object or a list, a `notMatches` grant
      // then denied the tool 100% of the time whatever it carried. A permanently-unsatisfiable clause
      // is not enforcement; it is an outage that reads like a policy.
      //
      // So: `_present` keeps the promise the panel makes in words ("A parameter that isn't supplied
      // fails its line"), and the walk answers the CONTENT question the operator actually asked. Any
      // scalar VALUE at any depth beneath the parameter can violate it — which is what made the array
      // and nested forms evasions in the first place — while a value carrying no scalar at all carries
      // no forbidden text either, and is allowed. This is the exact mirror of `paramRegexBlock`'s walk
      // in rules mode: the two shapes of the same question now read the payload the same way.
      //
      // WHAT THE WALK STILL DOES NOT SEE, stated because "anywhere beneath the parameter" reads like a
      // completeness claim and is not one: object KEYS. `walk` yields keys in the PATH, not the value,
      // so `{"columns": {"ssn": 1}}` does not violate `notMatches columns "(?i)ssn"` even though the
      // payload plainly names the column — measured. That is a pre-existing, product-wide reading of a
      // parameter, shared verbatim with `paramRegexBlock`'s rules-mode walk (`[_, leaf]`, `is_string`),
      // so the two modes still agree; it is NOT something this repair narrowed. It is deliberately left
      // alone rather than widened here: matching keys needs a second `regex.match` per row (breaking
      // `constraintCostsRegexOp`'s one-op-per-row promise against the server's 25-op cap) and it widens
      // a DENY on every policy already deployed. `bld_kw_hit_params` is the condition that does read
      // parameter names, at any depth, and is the answer for an operator who needs that.
      //
      // INLINE, not a shared helper rule, and that is a budget decision rather than a style one:
      // `computeStats().regexOps` counts `regex.*` occurrences in the emitted text against the
      // server's 25-op cap, and `constraintCostsRegexOp` promises the operator ONE op per `notMatches`
      // row. A helper carrying the `regex.match` would charge the policy once no matter how many rows
      // used it (under-counting the cap) while charging every grant policy that has no `notMatches` row
      // at all (regexCost.test.ts catches exactly this). Inlining keeps one emitted `regex.match` per
      // authored clause, so the hint and the cap both stay honest.
      //
      // `_leaf_text`, NOT `is_string(leaf)`. A walk that only looks at STRING leaves reopens the same
      // evasion one type-cast away: measured, `notMatches body "4[0-9]{6}"` blocked `body: "4111111"`
      // and ALLOWED `body: 4111111` — the identical digits, sent as a JSON number, became invisible to
      // a clause whose entire job is to refuse them. `_leaf_text` renders every SCALAR leaf (string,
      // number, boolean) as the text an operator would have written, so the pattern is matched against
      // what the payload actually says rather than against how it was typed. Containers and `null` yield
      // nothing: they carry no operator-authored value, and rendering them would match a pattern against
      // rego's own punctuation. Cost is unchanged — one `sprintf` where there was one `is_string`.
      return (
        `    _present(${f})\n` +
        `    count([1 | walk(input.tool_params[${f}], [_, leaf]); text := _leaf_text(leaf); ` +
        `regex.match(${JSON.stringify(c.pattern)}, text)]) == 0`
      );
    case "oneOf":
      return `    ${jsonSet(c.values.map((v) => v.trim().toLowerCase()))}[lower(_p_str(${f}))]`;
    case "noneOf":
      // Same inversion, same over-correction, same repair as `notMatches` — see above.
      // `{"table": ["payments"]}` must deny (a denied value IS carried) and `{"table": ["orders"]}`
      // must allow (none is); `_has_str` denied both.
      //
      // The type-cast evasion is sharper here than for `notMatches`, because the operator wrote the
      // denied value out by hand: measured, `noneOf account ["12345"]` blocked `account: "12345"` and
      // ALLOWED `account: 12345`. The set is keyed on text, so the leaf has to be compared as text.
      return (
        `    _present(${f})\n` +
        `    count([1 | walk(input.tool_params[${f}], [_, leaf]); text := _leaf_text(leaf); ` +
        `${jsonSet(c.values.map((v) => v.trim().toLowerCase()))}[lower(text)]]) == 0`
      );
    case "maxNumber":
      return `    _p_num(${f}) <= ${JSON.stringify(c.max)}`;
    case "required":
      return `    _present(${f})`;
    case "forbidden":
      return `    not _present(${f})`;
    case "hostIn": {
      // Anchored at the scheme and terminated at the first /?# so a lookalike host cannot be smuggled in
      // the path or query (`https://evil.com/api.internal.example.com`). An optional `//` userinfo segment
      // is NOT permitted before the host — `https://api.internal.example.com@evil.com/` must NOT pass,
      // and it doesn't, because `@` is excluded from the host character class below.
      const alt = c.hosts.map((h) => regexEscapeLiteral(h.trim().toLowerCase())).join("|");
      return `    regex.match(${JSON.stringify(`^(?i)https?://(${alt})(:[0-9]+)?([/?#]|$)`)}, lower(_p_str(${f})))`;
    }
    default:
      // Unreachable for a validated graph (validateConstraint rejects unknown kinds). Emitting a literal
      // `false` rather than nothing keeps a malformed blob FAIL-CLOSED: the tool's grant can never hold.
      return `    false`;
  }
}

/** The param-accessor helpers every constraint expression relies on. Emitted once, only when at least one
 *  grant exists, so a pre-2d graph's output is byte-identical to before.
 *
 *  `_p_str`/`_p_num` are total functions (a value when the param is present AND the right type, a
 *  never-matching sentinel otherwise) rather than partial rules, because a partial rule would make the
 *  whole enclosing body undefined on a missing param — which in a `not`-wrapped constraint like
 *  `notMatches` would flip the result to ALLOW. Returning a sentinel keeps every variant's truth value
 *  well-defined on absent input. */
function paramHelperBlock(): string {
  return `# --- per-tool parameter accessors (Phase 2d) ---
# Total, not partial: a partial rule left the enclosing body UNDEFINED on a missing param, which under a
# negated constraint (notMatches / noneOf / forbidden) would read as "constraint satisfied" and ALLOW the
# call. The sentinels below can never satisfy a positive constraint, so an absent param denies instead.
_present(f) { _ = input.tool_params[f] }
_p_str(f) = v { v := input.tool_params[f]; is_string(v) }
_p_str(f) = "\\u0000" { not _has_str(f) }
_has_str(f) { is_string(input.tool_params[f]) }
_p_num(f) = v { v := input.tool_params[f]; is_number(v) }
_p_num(f) = 1e308 { not _has_num(f) }
_has_num(f) { is_number(input.tool_params[f]) }
# NOTE: the NEGATED kinds (notMatches / noneOf) do NOT use \`_p_str\`. They ask a question about
# CONTENT, so they walk every string beneath the parameter instead — see \`constraintExpr\`. \`_p_str\`
# cannot serve them in either direction: it reports the same never-matching sentinel for "the argument
# is an object" as for "the argument is absent", which under \`not\` reads as "your constraint is
# satisfied" (the array/nested bypass), and requiring a top-level string instead made the clause
# UNSATISFIABLE for every object, list and number (a blanket denial of the tool). Both accessors below
# remain exactly right for the POSITIVE kinds they were written for.
#
# \`_leaf_text\` is what they use instead, over each node of a \`walk\`. PARTIAL on purpose — undefined for
# objects, arrays and null, so those nodes contribute no row to the enclosing comprehension. It is only
# ever read inside \`count([...]) == 0\`, where "no row" is a real, safe answer (that node carries no
# operator-authored value), so the partiality cannot leak an undefined into a body's truth value.
# It renders numbers and booleans as text because a content constraint that only inspected STRING leaves
# was evaded by re-typing: \`notMatches "4[0-9]{6}"\` blocked "4111111" and allowed 4111111, and
# \`noneOf ["12345"]\` blocked "12345" and allowed 12345.
_leaf_text(v) = v { is_string(v) }
_leaf_text(v) = sprintf("%v", [v]) { is_number(v) }
_leaf_text(v) = sprintf("%v", [v]) { is_boolean(v) }`;
}

/**
 * Emit the per-tool constraint section: a `_constrained` set naming every tool that carries constraints,
 * one `_grant_ok` body per constrained tool, and the `constraints_ok` gate the allow rule adds.
 *
 * `constraints_ok` holds when the tool is unconstrained OR its own grant body holds — so adding a grant
 * can only ever NARROW what the allowlist already permits, never widen it, and a tool nobody constrained
 * behaves exactly as it did before this feature existed.
 */

/**
 * Availability conjuncts for a grant's scoping facts — the ALLOWLIST-mode counterpart of
 * `engineCapabilityGuards`.
 *
 * The two modes need OPPOSITE shapes because they have opposite defaults. Rules mode is default-allow,
 * so skew is handled by FIRING a block. Allowlist mode is default-deny, so skew must WITHHOLD the
 * allow — and withholding does not happen on its own, which is the bug this fixes: `subsetOf`/`noneOf`
 * compile to `count([v | v := <expr>[_]; ...]) == 0`, and a comprehension over an undefined collection
 * yields `[]`, not undefined. `count([]) == 0` is TRUE, so the narrowing evaporated and the tool was
 * allowed unconstrained.
 *
 * This was not merely a version-skew hazard. `_opa_input_from_record` and the dry-run sample input in
 * api/routers/policies.py build OPA documents with NO `derived` key at all, so the product's own
 * replay path hit it on a current engine — an operator dry-running a credential-egress grant would
 * have been shown `allow` for calls that enforcement blocks.
 *
 * `object.get(input.derived, "<root>", null) != null` is a real boolean either way, so on an engine
 * that does not publish the root the grant body simply fails and the allowlist denies.
 */
function grantAvailabilityLines(facts: BuilderGrantFact[] | undefined): string[] {
  const roots = new Set<string>();
  (facts ?? []).forEach((f) => factRootsOf(f as BuilderCondition, roots));
  return [...roots]
    .sort()
    .map((root) => `    object.get(input.derived, ${JSON.stringify(root)}, null) != null`);
}

function grantsSection(grants: BuilderAllowlistGrant[]): string {
  if (grants.length === 0) return "";
  // THE GATE MUST COVER EVERY FORM `in_allowlist` CAN MATCH — which is TWO, not one:
  //
  //     in_allowlist { allow_names[lower(input.tool_name)] }          <- raw, lower-cased
  //     in_allowlist { allow_skeletons[input.tool_name_normalized] }  <- evasion-normalized
  //
  // Keying the grant gate on only ONE of them leaves the other as a hole, and it has now been wrong in
  // BOTH directions. Originally it keyed on the raw name, so a Cyrillic call name was admitted by the
  // skeleton branch and escaped its constraints. Re-keying it onto the normalized name fixed that case
  // and opened the mirror image: an operator whose own allowlist ENTRY is non-ASCII got
  // `_constrained := {"еxеcute_sql"}` (the builder's TS skeleton does not fold cross-script confusables
  // — a documented gap in ui/src/lib/skeleton.ts) while the ENGINE sends
  // `tool_name_normalized = "execute_sql"`. The raw branch admitted the call, `_constrained` missed it,
  // and `DROP TABLE orders` sailed past a grant requiring `^select`.
  //
  // So both forms of every constrained tool go into `_constrained`, the unconstrained branch requires
  // NEITHER to match, and each grant matches on either form. The two normalizations do not have to
  // agree for this to be sound — that is the point, because they demonstrably do not.
  const forms = (tool: string): string[] => [...new Set([tool.toLowerCase(), skeleton(tool)])];
  const constrained = jsonSet([...new Set(grants.flatMap((g) => forms(g.tool)))].sort());
  const bodies = grants.flatMap((g, i) => {
    const lines = g.constraints.map((c) => constraintExpr(c));
    // Availability FIRST: on an engine that cannot publish the fact the grant must fail before the
    // vacuously-true comprehension below is ever reached.
    const availability = grantAvailabilityLines(g.facts);
    // "allow": this body holding is what PERMITS the call, so an unanswerable clause must withhold it.
    const factLines = (g.facts ?? []).map((f) => `    ${compileConditionLine(f, new Map(), "allow")}`);
    const match = [
      `_grant_tool_${i} { lower(input.tool_name) == ${JSON.stringify(g.tool.toLowerCase())} }`,
      `_grant_tool_${i} { input.tool_name_normalized == ${JSON.stringify(skeleton(g.tool))} }`
    ].join("\n");
    const body = [`_grant_ok {`, `    _grant_tool_${i}`, ...availability, ...lines, ...factLines, `}`].join("\n");
    return [match, body];
  });
  return [
    paramHelperBlock(),
    "",
    `# --- per-tool constraints: a grant NARROWS an allowlisted tool, it never grants one ---`,
    `_constrained := ${constrained}`,
    // Unconstrained only if NEITHER form is constrained — a conjunction, so either form being present
    // sends the call down the `_grant_ok` path instead of past it.
    `constraints_ok { not _constrained[lower(input.tool_name)]; not _constrained[input.tool_name_normalized] }`,
    `constraints_ok { _grant_ok }`,
    "",
    bodies.join("\n\n")
  ].join("\n");
}

/** One human-readable line per constrained tool, so the scope a policy actually enforces is legible from
 *  the rego header without decoding the embedded graph. Returns [] when there are no grants — which is
 *  what keeps every pre-2d header byte-identical. */
function grantSummaryLines(allowlist: BuilderAllowlist | null | undefined): string[] {
  const grants = cleanAllowlistGrants(allowlist);
  if (grants.length === 0) return [];
  return [
    `# Per-tool scope (${grants.length} constrained tool${grants.length === 1 ? "" : "s"}) — ALL constraints must`,
    `# hold; a constrained tool is allowed ONLY for arguments matching its line below. Unlisted tools stay`,
    `# unconstrained. This is what an intent allowlist of bare tool NAMES cannot express.`,
    // Constraints AND facts, in the order `grantsSection` emits them. Rendering only `constraints` here
    // printed a bare `#   http_post:` for a facts-only grant — a header asserting a tool is constrained
    // by nothing while the rules below enforced three predicates on it. `cleanAllowlistGrants` already
    // refuses to drop a facts-only grant for exactly this reason; the prose has to keep the same promise,
    // because this comment is what a reviewer reads in the catalog and in git.
    ...grants.map((g) => {
      const scope = [...g.constraints.map(describeConstraint), ...(g.facts ?? []).map(describeFact)];
      return `#   ${commentSafe(g.tool)}: ${commentSafe(scope.join("; "))}`;
    })
  ];
}

/** Plain-English rendering of one scoping FACT for the header comment, the `describeConstraint` of the
 *  fact palette. Never parsed — the embedded graph stays the source of truth; this exists so the scope a
 *  policy enforces is legible without decoding the blob. The final fallback is unreachable for a policy
 *  that compiled: `validateAllowlistGrants` rejects any grant fact outside the three legal kinds
 *  (`invalid_grant`) before a header is ever produced.
 *
 *  EXPORTED so the builder's own scope cell renders the same words. The header comment and the UI row
 *  describe one clause; two renderings of it would drift, and an operator comparing the generated rego
 *  with the row that produced it could not tell whether they were the same restriction. */
export function describeFact(f: BuilderGrantFact): string {
  if (f.type === "not") return `NOT (${describeFact(f.inner)})`;
  switch (f.type) {
    case "scalarFact":
      switch (f.op) {
        case "equals":
          return `${f.field} == ${f.value ?? ""}`;
        case "in":
          return `${f.field} in {${(f.values ?? []).join(", ")}}`;
        case "matches":
          return `${f.field} matches /${f.value ?? ""}/`;
        case "notMatches":
          return `${f.field} does NOT match /${f.value ?? ""}/`;
      }
      break;
    case "collectionFact":
      switch (f.op) {
        case "subsetOf":
          return `${f.field} within {${(f.values ?? []).join(", ")}}`;
        case "noneOf":
          return `${f.field} excludes {${(f.values ?? []).join(", ")}}`;
        case "anyOf":
          return `${f.field} intersects {${(f.values ?? []).join(", ")}}`;
        case "maxCount":
          return `${f.field} count <= ${f.count ?? 0}`;
      }
      break;
    case "numericFact":
      return f.op === "max" ? `${f.field} <= ${f.value}` : `${f.field} >= ${f.value}`;
  }
  return "unrecognised scoping fact";
}

/** Plain-English rendering of one constraint for the header comment (never parsed — the embedded graph
 *  is the source of truth; this exists so a human reading the rego can see the intent). Exported for
 *  the same one-vocabulary reason as `describeFact`. */
export function describeConstraint(c: BuilderParamConstraint): string {
  switch (c.kind) {
    case "matches":
      return `${c.field} matches /${c.pattern}/`;
    case "notMatches":
      return `${c.field} does NOT match /${c.pattern}/`;
    case "oneOf":
      return `${c.field} in {${c.values.join(", ")}}`;
    case "noneOf":
      return `${c.field} not in {${c.values.join(", ")}}`;
    case "maxNumber":
      return `${c.field} <= ${c.max}`;
    case "required":
      return `${c.field} required`;
    case "forbidden":
      return `${c.field} must be absent`;
    case "hostIn":
      return `${c.field} host in {${c.hosts.join(", ")}}`;
    default:
      return "unrecognised constraint (fails closed)";
  }
}

/** The allowlist-mode header COMMENT lines (package + blob + hash lines are added identically by
 *  `buildFullRego` for both modes) — default-deny/tighten-only framing, the allowlist + refinements
 *  summary, the `norviq.intent.` governance-classification nuance, and the documented `learned_verbs`
 *  omission. The scope's identifier is newline-stripped via `commentSafe` before interpolation, same
 *  doctrine as the rules-mode header. Tier-aware (Phase 3) via `scopeLabel`/`scopeIdentifier`; for the
 *  class tier this reproduces the original "for agent class "<cls>"." wording byte-for-byte. */
function allowlistHeaderComment(graph: BuilderGraph, scope: BuilderScope): string[] {
  const tools = cleanAllowlistTools(graph.allowlist);
  const names = [...new Set(tools.map((t) => t.toLowerCase()))].sort();
  const refinements = cleanAllowlistRefinements(graph.allowlist);
  const enabled = REFINEMENT_ORDER.filter((k) => !!refinements[k]);
  const safeIdentifier = commentSafe(scopeIdentifier(scope));
  return [
    `# GENERATED by the Visual Policy Builder (INTENT ALLOWLIST mode) for ${scopeLabel(scope)} "${safeIdentifier}".`,
    `# DEFAULT-DENY, TIGHTEN-ONLY: a call is BLOCKED unless the tool is in the allowlist below AND every`,
    `# enabled refinement holds. The allowlist is matched evasion-normalized (lower-cased name + confusable`,
    `# skeleton, i.e. input.tool_name_normalized) so homoglyph/fullwidth/case tricks can't smuggle a`,
    `# non-intended tool past the allow.`,
    `# This policy lives at package norviq.intent.<token> — the documented namespace for intent-allowlist`,
    `# policies (docs.norviq.dev/guides/writing-policies/) — precisely so the server's own governance`,
    `# classification (coverage.py's _parse_agent_policy, threats.py's _governing_policies) recognizes it`,
    `# as an intent policy: the Overview reports kind="intent" with this allowlist's tools, and attack-path`,
    `# chokepoint governance counts it as a defense. At push time the engine isolates every policy into its`,
    `# own package (opa_client.py's managed_package/rewrite_package, norviq.managed.<key>), so this`,
    `# declared package never collides with another policy's — it is read for classification, not evaluation.`,
    `# OMITTED from this client-side generator: the server's "learned_verbs" admin-promoted verb overrides`,
    `# (registry data the browser does not have — see generate_intent_rego's learned_verbs param). A`,
    `# tool's read/egress classification below is name-heuristic only, never admin-promotion-overridden.`,
    `# Allowlist (${names.length} tool${names.length === 1 ? "" : "s"}): ${names.length ? commentSafe(names.join(", ")) : "(empty — denies every tool for this class)"}`,
    `# Refinements: ${enabled.length ? enabled.join(", ") : "(none)"}`,
    ...grantSummaryLines(graph.allowlist),
    `# Source of truth is the GRAPH, embedded below as a base64 JSON blob; this rego is regenerated`,
    `# deterministically from it and is never hand-edited (see VISUAL-POLICY-BUILDER-PLAN.md, section 2).`
  ];
}

/** Tier-aware (Phase 3): for the class tier this reproduces the original "for agent class "<cls>"."
 *  wording byte-for-byte (`scopeLabel` returns "agent class" and `scopeIdentifier` returns the bare
 *  class string for that tier) — the back-compat property the golden-snapshot test pins. */
function rulesHeaderComment(scope: BuilderScope): string[] {
  return [
    `# GENERATED by the Visual Policy Builder (graph -> rego compiler) for ${scopeLabel(scope)} "${commentSafe(scopeIdentifier(scope))}".`,
    `# Source of truth is the GRAPH, embedded below as a base64 JSON blob; this rego is regenerated`,
    `# deterministically from it and is never hand-edited (see VISUAL-POLICY-BUILDER-PLAN.md, section 2).`
  ];
}

/**
 * Emit the default-deny intent-allowlist body — see this section's header comment for what it mirrors
 * and deliberately omits. Structure (fixed, matches the Phase 2c brief exactly): default triple ->
 * allow_names/allow_skeletons sets -> in_allowlist membership -> enabled refinement helper blocks (in
 * fixed readonly/egress/scope/rate order, only the enabled ones) -> allow_intent (guards in the same
 * fixed order) -> denied -> the allow-decision triple -> the refinement-mismatch block triple.
 *
 * Tolerant of a malformed `graph.allowlist` (see `cleanAllowlistTools`/`cleanAllowlistRefinements`) for
 * the same "runs unconditionally, even on an invalid graph" reason documented on `buildFullRego`/
 * `compileGraph` — the malformed shape is what `validateAllowlistGraph` rejects; this function must not
 * throw when it runs anyway to compute stats for the (ultimately blanked) result.
 */
function buildAllowlistBody(graph: BuilderGraph, targetNamespace: string): string {
  const scope = graph.scope;
  const token = scopeToken(scope);
  const guardLine = scopeGuardLine(scope, targetNamespace);
  const reasonPhrase = scopeReasonPhrase(scope);
  const tools = cleanAllowlistTools(graph.allowlist);
  const names = [...new Set(tools.map((t) => t.toLowerCase()))].sort();
  const skels = [...new Set(tools.map((t) => skeleton(t)))].sort();
  const refinements = cleanAllowlistRefinements(graph.allowlist);

  const defaultTripleBlock = [
    `default decision = "block"`,
    `default rule_id = "intent_default_deny"`,
    `default reason = ${JSON.stringify(`Blocked: tool is not in the intended allowlist for ${reasonPhrase}`)}`
  ].join("\n");

  // `:=` (not `=`) deliberately: this mirrors the server generator's `_rego_quoted_set`
  // (norviq/api/threat_intent.py), and coverage.py's `_ALLOW_NAMES_RE` — /allow_names\s*:=\s*\{/ —
  // only parses the `:=` form. Emitting `=` compiled and enforced identically but made the Overview
  // report an intent policy with an EMPTY allow_tools list, so the operator could not see what the
  // policy actually permits. Keep both sets on `:=`.
  const allowSetsBlock = [`allow_names := ${jsonSet(names)}`, `allow_skeletons := ${jsonSet(skels)}`].join("\n");

  const membershipBlock = [
    `in_allowlist { allow_names[lower(input.tool_name)] }`,
    `in_allowlist { allow_skeletons[input.tool_name_normalized] }`
  ].join("\n");

  const helperBlockFor: Record<keyof BuilderAllowlistRefinements, () => string> = {
    readonly: readonlyHelperBlock,
    egress: egressHelperBlock,
    scope: scopeHelperBlock,
    rate: rateHelperBlock
  };
  const helperSection = REFINEMENT_ORDER.filter((k) => !!refinements[k])
    .map((k) => helperBlockFor[k]())
    .join("\n\n");

  const guardLineFor: Record<keyof BuilderAllowlistRefinements, string> = {
    readonly: "    is_read",
    egress: "    not is_egress",
    scope: "    in_scope",
    rate: "    rate_within"
  };
  // `constraints_ok` sits with the refinements as one more AND-guard on the single allow rule, so the
  // default-deny shape is untouched: still exactly one way to be allowed, now with a narrower gate.
  // Omitted entirely when there are no grants, which is what keeps pre-2d graphs byte-identical.
  const grants = cleanAllowlistGrants(graph.allowlist);
  const guardLines = [
    `    ${guardLine}`,
    `    in_allowlist`,
    ...REFINEMENT_ORDER.filter((k) => !!refinements[k]).map((k) => guardLineFor[k]),
    ...(grants.length ? [`    constraints_ok`] : [])
  ];
  const allowIntentBlock = [`allow_intent {`, ...guardLines, `}`].join("\n");
  const grantsBlock = grantsSection(grants);

  // A denied-but-allowlisted call now has TWO possible causes: a refinement, or a per-tool constraint.
  // They get distinct rule_ids so the operator sees WHICH gate rejected the call — "allowlisted but
  // blocked" with no further detail is exactly the kind of decision that gets debugged by guesswork.
  //
  // The two bodies MUST be mutually exclusive: `rule_id` is a complete rule, so two simultaneously-true
  // bodies assigning different values is a rego eval CONFLICT (which fails closed as an engine error, not
  // as a policy decision). `constraints_ok` / `not constraints_ok` partitions the space exactly.
  //
  // Emitted only when grants exist — with no grants `constraints_ok` is not defined at all, so
  // `not constraints_ok` would be vacuously TRUE and every refinement block would be misattributed.
  const blockAttribution = grants.length
    ? [
        `decision = "block" { denied; in_allowlist }`,
        `rule_id = "intent_refinement_mismatch" { denied; in_allowlist; constraints_ok }`,
        `reason = sprintf(${JSON.stringify(
          `Blocked: %s is allowlisted for ${reasonPhrase} but fails an enabled refinement (e.g. no-external-egress)`
        )}, [input.tool_name]) { denied; in_allowlist; constraints_ok }`,
        ``,
        `rule_id = "intent_constraint_violation" { denied; in_allowlist; not constraints_ok }`,
        `reason = sprintf(${JSON.stringify(
          `Blocked: %s is allowed for ${reasonPhrase}, but these arguments fall outside what it is scoped to do`
        )}, [input.tool_name]) { denied; in_allowlist; not constraints_ok }`
      ]
    : [
        `decision = "block" { denied; in_allowlist }`,
        `rule_id = "intent_refinement_mismatch" { denied; in_allowlist }`,
        `reason = sprintf(${JSON.stringify(
          `Blocked: %s is allowlisted for ${reasonPhrase} but fails an enabled refinement (e.g. no-external-egress)`
        )}, [input.tool_name]) { denied; in_allowlist }`
      ];

  const tailBlock = [
    `denied { ${guardLine}; not allow_intent }`,
    ``,
    `decision = "allow" { allow_intent }`,
    `rule_id = ${JSON.stringify(`intent_allow_${token}`)} { allow_intent }`,
    `reason = ${JSON.stringify(`Allowed: tool in the intended allowlist for ${reasonPhrase}`)} { allow_intent }`,
    ``,
    ...blockAttribution
  ].join("\n");

  const sections = [
    defaultTripleBlock,
    allowSetsBlock,
    membershipBlock,
    helperSection,
    grantsBlock,
    allowIntentBlock,
    tailBlock
  ].filter((s) => s.length > 0);
  return sections.join("\n\n") + "\n";
}

/** `targetNamespace` (Phase 3, default "") is used ONLY by the workload tier's guard (see
 *  `scopeGuardLine`) — ignored entirely for class/namespace tiers, so every pre-Phase-3 call site
 *  (and every class-tier fixture) compiles byte-identically whether or not it's supplied. */
/** Documented-namespace package prefix by mode (see the module header comment for the taxonomy
 *  reference): "rules" mode (tighten-only) emits into `norviq.custom.` — the same namespace the raw
 *  Monaco editor seeds a new policy into (`NEW_POLICY_REGO` in PolicyCatalog.tsx) — and "allowlist"
 *  mode emits into `norviq.intent.` so the server's own `norviq.intent.` classification (coverage.py's
 *  `_parse_agent_policy`, threats.py's `_governing_policies`) recognizes it as an intent policy. */
function packagePrefixFor(mode: BuilderMode): "norviq.custom." | "norviq.intent." {
  return mode === "allowlist" ? "norviq.intent." : "norviq.custom.";
}

function buildFullRego(graph: BuilderGraph, targetNamespace: string): string {
  const scope = graph.scope;
  const token = scopeToken(scope);
  const mode = modeOf(graph);
  const body = mode === "allowlist" ? buildAllowlistBody(graph, targetNamespace) : buildBody(graph, targetNamespace);
  const hash = fnv1aHex(body);
  const graphBlob = toBase64(JSON.stringify(graph));
  const descriptionLines = mode === "allowlist" ? allowlistHeaderComment(graph, scope) : rulesHeaderComment(scope);

  const header = [
    `package ${packagePrefixFor(mode)}${token}`,
    ``,
    ...descriptionLines,
    `# nrvq-builder-graph/v1: ${graphBlob}`,
    `# nrvq-builder-hash: ${hash}`,
    ``
  ].join("\n");

  return header + body;
}

/** Extract + decode the embedded graph blob from a compiled rego string. Returns null if absent/malformed. */
export function extractEmbeddedGraph(rego: string): unknown | null {
  const m = rego.match(/^# nrvq-builder-graph\/v1: (.+)$/m);
  if (!m) return null;
  try {
    return JSON.parse(fromBase64(m[1]));
  } catch {
    return null;
  }
}

/** Extract the `# nrvq-builder-hash:` value from a compiled rego string. Returns null if absent. */
export function extractBodyHash(rego: string): string | null {
  const m = rego.match(/^# nrvq-builder-hash: ([0-9a-f]{8})$/m);
  return m ? m[1] : null;
}

/**
 * Classify a rego string's relationship to its embedded builder graph:
 *  - "not-builder": no `# nrvq-builder-graph/v1:` header line at all — this rego was never produced
 *    by the builder (e.g. hand-written or composer-authored rego like comprehensive.rego).
 *  - "attached": the header IS present and the body (everything after the header block) still
 *    hashes to the embedded `# nrvq-builder-hash:` value — this rego is still exactly what the
 *    graph compiles to, so the graph remains the source of truth.
 *  - "detached": the header is present but the body's hash no longer matches — someone hand-edited
 *    the rego after it was generated, so the embedded graph blob no longer describes what's live and
 *    must not be trusted to reconstruct this policy on reopen.
 *
 * The body boundary matches buildFullRego() exactly: the body is everything after the `#
 * nrvq-builder-hash: <hex>` line (and its trailing newline), which is precisely the string
 * buildFullRego() ran fnv1aHex() over to produce that same hash.
 */
export function detachmentStatusOf(rego: string): "attached" | "detached" | "not-builder" {
  if (!/^# nrvq-builder-graph\/v1: /m.test(rego)) return "not-builder";

  const hashLine = rego.match(/^# nrvq-builder-hash: ([0-9a-f]{8})$/m);
  if (!hashLine || hashLine.index === undefined) return "detached"; // builder header present but no/malformed hash line to trust

  const bodyStart = hashLine.index + hashLine[0].length + 1; // +1 skips the single newline after the hash line
  const body = rego.slice(bodyStart);
  return fnv1aHex(body) === hashLine[1] ? "attached" : "detached";
}

/**
 * Compile a BuilderGraph into rego. Deterministic (same graph -> byte-identical output). On any
 * compile-time error (structural, reserved-scope, or budget), `rego` is the empty string and `errors`
 * is non-empty — the caller must not save/dry-run an empty-string result.
 *
 * `targetNamespace` (Phase 3, optional, default "") is the namespace this policy is being compiled to
 * be saved INTO — the same value every tier's Save path already POSTs as the `namespace` body field.
 * It is used for two things, both ignored entirely by the class tier (so every existing call site and
 * fixture — `compileGraph(graph)` with no second argument — compiles exactly as before):
 *   - the workload tier's rego guard (`input.agent.namespace == "<targetNamespace>"` — see
 *     `scopeGuardLine`'s doc comment for why the workload tier needs this supplied externally);
 *   - the `__cluster__`-as-target-namespace reserved-scope check for the class/workload tiers (the
 *     namespace tier checks its own `scope.namespace` field instead — see `validateScope`).
 */
export function compileGraph(graph: BuilderGraph, targetNamespace: string = ""): CompileResult {
  const structuralErrors = validateGraph(graph, targetNamespace);
  // Never build from a graph that failed validation. The rego is discarded below whenever there are
  // errors, so building it was always wasted work — but it is work that can THROW on a rehydrated graph
  // whose shape contradicts its types, and a throw escapes the {rego, errors} contract that every caller
  // relies on, replacing an actionable validation message with a crashed pane. Budget errors are not
  // reported alongside structural ones for the same reason: the byte count of rego built from an invalid
  // graph describes nothing the operator can act on.
  if (structuralErrors.length > 0) {
    return { rego: "", stats: computeStats(""), errors: structuralErrors };
  }
  const rego = buildFullRego(graph, targetNamespace);
  const stats = computeStats(rego);

  const budgetErrors: BuilderError[] = [];
  if (stats.bytes > BUDGET_MAX_BYTES) {
    budgetErrors.push({
      code: "budget_exceeded_bytes",
      message: `Compiled rego is ${stats.bytes} bytes, exceeding the ${BUDGET_MAX_BYTES}-byte cap`
    });
  }
  if (stats.lines > BUDGET_MAX_LINES) {
    budgetErrors.push({
      code: "budget_exceeded_lines",
      message: `Compiled rego has ${stats.lines} non-empty lines, exceeding the ${BUDGET_MAX_LINES}-line cap`
    });
  }
  if (stats.regexOps > BUDGET_MAX_REGEX_OPS) {
    budgetErrors.push({
      code: "budget_exceeded_regex_ops",
      message: `Compiled rego uses ${stats.regexOps} regex ops, exceeding the ${BUDGET_MAX_REGEX_OPS}-op cap`
    });
  }

  const errors = [...structuralErrors, ...budgetErrors];
  return { rego: errors.length > 0 ? "" : rego, stats, errors };
}
