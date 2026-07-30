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
  BuilderAllowlistRefinements,
  BuilderCondition,
  BuilderConditionParamRegex,
  BuilderDetector,
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
  | "reserved_scope"
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

function jsonArray(values: string[]): string {
  return `[${values.map((v) => JSON.stringify(v)).join(", ")}]`;
}

function jsonSet(values: string[]): string {
  return `{${values.map((v) => JSON.stringify(v)).join(", ")}}`;
}

// --- stats ---

const REGEX_BUILTIN = /regex\.(match|replace|find_n|find_all_string_submatch_n|split|globs_match|template_match)\s*\(/g;

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
const KEYWORD_HELPER_BLOCK = `bld_kw_hit(text, terms) {
    is_string(text)
    term := terms[_]
    contains(lower(text), term)
}
bld_kw_hit_tool(terms) {
    bld_kw_hit(input.tool_name, terms)
}
bld_kw_hit_params(terms) {
    some bld_kw_p
    is_string(input.tool_params[bld_kw_p])
    bld_kw_hit(input.tool_params[bld_kw_p], terms)
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
    if (cond.inner.type === "not") {
      errors.push({
        code: "not_double_negation",
        message: `Rule ${ruleIndex} ("${ruleId}"), row ${rowIndex}, condition ${conditionIndex}: NOT cannot wrap another NOT`,
        ruleIndex,
        rowIndex,
        conditionIndex
      });
    } else {
      validateCondition(cond.inner, pos, errors);
    }
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
  });
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
  const modeErrors = modeOf(graph) === "allowlist" ? validateAllowlistGraph(graph) : validateRulesGraph(graph);
  return [...validateScope(graph.scope, targetNamespace), ...modeErrors];
}

// --- emission ---

/** The rego identifier for a sourceVerb condition's predicate — shared by the compiler (emitting the
 *  predicate block) and compileConditionLine (referencing it from a rule body). Source keys are all
 *  `[a-z0-9]+` already (capabilitySources.ts's CapabilitySourceKey union), so no sanitization is
 *  needed here the way sanitizeClassToken() is needed for free-text class names. */
function sourceVerbPredicateName(source: string, verb: string): string {
  return `bld_srcverb_${source}_${verb}`;
}

function compileConditionLine(cond: BuilderCondition, paramRegexIndices: Map<BuilderCondition, number>): string {
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
      const tools = normalizeTools(cond.tools);
      return `${jsonSet(tools)}[input.tool_name]`;
    }
    case "trustBelow":
      return `input.agent.trust_score < ${JSON.stringify(cond.threshold)}`;
    case "sourceVerb":
      return sourceVerbPredicateName(cond.source, cond.verb);
    case "paramRegex": {
      const idx = paramRegexIndices.get(cond) ?? 0;
      return `bld_paramregex_${idx}`;
    }
    case "not":
      // Every other condition type emits as a single bare rego expression (a predicate reference, a set
      // membership test, or a comparison) — prefixing it with `not ` is always a valid negation. Nesting
      // (not-of-not) is rejected at validate time (`not_double_negation`); if it slips through here
      // anyway (buildFullRego runs unconditionally, even on an invalid graph, so stats can be computed —
      // see compileGraph), the recursion just produces a syntactically-odd-but-non-crashing `not not
      // ...` line in rego that is DISCARDED because compileGraph blanks `rego` whenever errors is
      // non-empty.
      return `not ${compileConditionLine(cond.inner, paramRegexIndices)}`;
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

function paramRegexBlock(index: number, cond: BuilderConditionParamRegex): string {
  return `bld_paramregex_${index} {\n    val := input.tool_params[${JSON.stringify(cond.field)}]\n    is_string(val)\n    regex.match(${JSON.stringify(
    cond.pattern
  )}, val)\n}`;
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
      row.forEach((cond) => lines.push(`    ${compileConditionLine(cond, paramRegexIndices)}`));
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
  (["blocks", "escalates", "audits"] as const)
    .filter((setName) => !usedDecisionSets.has(setName))
    .forEach((setName) => ruleBlocks.push(`${setName}[id] { id := [][_] }`));
  const ruleSection = ruleBlocks.join("\n\n");

  const reasonEntries = graph.rules.map((rule) => `    ${JSON.stringify(rule.ruleId)}: ${JSON.stringify(rule.reason)},`);
  reasonEntries.push(`    ${JSON.stringify(defaultRuleId)}: ${JSON.stringify(graph.defaults.reason)},`);
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
// edited by this spike) to the shape the builder is allowed to own: package `norviq.builder.<token>`
// (NOT `norviq.intent.<token>` — see the header comment this emits for the productization nuance),
// deliberately OMITTING the server's `learned_verbs` feature (admin-promoted verb overrides sourced from
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

function egressHelperBlock(): string {
  return `egress_tools = ${jsonSet(EGRESS_TOOL_NAMES)}
is_egress { egress_tools[lower(input.tool_name)] }
is_egress { egress_tools[lower(input.tool_name_normalized)] }`;
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
    `# PRODUCTIONIZATION NOTE: this policy lives at package norviq.builder.<token> — the builder's one`,
    `# policy slot for this class — NOT norviq.intent.<token>. The server-side generator this mirrors`,
    `# (norviq/api/threat_intent.py generate_intent_rego) uses the norviq.intent. package prefix for its`,
    `# own governance classification of intent policies (e.g. dashboards/audits that key off that prefix);`,
    `# that classification distinction does not apply to a builder-owned policy and is not reproduced here.`,
    `# OMITTED from this client-side generator: the server's "learned_verbs" admin-promoted verb overrides`,
    `# (registry data the browser does not have — see generate_intent_rego's learned_verbs param). A`,
    `# tool's read/egress classification below is name-heuristic only, never admin-promotion-overridden.`,
    `# Allowlist (${names.length} tool${names.length === 1 ? "" : "s"}): ${names.length ? names.join(", ") : "(empty — denies every tool for this class)"}`,
    `# Refinements: ${enabled.length ? enabled.join(", ") : "(none)"}`,
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

  const allowSetsBlock = [`allow_names = ${jsonSet(names)}`, `allow_skeletons = ${jsonSet(skels)}`].join("\n");

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
  const guardLines = [
    `    ${guardLine}`,
    `    in_allowlist`,
    ...REFINEMENT_ORDER.filter((k) => !!refinements[k]).map((k) => guardLineFor[k])
  ];
  const allowIntentBlock = [`allow_intent {`, ...guardLines, `}`].join("\n");

  const tailBlock = [
    `denied { ${guardLine}; not allow_intent }`,
    ``,
    `decision = "allow" { allow_intent }`,
    `rule_id = ${JSON.stringify(`intent_allow_${token}`)} { allow_intent }`,
    `reason = ${JSON.stringify(`Allowed: tool in the intended allowlist for ${reasonPhrase}`)} { allow_intent }`,
    ``,
    `decision = "block" { denied; in_allowlist }`,
    `rule_id = "intent_refinement_mismatch" { denied; in_allowlist }`,
    `reason = sprintf(${JSON.stringify(
      `Blocked: %s is allowlisted for ${reasonPhrase} but fails an enabled refinement (e.g. no-external-egress)`
    )}, [input.tool_name]) { denied; in_allowlist }`
  ].join("\n");

  const sections = [defaultTripleBlock, allowSetsBlock, membershipBlock, helperSection, allowIntentBlock, tailBlock].filter(
    (s) => s.length > 0
  );
  return sections.join("\n\n") + "\n";
}

/** `targetNamespace` (Phase 3, default "") is used ONLY by the workload tier's guard (see
 *  `scopeGuardLine`) — ignored entirely for class/namespace tiers, so every pre-Phase-3 call site
 *  (and every class-tier fixture) compiles byte-identically whether or not it's supplied. */
function buildFullRego(graph: BuilderGraph, targetNamespace: string): string {
  const scope = graph.scope;
  const token = scopeToken(scope);
  const mode = modeOf(graph);
  const body = mode === "allowlist" ? buildAllowlistBody(graph, targetNamespace) : buildBody(graph, targetNamespace);
  const hash = fnv1aHex(body);
  const graphBlob = toBase64(JSON.stringify(graph));
  const descriptionLines = mode === "allowlist" ? allowlistHeaderComment(graph, scope) : rulesHeaderComment(scope);

  const header = [
    `package norviq.builder.${token}`,
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
