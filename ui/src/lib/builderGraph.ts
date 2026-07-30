// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Visual Policy Builder — Phase 2 spike (round A, extended round Phase 2b). Graph document types.
// See specs/prompts/VISUAL-POLICY-BUILDER-PLAN.md for the full design. MVP scope: class-tier scope, 5
// built-in detectors, keyword/tool/trust conditions, plus (Phase 2b) a registry-backed source+verb
// condition, a param-regex condition, and a NOT wrapper. No free-form rego in any node — every field
// here is enum/string/number/string[]/nested-condition, so a compiled graph can never inject rego
// (builderCompile.ts JSON.stringify-escapes every literal, the composerRego.ts idiom; paramRegex's
// `pattern` is only ever passed through JSON.stringify into a rego STRING argument to `regex.match`,
// never spliced into rego syntax).
//
// Rule shape is OR-of-AND: `conditions` is an array of ROWS (OR between rows), each row an array of
// CONDITIONS (AND within a row) — exactly how comprehensive.rego expresses OR today (multiple
// `blocks["same_id"] { ... }` bodies sharing one rule_id). Every rule must have at least one row with
// at least one condition; the compiler rejects anything less (see builderCompile.ts).

import type { CapabilityVerb } from "./capabilitySources";

/** The 5 MVP built-in detectors, extracted (as self-contained templates) from comprehensive.rego. */
export type BuilderDetector = "sql_injection" | "shell_injection" | "prompt_injection" | "pii" | "destructive_tool";

/** Where a keyword condition looks for a match. */
export type BuilderKeywordTarget = "tool" | "params" | "both";

export interface BuilderConditionDetector {
  type: "detector";
  detector: BuilderDetector;
}

export interface BuilderConditionKeyword {
  type: "keyword";
  keywords: string[];
  target: BuilderKeywordTarget;
}

export interface BuilderConditionToolIn {
  type: "toolIn";
  tools: string[];
}

export interface BuilderConditionTrustBelow {
  type: "trustBelow";
  /** 0 < threshold <= 1 */
  threshold: number;
}

/**
 * Registry-backed source+verb condition (Phase 2b). `source` is a CapabilitySourceKey from
 * capabilitySources.ts (the compile-time mirror of the Python capability registry) — kept as a plain
 * `string` here (not the narrower union) so an unknown/stale source loaded from an old graph blob is a
 * normal compile-time validation error (`invalid_source_verb`) rather than a TypeScript type failure at
 * load time. `verb` is the closed CapabilityVerb union — see capabilitySources.ts.
 */
export interface BuilderConditionSourceVerb {
  type: "sourceVerb";
  source: string;
  verb: CapabilityVerb;
}

/**
 * A single string-parameter regex match (Phase 2b): `input.tool_params[field]` matched against
 * `pattern` via rego's `regex.match`. `pattern` is validated at compile time via `new RegExp(pattern)`
 * (browser regex syntax) before being JSON.stringify-escaped into the rego string literal — it is never
 * possible for `pattern` to inject rego syntax, only to fail validation as not-a-valid-pattern.
 */
export interface BuilderConditionParamRegex {
  type: "paramRegex";
  field: string;
  pattern: string;
}

/**
 * Negates exactly one non-`not` condition (Phase 2b). `inner` is typed as the full `BuilderCondition`
 * union (NOT `Exclude<BuilderCondition, BuilderConditionNot>`) deliberately: a graph loaded from the
 * embedded base64 blob comes back through `JSON.parse` as `unknown` (see builderCompile.ts's
 * `extractEmbeddedGraph`), so nothing statically prevents a `not` wrapping a `not` at runtime — that
 * shape must be caught by builderCompile.ts's `validateCondition` (`not_double_negation`), which needs
 * `cond.inner.type === "not"` to be a legal, narrowable comparison. A type-level `Exclude` here would
 * make TypeScript treat that runtime check as unreachable and refuse to compile it — the invariant
 * ("wraps exactly one non-`not` condition") is enforced at compile time by the validator, not by this
 * field's type.
 */
export interface BuilderConditionNot {
  type: "not";
  inner: BuilderCondition;
}

export type BuilderCondition =
  | BuilderConditionDetector
  | BuilderConditionKeyword
  | BuilderConditionToolIn
  | BuilderConditionTrustBelow
  | BuilderConditionSourceVerb
  | BuilderConditionParamRegex
  | BuilderConditionNot;

export type BuilderDecision = "block" | "escalate" | "audit";

export interface BuilderRule {
  id: string;
  decision: BuilderDecision;
  /** Slug used as the rego partial-set key (`blocks["<ruleId>"]` etc.) and in the reasons map. */
  ruleId: string;
  reason: string;
  /** OR-of-AND: outer array = OR rows, inner array = AND within a row. */
  conditions: BuilderCondition[][];
}

/** Agent-class tier (the original, MVP scope): the loader key POSTed to the server is the class name
 *  verbatim (`agent_class = "<class>"`) and the compiled rego guards on `input.agent.agent_class`. */
export interface BuilderScopeClass {
  kind: "class";
  agentClass: string;
}

/**
 * Namespace tier (Phase 3): applies to EVERY call in the namespace, not just one class — the server's
 * `_collect_candidates` always looks up `f"{namespace}:namespace:{namespace}"` regardless of the
 * caller's own `agent_class`, so the compiled rego must NOT guard on `agent_class` (it would never
 * fire); it guards on `input.agent.namespace` instead (defense-in-depth — the loader key already scopes
 * lookup to this namespace, but the rego makes that scoping explicit too). The loader key POSTed is
 * `agent_class = "namespace:<namespace>"` (see `resolve_policy_key`/builderCompile.ts's `loaderKeyFor`).
 */
export interface BuilderScopeNamespace {
  kind: "namespace";
  namespace: string;
}

/**
 * Workload tier (Phase 3): scoped to one Deployment (deployment kind ONLY — `_collect_candidates` only
 * ever looks up `deployment:<name>`; any other kind `resolve_policy_key` would happily mint, e.g.
 * `statefulset:foo`, is created but SILENTLY NEVER ENFORCED, so this type intentionally has no `kind`
 * field of its own — it is always a deployment). The OPA input has no workload/deployment field at all
 * (`input.agent` is only `{spiffe_id, namespace, agent_class}`), so a workload policy cannot self-guard
 * on the workload name — scoping is purely by loader key (`agent_class = "deployment:<workloadName>"`);
 * the compiled rego's only guard is `input.agent.namespace == "<the target namespace>"` (the target
 * namespace is not part of this scope object — it's supplied to the compiler separately, since it's the
 * same "where does this policy live" value the caller already tracks for every tier's POST).
 */
export interface BuilderScopeWorkload {
  kind: "workload";
  workloadName: string;
}

/** Discriminated union of the three policy tiers (Phase 3). Back-compat is critical: an existing graph
 *  with `kind: "class"` (every graph saved before Phase 3) must keep compiling byte-identically —
 *  `BuilderScopeClass`'s shape is unchanged from the original single-member `BuilderScope`. */
export type BuilderScope = BuilderScopeClass | BuilderScopeNamespace | BuilderScopeWorkload;

export interface BuilderDefaults {
  decision: "allow" | "block";
  reason: string;
}

/**
 * Phase 2c: a graph's MODE. "rules" (the default) is the existing tighten-only OR-of-AND rule rail,
 * unchanged. "allowlist" is a whole different POLICY SHAPE — default-deny, allow only the listed tools
 * — which cannot compose with `rules[]` in one class policy (see builderCompile.ts's `buildFullRego`
 * branch), so it lives as a sibling mode rather than another condition type. Optional and
 * defaulting-to-"rules" is deliberate: every graph object literal in this codebase (existing fixtures,
 * PolicyCatalog.test.tsx's mutatedBuilderRego, every builderCompile.test.ts graph) was written before
 * this field existed and has no `mode` key at all — treating an absent/unrecognized value as "rules"
 * (see builderCompile.ts's `modeOf`) means none of that has to change for this to compile identically.
 */
export type BuilderMode = "rules" | "allowlist";

/** The four coarse refinement toggles an intent allowlist can enable (Phase 2c) — mirrors the server's
 *  `threat_intent.py` `Intent` dataclass's four toggles (readonly/scope/rate/egress), renamed here to
 *  match the compiled rego's own predicate names (readonly->is_read, egress->is_egress, etc). */
export interface BuilderAllowlistRefinements {
  readonly: boolean;
  egress: boolean;
  scope: boolean;
  rate: boolean;
}

/**
 * An intent allowlist (Phase 2c): only `tools` may be called for the class, and only when every
 * enabled refinement in `refinements` also holds — everything else (every non-listed tool, and any
 * listed tool that fails an enabled refinement) is blocked. `tools` MAY be empty — that is a valid,
 * intentional "deny everything for this class" allowlist (mirrors `generate_intent_rego`'s own support
 * for an empty allowlist); the UI surfaces a warning for that case but the compiler does not reject it.
 * Tool names are normalized (trimmed, lower-cased, deduped, sorted) at compile time, not here — this
 * type carries the author's raw, as-typed strings.
 */
export interface BuilderAllowlist {
  tools: string[];
  refinements: BuilderAllowlistRefinements;
}

export interface BuilderGraph {
  schemaVersion: 1;
  scope: BuilderScope;
  /** Optional, default "rules" — see `BuilderMode`'s doc comment for why this must stay optional. */
  mode?: BuilderMode;
  rules: BuilderRule[];
  defaults: BuilderDefaults;
  /** Present (and meaningful) only when `mode === "allowlist"`; ignored by the compiler otherwise, and
   *  the UI leaves it undefined while in "rules" mode rather than carrying stale allowlist state along. */
  allowlist?: BuilderAllowlist;
}
