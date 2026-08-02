// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Declared intent -> BuilderGraph, so a proposal built from RECORDED TRAFFIC can be edited in the
// visual builder instead of the Intents screen growing a second editor.
//
// The two screens keep the jobs they are actually good at. /intents does what the builder structurally
// cannot: `POST /intents/propose` derives a candidate from what the class ACTUALLY did, and
// `POST /intents/dry-run` replays recorded calls with per-rule coverage and a near-miss explainer.
// The builder does what /intents should not reimplement: authoring, editing, the embedded-graph
// provenance trail, and the gated save. This function is the seam.
//
// THE DANGEROUS DIRECTION IS SILENT LOSS. An intent predicate that has no BuilderGraph
// representation, dropped quietly, yields a policy that is MORE PERMISSIVE than the one the operator
// dry-ran and approved — while looking like the same policy. So conversion is total or it is
// reported: every predicate is either translated or named in `dropped`, and the caller is expected to
// refuse the handoff (not merely warn) when `dropped` is non-empty. There is a test for that.

import type {
  BuilderAllowlistGrant,
  BuilderConditionCollectionFact,
  BuilderConditionNumericFact,
  BuilderGrantFact,
  BuilderGraph,
  BuilderParamConstraint
} from "./builderGraph";

/** The subset of the server's intent shape this converter reads. Mirrors norviq/engine/intent/schema.py. */
export type IntentPredicateSpec = string | Record<string, unknown>;
export type IntentRuleLike = {
  id: string;
  server?: string;
  from?: string;
  match?: Record<string, IntentPredicateSpec>;
  require?: Record<string, IntentPredicateSpec>;
};
export type IntentLike = {
  name?: string;
  class?: string;
  call?: IntentRuleLike[];
  answer?: IntentRuleLike[];
  content?: IntentRuleLike[];
};

export type IntentConversion = {
  graph: BuilderGraph;
  /** Human-readable reason for every predicate that could NOT be represented. Empty = total. */
  dropped: string[];
};

const PARAM_PATH_PREFIX = "param_paths.";

/** `param_paths.query` -> `query`, but only for a TOP-LEVEL path.
 *
 *  An allowlist grant addresses `input.tool_params[field]` — one flat key. A nested path
 *  (`filters.ids[0]`) has no grant representation at all, and pretending otherwise by taking the last
 *  segment would silently point the constraint at a DIFFERENT argument. Returns null for those, which
 *  sends them to `dropped`. */
function flatFieldFor(path: string): string | null {
  const field = path.slice(PARAM_PATH_PREFIX.length);
  if (!field || field.includes(".") || field.includes("[")) return null;
  return field;
}

function asRecord(spec: IntentPredicateSpec): Record<string, unknown> {
  return typeof spec === "string" ? { equals: spec } : (spec ?? {});
}

/** Tool names a rule admits, or null when it does not scope by tool name at all. */
function toolNamesOf(rule: IntentRuleLike): string[] | null {
  const spec = { ...(rule.match ?? {}), ...(rule.require ?? {}) }["tool_name"];
  if (spec === undefined) return null;
  const ops = asRecord(spec);
  if (typeof ops.equals === "string") return [ops.equals];
  if (Array.isArray(ops.in)) return ops.in.filter((v): v is string => typeof v === "string");
  return null;
}

/** Fields a grant can now carry directly as a scoping FACT (see BuilderAllowlistGrant.facts). */
const COLLECTION_FACT_FIELDS = new Set([
  "data_classes",
  "sql_tables",
  "sql_statements",
  "param_values",
  "destinations.emails",
  "destinations.urls",
  "destinations.hosts",
  "destinations.schemes"
]);
const NUMERIC_FACT_FIELDS = new Set(["param_bytes", "call_depth", "trust_score"]);
const SCALAR_FACT_FIELDS = new Set([
  "verb",
  "tool_kind",
  "sql_normalized",
  "direction",
  "mcp.server",
  "mcp.pin_status",
  "mcp.scan_severity"
]);

/**
 * Translate one non-tool_name predicate into a grant FACT, when it is one.
 *
 * These are the predicates that could not previously cross: they are engine-derived facts about the
 * whole call ("does it carry a credential", "where is it going", "which tables") rather than about a
 * single named argument, so no per-field constraint could ever express them. A grant carries them
 * directly now, which is what closed the recorded gap.
 *
 * The intent's operator names ARE the builder's operator names — both mirror
 * norviq/engine/intent/schema.py — so this is a re-shaping, not a translation, and there is no
 * vocabulary in which the two could disagree.
 */
function factsFor(field: string, spec: IntentPredicateSpec): BuilderGrantFact[] {
  const ops = asRecord(spec);
  const out: BuilderGrantFact[] = [];
  if (COLLECTION_FACT_FIELDS.has(field)) {
    // EVERY operator, not the first. schema.py accepts several in one predicate spec
    // (`set(spec) <= COLLECTION_OPS`) and compiler.py emits all of them, so returning on the first hit
    // silently discarded the rest — while `dropped` stayed empty, which is worse than discarding them
    // loudly: the handoff refusal keys on `dropped.length`, so it could not fire, and the operator
    // saved a policy strictly more permissive than the one they dry-ran.
    (["subsetOf", "noneOf", "anyOf"] as const).forEach((op) => {
      const v = ops[op];
      if (Array.isArray(v)) {
        out.push({ type: "collectionFact", field: field as BuilderConditionCollectionFact["field"], op,
                   values: v.filter((x): x is string => typeof x === "string") });
      }
    });
    if (typeof ops.maxCount === "number") {
      out.push({ type: "collectionFact", field: field as BuilderConditionCollectionFact["field"],
                 op: "maxCount", count: ops.maxCount });
    }
    return out;
  }
  if (NUMERIC_FACT_FIELDS.has(field)) {
    (["max", "min"] as const).forEach((op) => {
      if (typeof ops[op] === "number") {
        out.push({ type: "numericFact", field: field as BuilderConditionNumericFact["field"], op,
                   value: ops[op] as number });
      }
    });
    return out;
  }
  if (SCALAR_FACT_FIELDS.has(field)) {
    if (typeof ops.equals === "string") out.push({ type: "scalarFact", field, op: "equals", value: ops.equals });
    if (Array.isArray(ops.in)) out.push({ type: "scalarFact", field, op: "in",
                                         values: ops.in.filter((x): x is string => typeof x === "string") });
    if (typeof ops.matches === "string") out.push({ type: "scalarFact", field, op: "matches", value: ops.matches });
    if (typeof ops.notMatches === "string") out.push({ type: "scalarFact", field, op: "notMatches", value: ops.notMatches });
    return out;
  }
  return out;
}

/** How many operators a predicate spec actually states — the denominator the exhaustiveness invariant
 *  needs. A bare string is shorthand for one `equals`. */
function operatorCount(spec: IntentPredicateSpec): number {
  return typeof spec === "string" ? 1 : Object.keys(spec ?? {}).length;
}

/** Translate one non-tool_name predicate into grant constraints — EVERY operator it states.
 *
 *  Returns `{ constraints, unrepresentable }`. The "every operator" fix was applied to `factsFor` and
 *  NOT here, so a predicate like `{matches: "^select ", notMatches: "drop|delete"}` kept only the
 *  `matches` and left `dropped` EMPTY — the handoff refusal keys on `dropped.length`, so it could not
 *  fire, and the operator saved a policy that had quietly lost its negative clause. Same bug, same
 *  file, other function.
 */
function constraintsFor(field: string, spec: IntentPredicateSpec): { constraints: BuilderParamConstraint[]; unrepresentable: string[] } {
  const out: BuilderParamConstraint[] = [];
  const bad: string[] = [];
  if (!field.startsWith(PARAM_PATH_PREFIX)) {
    return { constraints: out, unrepresentable: [`${field}: no allowlist-grant equivalent for this field/operator combination`] };
  }
  const flat = flatFieldFor(field);
  if (!flat) {
    return { constraints: out, unrepresentable: [`${field}: a grant addresses one flat parameter, so a nested path has no equivalent`] };
  }
  const ops = asRecord(spec);
  if (typeof ops.matches === "string") out.push({ kind: "matches", field: flat, pattern: ops.matches });
  if (typeof ops.notMatches === "string") out.push({ kind: "notMatches", field: flat, pattern: ops.notMatches });
  if (typeof ops.equals === "string") out.push({ kind: "oneOf", field: flat, values: [ops.equals] });
  if (Array.isArray(ops.in)) {
    const values = ops.in.filter((v): v is string => typeof v === "string");
    if (values.length) out.push({ kind: "oneOf", field: flat, values });
  }
  const stated = operatorCount(spec);
  if (out.length < stated) {
    bad.push(`${field}: states ${stated} operator(s), ${out.length} representable`);
  }
  return { constraints: out, unrepresentable: bad };
}

/**
 * Convert a declared intent into an allowlist-mode BuilderGraph.
 *
 * Allowlist mode, not rules mode, because an intent is default-DENY: it admits what it states and
 * denies everything else. Rendering it as tighten-only block rules would inverot its meaning.
 */
export function intentToBuilderGraph(intent: IntentLike, agentClass?: string): IntentConversion {
  const dropped: string[] = [];
  const cls = (agentClass || intent.class || "").trim();
  const tools = new Set<string>();
  const grants: BuilderAllowlistGrant[] = [];

  // Only the CALL plane maps. The answer/content planes govern what a server sends BACK, which the
  // builder has no notion of — dropping them silently would turn a two-plane intent into a one-plane
  // policy that looks complete.
  (["answer", "content"] as const).forEach((plane) => {
    const rules = intent[plane];
    if (rules && rules.length) {
      dropped.push(`${plane} plane (${rules.length} rule(s)): the builder governs the call plane only`);
    }
  });

  (intent.call ?? []).forEach((rule) => {
    const names = toolNamesOf(rule);
    if (!names || names.length === 0) {
      // A rule that admits by VERB or destination rather than tool name has no allowlist form: an
      // allowlist is keyed on names. Converting it to "allow nothing" would be wrong in the safe
      // direction but would silently discard the operator's rule, so report it.
      dropped.push(`rule ${rule.id}: does not scope by tool name, which an allowlist requires`);
      return;
    }
    names.forEach((n) => tools.add(n));

    if (rule.server || rule.from) {
      dropped.push(`rule ${rule.id}: server/from scoping has no allowlist-grant equivalent`);
    }

    const constraints: BuilderParamConstraint[] = [];
    const facts: BuilderGrantFact[] = [];
    const predicates = { ...(rule.match ?? {}), ...(rule.require ?? {}) };
    Object.entries(predicates).forEach(([field, spec]) => {
      if (field === "tool_name") return;
      // Facts first: an engine-derived fact about the whole call has a direct grant representation and
      // must not be forced through the per-field constraint path, which would either lose it or point
      // it at an argument that does not exist.
      const fs = factsFor(field, spec);
      if (fs.length) {
        facts.push(...fs);
        // Carrying SOME operators of a predicate but not all is the silent-permissive case: report any
        // the builder could not represent rather than letting them evaporate.
        const stated = operatorCount(spec);
        if (fs.length < stated) {
          dropped.push(`rule ${rule.id}: ${field} states ${stated} operator(s), ${fs.length} representable`);
        }
        return;
      }
      const { constraints: cs, unrepresentable } = constraintsFor(field, spec);
      constraints.push(...cs);
      unrepresentable.forEach((u) => dropped.push(`rule ${rule.id}: ${u}`));
    });

    if (constraints.length || facts.length) {
      names.forEach((tool) => {
        const existing = grants.find((g) => g.tool === tool);
        // One grant per tool: the compiler rejects duplicates rather than merging, because silently
        // dropping half an operator's constraints reads as "the policy is too permissive" long after
        // anyone remembers why.
        if (existing) {
          existing.constraints.push(...constraints);
          if (facts.length) existing.facts = [...(existing.facts ?? []), ...facts];
        } else {
          grants.push({ tool, constraints: [...constraints], ...(facts.length ? { facts: [...facts] } : {}) });
        }
      });
    }
  });

  const graph: BuilderGraph = {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: cls },
    mode: "allowlist",
    rules: [],
    defaults: { decision: "block", reason: "not permitted by this intent" },
    allowlist: {
      tools: [...tools].sort(),
      refinements: { readonly: false, egress: false, scope: false, rate: false },
      ...(grants.length ? { grants } : {})
    }
  };
  return { graph, dropped };
}
