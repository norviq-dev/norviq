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

import type { BuilderAllowlistGrant, BuilderGraph, BuilderParamConstraint } from "./builderGraph";

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

/** Translate one non-tool_name predicate into a grant constraint, or explain why it cannot be. */
function constraintFor(field: string, spec: IntentPredicateSpec): BuilderParamConstraint | string {
  if (!field.startsWith(PARAM_PATH_PREFIX)) {
    // data_classes / destinations.* / sql_tables / param_bytes / verb / mcp.* are all expressible by
    // the builder's RULES mode (see builderScopingFacts.test.ts) but not yet inside an allowlist
    // GRANT — which is the exact gap tests/fixtures/cross_compiler records.
    return `${field}: an allowlist grant cannot express this yet (only the builder's rules mode can)`;
  }
  const flat = flatFieldFor(field);
  if (!flat) return `${field}: a grant addresses one flat parameter, so a nested path has no equivalent`;
  const ops = asRecord(spec);
  if (typeof ops.matches === "string") return { kind: "matches", field: flat, pattern: ops.matches };
  if (typeof ops.notMatches === "string") return { kind: "notMatches", field: flat, pattern: ops.notMatches };
  if (typeof ops.equals === "string") return { kind: "oneOf", field: flat, values: [ops.equals] };
  if (Array.isArray(ops.in)) {
    const values = ops.in.filter((v): v is string => typeof v === "string");
    if (values.length) return { kind: "oneOf", field: flat, values };
  }
  return `${field}: operator ${Object.keys(ops).join("/") || "(none)"} has no grant equivalent`;
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
    const predicates = { ...(rule.match ?? {}), ...(rule.require ?? {}) };
    Object.entries(predicates).forEach(([field, spec]) => {
      if (field === "tool_name") return;
      const c = constraintFor(field, spec);
      if (typeof c === "string") dropped.push(`rule ${rule.id}: ${c}`);
      else constraints.push(c);
    });

    if (constraints.length) {
      names.forEach((tool) => {
        const existing = grants.find((g) => g.tool === tool);
        // One grant per tool: the compiler rejects duplicates rather than merging, because silently
        // dropping half an operator's constraints reads as "the policy is too permissive" long after
        // anyone remembers why.
        if (existing) existing.constraints.push(...constraints);
        else grants.push({ tool, constraints: [...constraints] });
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
