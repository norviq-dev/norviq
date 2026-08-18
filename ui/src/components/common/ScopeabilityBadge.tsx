// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import type { CSSProperties } from "react";

/**
 * What an operator can actually DO with a tool — the second thing the eye should land on.
 *
 * `ProvenanceBadge` says how well we know the name. This says what that knowledge buys, which is the
 * question an operator is really asking. The two are not redundant: a tool can be fully declared and
 * pinned and still be unscopeable, because the stored definition is an 8 KiB slice and a long
 * description sorts alphabetically ahead of `inputSchema` and evicts it.
 *
 *   scopeable  — a schema is present, so `param_paths.<path>` conditions can address its arguments
 *   no schema  — declared, but the schema is missing or unparseable. Name-level rules still work
 *   name only  — observed, never declared. Whole-call facts work; per-argument scoping does not
 *
 * "No schema" is deliberately `--escalate` rather than neutral: it is a capability an operator expected
 * to have and does not, and treating it as unremarkable is how it goes unnoticed.
 */
export interface ScopeabilityBadgeProps {
  /** `schema_available` from the registry row. */
  schemaAvailable: boolean;
  /** `source` from the registry row. */
  source: "mcp_declared" | "observed";
}

function pillStyle(hex: string): CSSProperties {
  return { background: `${hex}15`, color: hex, borderColor: `${hex}30` };
}

/** Observed tools have no definition at all, so neutral — this is not a defect, it is the tier. */
const NEUTRAL: CSSProperties = { background: "#1f1f1f", color: "#a0a0a0", borderColor: "#2a2a2a" };

export function ScopeabilityBadge({ schemaAvailable, source }: ScopeabilityBadgeProps) {
  if (source === "observed") {
    return (
      <span
        className="pill"
        data-testid="scopeability-name-only"
        title="No definition, so only the tool name can be matched. Whole-call facts still apply."
        style={NEUTRAL}
      >
        Name only
      </span>
    );
  }
  if (!schemaAvailable) {
    return (
      <span
        className="pill"
        data-testid="scopeability-no-schema"
        // Three different states set `schema_available = false` — the definition was truncated, or it
        // was unparseable, or it simply declares no `inputSchema` (every zero-argument tool). Naming
        // the 8 KiB eviction as THE cause sent operators hunting a truncation that never happened on
        // the commonest of the three. "Approved definition" was wrong for the same quarantined pins
        // as the provenance badge. State the consequence, which is true of all three.
        title="No argument schema in the stored definition, so arguments cannot be scoped — match by name, or hand-write a path"
        style={pillStyle("#ffb020")}
      >
        No schema
      </span>
    );
  }
  return (
    <span
      className="pill"
      data-testid="scopeability-scopeable"
      title="A policy can narrow this tool by its arguments"
      style={pillStyle("#00e5a0")}
    >
      Scopeable
    </span>
  );
}
