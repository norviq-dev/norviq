// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import type { CSSProperties } from "react";

/**
 * How well Norviq knows a tool name — the distinction the whole registry exists to preserve.
 *
 * The bug this component is the antidote to: the builder used to infer a "known tools" set by unioning
 * observed names with capability SUBSTRINGS ("post", "http", "delete") and treating the union as an
 * existence oracle. It therefore suggested names that could not exist and then suppressed its own
 * warning for exactly those names. Sources of different strength must stay visibly different.
 *
 * FOUR states, and the fourth is the one that is easy to get wrong:
 *
 *   declared — an MCP server published a definition and an operator approved it. May carry a JSON
 *              Schema, so its arguments can be scoped. `--accent`.
 *   observed — the name appeared in real traffic. Proves it exists; says nothing about its shape.
 *   unknown  — not in the registry at all. Advisory only: deny-by-default REQUIRES authoring rules for
 *              tools nobody has called, so this must never gate anything.
 *   silent   — the registry could not be read (fetch failed, or empty). Renders NOTHING, deliberately.
 *
 * On `silent`: the temptation is to fall back to `unknown`, and that would be a lie. "We could not check"
 * is not "we checked and found nothing", and a badge saying `Unknown` in that state would be a claim the
 * UI has no basis for. Whoever renders this must pair the absent badge with a visible band saying names
 * are not being checked — silence must never read as an all-clear.
 */
export type ProvenanceSource = "mcp_declared" | "observed";

export interface ProvenanceBadgeProps {
  /** The registry row's `source`, or null when the name is not in the registry at all. */
  source?: ProvenanceSource | null;
  /** True when the registry itself is unavailable — renders nothing. Wins over every other prop. */
  registryNull?: boolean;
}

const TONE: Record<string, { label: string; hex: string; title: string }> = {
  mcp_declared: {
    label: "Declared",
    hex: "#2ddab8",
    title: "An MCP server published this definition and an operator approved it"
  },
  observed: {
    label: "Observed",
    hex: "#ffb020",
    title: "Seen in real traffic. No definition, so its arguments cannot be scoped"
  },
  unknown: {
    label: "Unknown",
    hex: "#ffb020",
    title: "Not in this namespace's tool registry — advisory only, it never blocks authoring"
  }
};

/** The literal-hex + alpha-suffix recipe every status pill in this app uses. Not `rgba()`. */
function pillStyle(hex: string): CSSProperties {
  return { background: `${hex}15`, color: hex, borderColor: `${hex}30` };
}

export function ProvenanceBadge({ source, registryNull = false }: ProvenanceBadgeProps) {
  // Renders nothing, and callers must NOT substitute a fallback. See the header.
  if (registryNull) return null;
  const tone = TONE[source ?? "unknown"] ?? TONE.unknown;
  return (
    <span
      className="pill"
      data-testid={`provenance-${source ?? "unknown"}`}
      title={tone.title}
      style={pillStyle(tone.hex)}
    >
      {tone.label}
    </span>
  );
}
