// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The right two-thirds of an allowed-tool row — and the single most important thing in the redesign.
 *
 * THE DEFECT IT REPLACES. An allowed tool used to render as a small chip with a 10.5px grey text
 * button reading `+ scope`. That button is the entire product differentiator: Norviq's claim is that
 * an allowlist of tool NAMES is not a security control, because a name is exactly what the agent
 * framework already grants. The control is the rest of the sentence — "send_dm, but only to
 * @acme.com". Shipping that behind an unlabelled chip affordance ships the differentiator switched
 * off, and a first-time operator finishes the flow having built a capability list while believing
 * they built a policy.
 *
 * SO THE CELL NEVER RENDERS EMPTY. Four slots, always filled:
 *   headline — what the grant currently permits, in five words
 *   detail   — what could be narrowed, or what IS narrowed
 *   impact   — the consequence, stated as a policy fact rather than a guess about traffic
 *   CTA      — the way forward, with three faces: Narrow it → Edit → Collapse
 *
 * An empty slot is what made the old chip readable as "done". The unscoped state is not a neutral
 * default; it is the widest possible grant, and it says so.
 *
 * WHY THE IMPACT LINE TALKS ABOUT POLICY, NOT TRAFFIC. The design shows per-tool call counts
 * ("Allows 312 · 4 would now be denied"). `DryRunReplay` carries no per-tool totals — only a
 * TRUNCATED sample of newly-blocked calls — so a count rendered here would be a lower bound presented
 * as a total. What this cell states instead is always exactly true and needs no endpoint: an
 * unscoped grant allows every call to that tool, whatever its arguments. Traffic is added only where
 * the dry run genuinely names this tool, and is labelled as a sample when it is one.
 */

import { ArrowRight, ChevronUp, Pencil } from "lucide-react";
import { describeConstraint, describeFact } from "../../lib/builderCompile";
import type { BuilderGrantFact, BuilderParamConstraint } from "../../lib/builderGraph";

export interface ScopeCellProps {
  tool: string;
  constraints: BuilderParamConstraint[];
  facts: BuilderGrantFact[];
  /** Argument paths the tool declares that a grant can actually address. */
  addressableArgs: string[];
  /** Every argument path the schema declares, addressable or not. */
  totalArgs: number;
  /** False when no approved definition carries an inputSchema — a real, distinct state. */
  schemaAvailable: boolean;
  expanded: boolean;
  onToggle: () => void;
  /** Calls the last dry run says this grant would newly deny. Omit when no dry run has been done. */
  newlyDenied?: number | null;
  /** True when the dry run's sample was truncated, so `newlyDenied` is a lower bound. */
  sampled?: boolean;
  "data-testid"?: string;
}

/** Every condition on this grant, in the SAME words the generated rego's header comment uses. */
export function scopeSummary(
  constraints: BuilderParamConstraint[],
  facts: BuilderGrantFact[]
): string[] {
  return [...constraints.map(describeConstraint), ...facts.map(describeFact)];
}

export function ScopeCell({
  tool,
  constraints,
  facts,
  addressableArgs,
  totalArgs,
  schemaAvailable,
  expanded,
  onToggle,
  newlyDenied = null,
  sampled = false,
  "data-testid": testId
}: ScopeCellProps) {
  const conditions = scopeSummary(constraints, facts);
  const scoped = conditions.length > 0;
  const base = testId ?? `scope-cell-${tool}`;

  // ---- slot 1: headline ------------------------------------------------------------------------
  const headline = scoped
    ? `Narrowed · ${conditions.length} condition${conditions.length === 1 ? "" : "s"}`
    : "Any arguments · unrestricted";

  // ---- slot 2: detail --------------------------------------------------------------------------
  let detail: React.ReactNode;
  if (scoped) {
    detail = (
      <span style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
        {conditions.map((c) => (
          <span
            key={c}
            className="mono"
            data-testid={`${base}-condition`}
            style={{
              fontSize: 11,
              padding: "2px 7px",
              borderRadius: 999,
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)"
            }}
          >
            {c}
          </span>
        ))}
      </span>
    );
  } else if (!schemaAvailable) {
    // Not an error and not an absence of arguments — the definition simply carries no schema, so the
    // only honest advice is the one route that still works.
    detail = <>No schema — add whole-call conditions, or type a path you know.</>;
  } else if (addressableArgs.length === 0) {
    detail = <>None of its {totalArgs} arguments can be addressed — scope what the call carries or reaches instead.</>;
  } else {
    detail = (
      <>
        {addressableArgs.length} of its {totalArgs} argument{totalArgs === 1 ? "" : "s"} can be narrowed —{" "}
        {addressableArgs.slice(0, 2).map((a, i) => (
          <span key={a}>
            {i > 0 && ", "}
            <span className="mono" style={{ color: "var(--text-secondary)" }}>
              {a}
            </span>
          </span>
        ))}
        {addressableArgs.length > 2 && ` and ${addressableArgs.length - 2} more`}
      </>
    );
  }

  // ---- slot 3: impact --------------------------------------------------------------------------
  // Always a POLICY fact, which is always knowable. Traffic is appended only when the dry run
  // actually names this tool, and is marked as a sample when the server truncated it.
  const impact = scoped
    ? conditions.length === 1
      ? "Allows a call only when its one condition holds."
      : `Allows a call only when all ${conditions.length} conditions hold.`
    : `Allows every call to ${tool}, with any arguments.`;
  const traffic =
    newlyDenied === null
      ? null
      : newlyDenied > 0
        ? `${sampled ? "at least " : ""}${newlyDenied} replayed call${newlyDenied === 1 ? "" : "s"} would now be denied`
        : "No replayed call would be denied by this grant.";

  // ---- slot 4: CTA -----------------------------------------------------------------------------
  const Icon = expanded ? ChevronUp : scoped ? Pencil : ArrowRight;
  const ctaLabel = expanded ? "Collapse" : scoped ? "Edit" : "Narrow it";

  return (
    <div
      data-testid={base}
      style={{ flex: "2 1 300px", minWidth: 0, display: "flex", gap: 10, alignItems: "flex-start" }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          data-testid={`${base}-headline`}
          style={{
            fontSize: 12.5,
            fontWeight: 600,
            // An unscoped grant is the WIDEST thing this policy can say. Amber is not decoration:
            // the row is telling the operator there is work left, and a neutral grey said "fine".
            color: scoped ? "var(--allow)" : "var(--escalate)"
          }}
        >
          {headline}
        </div>
        <div
          data-testid={`${base}-detail`}
          style={{ fontSize: 11.5, lineHeight: 1.5, color: "var(--text-muted)", marginTop: 3 }}
        >
          {detail}
        </div>
        <div
          data-testid={`${base}-impact`}
          style={{ fontSize: 11.5, lineHeight: 1.5, color: "var(--text-secondary)", marginTop: 3 }}
        >
          {impact}
          {traffic && <span style={{ color: "var(--block)" }}> · {traffic}</span>}
        </div>
      </div>
      <button
        type="button"
        data-testid={`${base}-cta`}
        aria-expanded={expanded}
        onClick={onToggle}
        // Filled primary ONLY when unscoped. The CTA is loud exactly while there is something
        // important left undone, and recedes to a quiet outline once the grant has been narrowed.
        className={`btn btn-sm ${expanded || scoped ? "btn-outline" : "btn-primary"}`}
        style={{ flex: "none" }}
      >
        <Icon size={13} /> {ctaLabel}
      </button>
    </div>
  );
}
