// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import type { CSSProperties, ReactNode } from "react";

/**
 * A control plus the reason it is unavailable, as visible text.
 *
 * WHY THIS IS A COMPONENT AND NOT A `title`. `index.css` sets `.btn:disabled { pointer-events: none }`.
 * A disabled button therefore never receives hover, so a `title` on it can never be shown — the
 * explanation is written, shipped, and unreachable. Three surfaces relied on exactly that: the builder's
 * Save button, Propose's Save-as-draft, and MCP's Approve.
 *
 * The consequence is worse than a missing tooltip. Two different blockers render as the same grey
 * button: "you have not dry-run yet" looks identical to "you are not an admin", so the operator cannot
 * tell whether to act or to ask someone else.
 *
 * Tone carries meaning and is not decoration:
 *   escalate — you can clear this yourself (run a dry-run, pick a namespace)
 *   block    — a refusal that will not clear by retrying (the handoff would weaken the policy)
 *   muted    — a permission or environment fact (needs admin, registry unavailable)
 */
export type DisabledReasonTone = "escalate" | "block" | "muted";

export interface InlineDisabledReasonProps {
  /** The control itself — usually a disabled `KitButton`. */
  children: ReactNode;
  /** Why it is unavailable. Rendered as text, always. Omit to render the control bare. */
  reason?: ReactNode;
  tone?: DisabledReasonTone;
  /** Right-align for a footer action bar; left-align inline in a form. */
  align?: "start" | "end";
  "data-testid"?: string;
}

const TONE_COLOR: Record<DisabledReasonTone, string> = {
  escalate: "var(--escalate)",
  block: "var(--block)",
  muted: "var(--text-muted)"
};

export function InlineDisabledReason({
  children,
  reason,
  tone = "escalate",
  align = "end",
  "data-testid": testId
}: InlineDisabledReasonProps) {
  const wrap: CSSProperties = {
    display: "flex",
    flexDirection: "column",
    alignItems: align === "end" ? "flex-end" : "flex-start",
    gap: 3
  };
  return (
    <div style={wrap} data-testid={testId}>
      {children}
      {reason ? (
        // `role="status"` so a screen reader announces the reason when it appears, rather than leaving
        // the user to discover that a button they expected went grey.
        <span
          role="status"
          data-testid={testId ? `${testId}-reason` : "disabled-reason"}
          style={{
            fontSize: 11.5,
            lineHeight: 1.45,
            color: TONE_COLOR[tone],
            // 320px was wide enough that a two-clause reason set the COLUMN's width, and since the
            // column right-aligns inside an action row whose right edge is mid-row, the text spilled
            // leftward underneath the neighbouring button — reading as a caption belonging to
            // neither control. 220 keeps a reason hanging under the button it explains.
            // Long enough to say a sentence; short enough that it cannot annex its neighbour.
            maxWidth: 220,
            textAlign: align === "end" ? "right" : "left"
          }}
        >
          {reason}
        </span>
      ) : null}
    </div>
  );
}
