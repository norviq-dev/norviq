// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The exact text that made a scanner rule fire.
 *
 * `McpFinding.evidence` has been on the API since the scanner shipped and was rendered NOWHERE. The
 * console showed the rule name and a rationale — "Instructs the model to act before answering" — and
 * left the operator to take it on faith. Approving or refusing a definition is a judgement about a
 * specific sentence; without the sentence there is no judgement, only deference to a heuristic.
 *
 * Three properties make showing attacker-authored text safe, and all three are visible:
 *  - it is QUOTED, so it reads as reported speech rather than as the console's own words;
 *  - it is labelled attacker-authored, so its authorship is never in doubt;
 *  - it is inert — the model never reads this page, and the proxy already stripped this text before
 *    the model saw the definition. The label says that too, because an operator who thinks they are
 *    looking at a live payload will hesitate to read it carefully.
 *
 * `user-select: all` is functional, not styling: the operator's next step is usually to paste this
 * into a ticket, and a click-drag over adversarial text risks selecting a partial payload.
 */

export interface EvidenceBlockProps {
  evidence: string;
  /** Where in the definition it was found — `inputSchema.properties.channel.description`. */
  field?: string;
  "data-testid"?: string;
}

export function EvidenceBlock({ evidence, field, "data-testid": testId = "evidence-block" }: EvidenceBlockProps) {
  // A finding without evidence renders nothing rather than an empty quote — an empty blockquote reads
  // as "the scanner found nothing quotable", which is a different and false claim.
  if (!evidence || !evidence.trim()) return null;

  return (
    <div data-testid={testId} style={{ padding: "11px 12px", borderTop: "1px solid var(--border)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 7 }}>
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--escalate)"
          }}
        >
          Evidence · attacker-authored
        </span>
        <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>quoted verbatim, never executed</span>
      </div>
      {field ? (
        <div className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)", marginBottom: 6, overflowWrap: "anywhere" }}>
          {field}
        </div>
      ) : null}
      <blockquote
        data-testid={`${testId}-quote`}
        className="mono"
        style={{
          margin: 0,
          padding: "10px 11px",
          borderLeft: "3px solid var(--escalate)",
          borderRadius: "0 8px 8px 0",
          background: "var(--bg-void)",
          fontSize: 12,
          lineHeight: 1.6,
          color: "var(--text-secondary)",
          overflowWrap: "anywhere",
          // Long payloads scroll rather than truncate: an ellipsis would hide the tail of an attack,
          // which is exactly where the interesting part usually is.
          maxHeight: 220,
          overflowY: "auto",
          userSelect: "all"
        }}
      >
        {`“${evidence}”`}
      </blockquote>
      <div style={{ marginTop: 7, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}>
        Stripped before the model saw it. Inert here.
      </div>
    </div>
  );
}
