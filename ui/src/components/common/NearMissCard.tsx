// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Why one recorded call would be refused — clause by clause.
 *
 * The old rendering was the compiler's whole reason string in a table cell: `no intent rule matched;
 * closest send-send-email met 3/4, failed: param_paths.to matches ^[^@]+@acme\.com$`. Everything the
 * operator needs is in there, and none of it is legible: to act on it they have to find the rule,
 * count its clauses, work out which three passed, and read a regex.
 *
 * THE HEADLINE MUST RECONCILE. "met 3 of 4" beside a list of two clauses is worse than no list — the
 * operator concludes the screen is wrong and stops trusting the rest of it. The two missing clauses
 * are the ones the COMPILER adds, not the operator: the plane, and the availability guard for a
 * version-gated root. So implicit clauses are rendered, marked as implicit, and counted. The API
 * publishes the full label list precisely so this addition is structural rather than coincidental
 * (`norviq/engine/intent/dryrun.py`).
 *
 * When the API could not decompose the reason, the raw sentence is shown instead. Degraded, never
 * self-contradictory.
 */

import { Check, X } from "lucide-react";
import { sentenceOf } from "../../lib/predicateSentence";
import { LookalikeNote } from "./LookalikeNote";

export type BlockedCallDetail = {
  index: number;
  tool_name: string;
  reason: string;
  closest_rule?: string;
  met?: number;
  predicates?: string[];
  failed?: string[];
};

function Clause({ label, failed }: { label: string; failed: boolean }) {
  const s = sentenceOf(label);
  return (
    <div
      data-testid={`clause-${failed ? "failed" : "met"}`}
      style={{
        display: "flex",
        gap: 9,
        alignItems: "flex-start",
        padding: failed ? "9px 11px" : "8px 11px",
        borderRadius: 10,
        background: failed ? "#ff3b5c15" : "var(--bg-elevated)",
        border: failed ? "1px solid #ff3b5c30" : "1px solid transparent"
      }}
    >
      <span style={{ flex: "none", marginTop: 2, color: failed ? "var(--block)" : "var(--allow)" }}>
        {failed ? <X size={13} strokeWidth={3} /> : <Check size={13} strokeWidth={3} />}
      </span>
      <span style={{ minWidth: 0 }}>
        <span style={{ display: "block", fontSize: 13, lineHeight: 1.5, color: failed ? "var(--text-primary)" : "var(--text-secondary)" }}>
          {s.prose}
          {s.implicit && (
            <span style={{ fontSize: 12, color: "var(--text-faint)" }}> — implicit, applied to every rule</span>
          )}
        </span>
        {/* The engine's own words, on the failing clause only. This is the string an operator will
            search the rule for, so it has to be the same string the rule card shows. */}
        {failed && s.humanised && (
          <span
            className="mono"
            style={{ display: "block", marginTop: 3, fontSize: 12, color: "var(--text-faint)", overflowWrap: "anywhere" }}
          >
            {s.raw}
          </span>
        )}
        {/* On a MET clause too, not only a failed one: "calls to send_email · met" against a rule
            written from a lookalike is the reading that most needs correcting. */}
        {s.lookalikes && <LookalikeNote lookalikes={s.lookalikes} />}
      </span>
    </div>
  );
}

export interface NearMissCardProps {
  call: BlockedCallDetail;
  /** How many replayed calls were refused for the same reason, when the caller has grouped them. */
  occurrences?: number;
  "data-testid"?: string;
}

export function NearMissCard({ call, occurrences, "data-testid": testId }: NearMissCardProps) {
  const predicates = call.predicates ?? [];
  const failed = new Set(call.failed ?? []);
  const decomposed = predicates.length > 0 && typeof call.met === "number";

  return (
    <div
      data-testid={testId ?? `near-miss-${call.index}`}
      style={{ borderTop: "1px solid var(--border)", padding: "15px 0" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 11 }}>
        <span className="mono" style={{ fontSize: 14 }}>
          {call.tool_name || "(unnamed tool)"}
        </span>
        <span className="pill" style={{ background: "#ff3b5c15", color: "var(--block)", borderColor: "#ff3b5c30" }}>
          Refused
        </span>
        {typeof occurrences === "number" && occurrences > 1 && (
          <span style={{ fontSize: 12.5, color: "var(--text-muted)" }}>{occurrences} calls</span>
        )}
        <span style={{ flex: 1 }} />
        {decomposed && (
          <span style={{ fontSize: 12.5, color: "var(--text-secondary)" }} data-testid="near-miss-summary">
            closest rule <span className="mono" style={{ color: "var(--text-primary)" }}>{call.closest_rule}</span> ·
            met {call.met} of {predicates.length}
          </span>
        )}
      </div>

      {decomposed ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
          {/* Failing clauses first: the operator is here to find what to change, and on a rule with
              eight predicates the one that matters should not be seventh. */}
          {predicates
            .slice()
            .sort((a, b) => Number(failed.has(b)) - Number(failed.has(a)))
            .map((p) => (
              <Clause key={p} label={p} failed={failed.has(p)} />
            ))}
        </div>
      ) : (
        <div className="mono" style={{ fontSize: 12, lineHeight: 1.6, color: "var(--text-secondary)", whiteSpace: "normal" }}>
          {call.reason}
        </div>
      )}
    </div>
  );
}
