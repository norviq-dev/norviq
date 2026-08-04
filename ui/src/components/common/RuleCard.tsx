// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * One proposed allow rule, as two questions rather than a list of predicates.
 *
 * APPLIES TO answers "is this rule about the call I am worried about?" — the question an operator
 * scanning a proposal is actually asking. ALLOWED IF answers "and what must additionally hold?".
 * Flattened into one `a · b · c` line, as this screen used to render them, the two are
 * indistinguishable: every rule looks like it might govern every call, so the operator reads all of
 * them or none.
 *
 * `Show raw` is not a debug affordance. The predicates are what the engine stores and what the
 * near-miss report quotes back, so an operator who has read a refusal needs to find the same strings
 * here. One dialect, per the design brief — both sides render through `predicateSentence`.
 */

import { useState } from "react";
import { predicateSentence, termsOfRule, type PredicateTerm } from "../../lib/predicateSentence";
import { LookalikeNote } from "./LookalikeNote";

export type ProposedRule = {
  id: string;
  server?: string;
  match?: Record<string, unknown>;
  require?: Record<string, unknown>;
};

function Band({ label, terms, empty, testId }: { label: string; terms: PredicateTerm[]; empty: string; testId?: string }) {
  return (
    <div style={{ marginTop: 10 }}>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--text-muted)",
          marginBottom: 5
        }}
      >
        {label}
      </div>
      {terms.length === 0 ? (
        <div style={{ fontSize: 13, color: "var(--text-muted)" }}>{empty}</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {terms.map((t) => {
            const s = predicateSentence(t);
            return (
              <div key={t.raw} style={{ fontSize: 13, lineHeight: 1.5, color: "var(--text-secondary)" }}>
                {s.prose}
                {/* Beneath the clause it qualifies, not beside the rule id: which of a rule's names is
                    the lookalike is the whole question, and a card-level badge cannot answer it. */}
                {s.lookalikes && <LookalikeNote lookalikes={s.lookalikes} data-testid={testId && `${testId}-lookalike`} />}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export interface RuleCardProps {
  rule: ProposedRule;
  /** How many replayed calls this rule permitted. `null` before a dry run has been done. */
  calls?: number | null;
  /** True when the dry run matched nothing against it. */
  unused?: boolean;
  /** Clauses hoisted to a set-level line, so they are not repeated on every card. */
  hoisted?: string[];
  "data-testid"?: string;
}

export function RuleCard({ rule, calls = null, unused = false, hoisted = [], "data-testid": testId }: RuleCardProps) {
  const [raw, setRaw] = useState(false);
  const { appliesTo, allowedIf } = termsOfRule(rule);
  const shown = allowedIf.filter((t) => !hoisted.includes(t.raw));

  return (
    <div
      data-testid={testId ?? `rule-${rule.id}`}
      style={{
        border: "1px solid var(--border)",
        borderRadius: 12,
        padding: "13px 14px",
        background: "var(--bg-void)"
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 9, flexWrap: "wrap" }}>
        <code className="mono" style={{ fontSize: 13 }}>
          {rule.id}
        </code>
        {unused ? (
          <span
            className="pill"
            title="No recorded call matched this rule"
            style={{ background: "#FFB02015", color: "#FFB020", borderColor: "#FFB02030" }}
            data-testid={`rule-${rule.id}-unused`}
          >
            Matched nothing
          </span>
        ) : typeof calls === "number" ? (
          <span
            className="pill"
            style={{ background: "#00E5A015", color: "#00E5A0", borderColor: "#00E5A030" }}
            data-testid={`rule-${rule.id}-calls`}
          >
            {calls} calls
          </span>
        ) : null}
        <span style={{ flex: 1 }} />
        <button type="button" className="linklike" style={{ fontSize: 12 }} onClick={() => setRaw((v) => !v)}
          data-testid={`rule-${rule.id}-raw-toggle`}>
          {raw ? "Hide raw" : "Show raw"}
        </button>
      </div>

      <Band
        label="Applies to"
        terms={appliesTo}
        empty="every call this class makes"
        testId={`rule-${rule.id}-applies`}
      />
      <Band
        label="Allowed if"
        terms={shown}
        testId={`rule-${rule.id}-allowed`}
        // Not "nothing" on its own: an empty ALLOWED IF is the rule granting the tool outright, which
        // is a meaningful and slightly alarming state rather than a missing value.
        empty={
          hoisted.length > 0
            ? "nothing further beyond the clause applied to every rule — this grants the tool outright"
            : "nothing further — this grants the tool outright"
        }
      />

      {raw && (
        <pre
          className="json"
          data-testid={`rule-${rule.id}-raw`}
          style={{
            marginTop: 10,
            padding: "9px 10px",
            borderRadius: 8,
            background: "var(--bg-elevated)",
            fontSize: 11.5,
            color: "var(--text-secondary)"
          }}
        >
          {[...appliesTo, ...allowedIf].map((t) => t.raw).join("\n")}
        </pre>
      )}
    </div>
  );
}
