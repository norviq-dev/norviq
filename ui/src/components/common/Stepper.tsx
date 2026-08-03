// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { Check } from "lucide-react";
import type { CSSProperties } from "react";

/**
 * Where you are in a sequence that must be done in order.
 *
 * Both surfaces that use this have a mandatory order enforced only by disabled buttons today — the
 * builder (scope → what it may do → check & enforce) and Propose (propose → dry run → save as draft).
 * A disabled control tells you that you cannot act; it does not tell you what you are in the middle of,
 * or that there is a step after this one. That is the gap this closes.
 *
 * The trailing hint is part of the component rather than a caller's afterthought because both surfaces
 * need to say the same reassuring thing in the same place — nothing here enforces until you save.
 */
export interface Step {
  label: string;
  /** Optional: the sub-surface this step corresponds to, for a title tooltip. */
  title?: string;
}

export interface StepperProps {
  steps: Step[];
  /** Zero-based. Everything before it is done, everything after is to-do. */
  current: number;
  /** Right-aligned reassurance, e.g. "Nothing is enforced until you save." */
  hint?: string;
  "data-testid"?: string;
}

const DOT: CSSProperties = {
  flex: "none",
  width: 18,
  height: 18,
  borderRadius: 999,
  display: "grid",
  placeItems: "center",
  fontSize: 10.5,
  // 600, not the prototype's 700: Outfit is self-hosted at 400/500/600 only, so 700 would synthesise a
  // faux-bold that renders heavier and blurrier than every other weight in the app.
  fontWeight: 600
};

export function Stepper({ steps, current, hint, "data-testid": testId }: StepperProps) {
  return (
    <div
      data-testid={testId}
      style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}
    >
      {steps.map((step, i) => {
        const done = i < current;
        const isCurrent = i === current;
        return (
          <div key={step.label} style={{ display: "contents" }}>
            {i > 0 && (
              <span aria-hidden style={{ color: "var(--border-active)" }}>
                ›
              </span>
            )}
            <span
              data-testid={testId ? `${testId}-step-${i}` : undefined}
              // The current step is the one a screen reader should land on as "here".
              aria-current={isCurrent ? "step" : undefined}
              title={step.title}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 12px",
                borderRadius: 9,
                fontSize: 13,
                fontWeight: 500,
                background: isCurrent ? "var(--bg-surface-hover)" : "transparent",
                color: done || isCurrent ? "var(--text-primary)" : "var(--text-muted)"
              }}
            >
              <span
                style={{
                  ...DOT,
                  background: done ? "var(--accent)" : "var(--bg-elevated)",
                  color: done ? "var(--bg-void)" : isCurrent ? "var(--text-secondary)" : "var(--text-muted)"
                }}
              >
                {/* A tick for a finished step, its number otherwise — the number is only useful while
                    the step is still ahead of you. */}
                {done ? <Check size={10} strokeWidth={3.5} aria-hidden /> : i + 1}
              </span>
              {step.label}
            </span>
          </div>
        );
      })}
      {hint && (
        <>
          <span style={{ flex: 1 }} />
          <span style={{ fontSize: 12, color: "var(--text-faint)" }}>{hint}</span>
        </>
      )}
    </div>
  );
}
