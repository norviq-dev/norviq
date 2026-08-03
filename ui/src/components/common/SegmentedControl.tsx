// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import type { CSSProperties } from "react";

/**
 * A small exclusive choice rendered inline — decision verbs, time ranges, plane filters.
 *
 * Used where a `<select>` would hide the alternatives behind a click. That matters here because the
 * choices carry meaning an operator is comparing: Block vs Escalate vs Audit is a decision about
 * consequence, not a preference, and seeing the three together is the point.
 *
 * Each option may carry its own tone, so the active segment is tinted by what it MEANS rather than by
 * the brand accent — a selected `Block` reads `--block`, a selected `Escalate` reads `--escalate`. That
 * is the same literal-hex + alpha recipe as `.pill`, and it is why this does not just use `.tab-kit`.
 *
 * Semantics: a real radiogroup. Arrow keys move between options and the whole group takes one tab stop,
 * which is what a keyboard user expects from a segmented control and what a row of buttons would get
 * wrong.
 */
export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  /** Literal hex for the active state. Defaults to the brand accent. Must be an existing token value. */
  hex?: string;
  title?: string;
}

export interface SegmentedControlProps<T extends string> {
  options: SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  ariaLabel: string;
  "data-testid"?: string;
}

const SHELL: CSSProperties = {
  display: "inline-flex",
  padding: 2,
  borderRadius: 9,
  background: "var(--bg-void)",
  border: "1px solid var(--border)",
  gap: 2
};

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
  "data-testid": testId
}: SegmentedControlProps<T>) {
  const move = (delta: number) => {
    const i = options.findIndex((o) => o.value === value);
    if (i < 0) return;
    // Wraps deliberately: with three or four options, wrapping is faster than reversing direction and
    // matches how a radiogroup behaves elsewhere.
    const next = options[(i + delta + options.length) % options.length];
    onChange(next.value);
  };

  return (
    <div role="radiogroup" aria-label={ariaLabel} data-testid={testId} style={SHELL}>
      {options.map((opt) => {
        const active = opt.value === value;
        const hex = opt.hex ?? "#2ddab8";
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={active}
            title={opt.title}
            // Only the active segment is in the tab order — the group is one stop, arrows move within.
            tabIndex={active ? 0 : -1}
            data-testid={testId ? `${testId}-${opt.value}` : undefined}
            onClick={() => onChange(opt.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowRight" || e.key === "ArrowDown") {
                e.preventDefault();
                move(1);
              } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
                e.preventDefault();
                move(-1);
              }
            }}
            style={{
              padding: "5px 12px",
              borderRadius: 7,
              border: "none",
              fontSize: 13,
              fontFamily: "inherit",
              cursor: "pointer",
              background: active ? `${hex}15` : "transparent",
              color: active ? hex : "var(--text-muted)",
              fontWeight: active ? 600 : 400
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
