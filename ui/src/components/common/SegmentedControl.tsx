// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useEffect, useRef, type CSSProperties } from "react";

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
 *
 * FOCUS FOLLOWS THE SELECTION — see the effect below. A roving tabindex that moves the selection without
 * moving focus is not a smaller bug than no keyboard support: the focus ring sits on one segment while
 * the active tint sits on another, the focused element has just been given `tabIndex={-1}` so it has
 * dropped out of the tab order, a screen reader is announcing the segment that is no longer checked, and
 * a Space or Enter meant as "confirm" fires the click handler of the OLD segment and silently reverts the
 * choice. On the Tools observed-window picker that means an operator who arrowed to 24h and pressed Space
 * is reading a 30d window under a 24h intent.
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
  const groupRef = useRef<HTMLDivElement | null>(null);
  const segments = useRef(new Map<string, HTMLButtonElement>());

  /**
   * Keep the focus ring on whichever segment is checked, whenever the operator is already inside the
   * group. Written as an effect on `value` rather than as a `.focus()` inside `move()` on purpose: this
   * is a CONTROLLED component, so the selection only really moves when the owner re-renders us with a
   * new `value`. Focusing eagerly would put the ring on a segment the owner declined to select — the
   * same desync, mirrored. The `contains` guard is what stops the group stealing focus on mount or when
   * an unrelated part of the page drives `value`.
   */
  useEffect(() => {
    const group = groupRef.current;
    const active = segments.current.get(value);
    if (!group || !active) return;
    const focused = document.activeElement;
    if (!focused || focused === active || !group.contains(focused)) return;
    active.focus();
  }, [value]);

  const activeIndex = options.findIndex((o) => o.value === value);

  /**
   * WHERE THE SINGLE TAB STOP GOES WHEN NOTHING IS CHECKED.
   *
   * `value` not being one of the options is not hypothetical — it is one stale deep link or one renamed
   * option away. The roving tabindex then gave EVERY segment `tabIndex={-1}` and `move()` returned on
   * `i < 0`, so the control dropped out of the tab order and ignored arrow keys: a row of segments,
   * none tinted, that does not answer the keyboard at all and says nothing about why. Fixing the focus
   * ring while leaving that in place would be finishing half the invariant — focus and selection agree
   * everywhere except the one state where they cannot, and there the control just dies quietly.
   *
   * So the group keeps its tab stop on the first segment, and the first arrow key selects that segment
   * — which both restores keyboard access and resolves the mismatch into a real selection the owner
   * can see. Nothing is claimed to be checked in the meantime: `aria-checked` stays false on all of
   * them, because it is true of none of them.
   */
  const tabStopIndex = activeIndex >= 0 ? activeIndex : 0;

  const move = (delta: number) => {
    if (options.length === 0) return;
    if (activeIndex < 0) {
      onChange(options[0].value);
      return;
    }
    // Wraps deliberately: with three or four options, wrapping is faster than reversing direction and
    // matches how a radiogroup behaves elsewhere.
    const next = options[(activeIndex + delta + options.length) % options.length];
    onChange(next.value);
  };

  return (
    <div role="radiogroup" aria-label={ariaLabel} data-testid={testId} style={SHELL} ref={groupRef}>
      {options.map((opt, i) => {
        const active = opt.value === value;
        const hex = opt.hex ?? "#2ddab8";
        return (
          <button
            key={opt.value}
            ref={(el) => {
              if (el) segments.current.set(opt.value, el);
              else segments.current.delete(opt.value);
            }}
            type="button"
            role="radio"
            aria-checked={active}
            title={opt.title}
            // Only one segment is in the tab order — the group is one stop, arrows move within. That is
            // the checked one, or the first when `value` matches none; see `tabStopIndex`.
            tabIndex={i === tabStopIndex ? 0 : -1}
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
