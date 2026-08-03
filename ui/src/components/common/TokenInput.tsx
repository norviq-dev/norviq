// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useState, type CSSProperties, type KeyboardEvent } from "react";

/**
 * A list of values as discrete removable tokens, rather than a comma-separated string.
 *
 * WHY THIS REPLACES A TEXT BOX. Every value list in the builder today is free text split on commas, and
 * that shape hides three failure modes an operator cannot see:
 *
 *   - trailing and interior whitespace becomes part of the value, so `secret, pci` silently yields
 *     `" pci"` and the policy stops matching what the author meant;
 *   - a duplicate is invisible in a long line and compiles to a set that quietly de-duplicates;
 *   - an empty element from a trailing comma produces `""`, which in a `noneOf` is a member that can
 *     never match and in a `subsetOf` is a value the operator never wrote.
 *
 * Tokenising makes each value a thing you can see and delete. The component normalises on commit —
 * trims, drops blanks, refuses duplicates — so the compiler never receives the artefacts above.
 *
 * COMMA IS A COMMIT KEY, not a character. Operators paste comma-separated lists out of habit and out of
 * existing policies, so a paste of `secret, pci, pii` must become three tokens rather than one.
 */
export interface TokenInputProps {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  /**
   * Surface the control sits on. The scope panel puts it on `--bg-surface`, so the field is
   * `--bg-elevated`; the rules-mode clause band is already `--bg-elevated`, so the field steps one
   * darker to stay legible as a distinct control rather than melting into its container.
   */
  surface?: "default" | "sunken";
  /** Text of the trailing add affordance, e.g. `+ value` or `+ tool`. */
  addLabel?: string;
  ariaLabel: string;
  "data-testid"?: string;
}

export function TokenInput({
  values,
  onChange,
  placeholder = "",
  surface = "default",
  addLabel = "+ value",
  ariaLabel,
  "data-testid": testId
}: TokenInputProps) {
  const [draft, setDraft] = useState("");

  const commit = (raw: string) => {
    const fresh = raw
      .split(",")
      .map((v) => v.trim())
      .filter((v) => v !== "" && !values.includes(v));
    if (fresh.length) onChange([...values, ...fresh]);
    setDraft("");
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      commit(draft);
      return;
    }
    // Backspace on an empty draft removes the last token — the standard chip-input affordance, and the
    // only way to correct a mistake without reaching for the mouse.
    if (e.key === "Backspace" && draft === "" && values.length > 0) {
      e.preventDefault();
      onChange(values.slice(0, -1));
    }
  };

  const shell: CSSProperties = {
    flex: "1 1 190px",
    minWidth: 150,
    display: "flex",
    alignItems: "center",
    gap: 6,
    flexWrap: "wrap",
    minHeight: 32,
    padding: "4px 8px",
    borderRadius: 10,
    background: surface === "sunken" ? "var(--bg-surface)" : "var(--bg-elevated)",
    border: "1px solid var(--border)"
  };

  return (
    <div style={shell} data-testid={testId}>
      {values.map((v) => (
        <span
          key={v}
          data-testid={testId ? `${testId}-token-${v}` : undefined}
          className="mono"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 5,
            padding: "3px 8px",
            borderRadius: 4,
            background: surface === "sunken" ? "var(--bg-void)" : "var(--bg-surface)",
            border: "1px solid var(--border)",
            fontSize: 12
          }}
        >
          {v}
          <button
            type="button"
            aria-label={`Remove ${v}`}
            onClick={() => onChange(values.filter((x) => x !== v))}
            style={{
              border: "none",
              background: "transparent",
              color: "var(--text-faint)",
              cursor: "pointer",
              padding: 0,
              lineHeight: 1,
              fontSize: 13
            }}
          >
            ×
          </button>
        </span>
      ))}
      <input
        aria-label={ariaLabel}
        data-testid={testId ? `${testId}-draft` : undefined}
        value={draft}
        placeholder={values.length === 0 ? placeholder : ""}
        onChange={(e) => {
          // A pasted list arrives as one change event containing commas — split it here rather than
          // waiting for a keystroke that will never come.
          if (e.target.value.includes(",")) commit(e.target.value);
          else setDraft(e.target.value);
        }}
        onKeyDown={onKeyDown}
        // Committing on blur stops a typed-but-unconfirmed value from vanishing when the operator
        // clicks Save — losing a restriction silently is the failure this whole workstream is about.
        onBlur={() => commit(draft)}
        style={{
          flex: "1 1 60px",
          minWidth: 60,
          border: "none",
          outline: "none",
          background: "transparent",
          color: "var(--text-primary)",
          fontFamily: "var(--font-mono)",
          fontSize: 13
        }}
      />
      {draft === "" && (
        <span aria-hidden style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {addLabel}
        </span>
      )}
    </div>
  );
}
