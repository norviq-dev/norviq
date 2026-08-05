// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Choosing WHAT a condition is about.
 *
 * This replaces two `<select>` elements whose option lists were the only place the tool's own
 * arguments were ever named. A native select is the wrong instrument for the job in three ways that
 * matter here:
 *
 *   1. It cannot show a REASON. Non-addressable arguments (`retries: integer`, `attachments: array`)
 *      were rendered as disabled `<option>`s with the reason appended to the label and repeated in a
 *      `title` — a tooltip on a disabled option, which no browser shows. The operator saw a greyed
 *      line and no way to learn why.
 *   2. It cannot be SEARCHED. A tool with thirty arguments is a scroll.
 *   3. It collapses the moment you look away, so the two groups — this tool's own arguments, and what
 *      the call carries or reaches — could never be compared side by side, which is the one
 *      comparison that teaches the difference between them.
 *
 * WHY DISABLED OPTIONS STAY VISIBLE. Dropping an argument the schema declares teaches the operator it
 * does not exist. It does exist; it just cannot be addressed by `param_paths`, and that is a fact
 * about the engine worth knowing before you go looking for it again. They carry `aria-disabled`
 * rather than `disabled` so a screen reader can still reach them and read the reason.
 */

import { useMemo, useRef, useState } from "react";
import { Plus, Search, X } from "lucide-react";

export interface PickerOption {
  id: string;
  /** The thing itself — an argument path, or a fact's plain-English name. */
  label: string;
  /** Type or shape, shown muted beside the label (`string · nested`). */
  meta?: string;
  /** What it is for. Group 2 leans on this; group 1 rarely needs it. */
  hint?: string;
  /** Marked `*` — the schema lists it in `required`. */
  required?: boolean;
  /** Rendered, never hidden. `reason` is mandatory when this is true. */
  disabled?: boolean;
  reason?: string;
  /** Already on this grant. Still pickable — adding a second clause about one field is legitimate. */
  used?: boolean;
  /** OTHER NAMES THE REST OF THE PRODUCT PRINTS FOR THIS SAME THING. Searched, never displayed.
   *
   *  A declared argument is listed here as `to`, but picking it writes a fact on `param_paths.to`, and
   *  `param_paths.to` is what the scope chip and the compiled rego then show the operator. Matching only
   *  `id`/`label` meant the one string they had just been shown matched nothing, and the empty state
   *  told them the argument "was never declared" — about an argument out of the tool's own schema. */
  aliases?: string[];
}

export interface PickerGroup {
  key: string;
  label: string;
  /** `accent` = this tool's own arguments. `audit` = engine-derived facts about the whole call. */
  tone: "accent" | "audit";
  /** A line under the group heading — provenance, or why the group is empty. */
  sub?: string;
  options: PickerOption[];
}

export interface ConditionPickerProps {
  groups: PickerGroup[];
  onPick: (groupKey: string, optionId: string) => void;
  "data-testid"?: string;
}

const TONE = { accent: "var(--accent)", audit: "var(--audit)" } as const;

export function ConditionPicker({ groups, onPick, "data-testid": testId = "builder-condition-picker" }: ConditionPickerProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return groups;
    return groups
      .map((g) => ({
        group: g,
        options: g.options.filter(
          (o) =>
            // THE RAW NAME FIRST. `id` is the vocabulary the rest of the product speaks: the compiled
            // rego, `describeFact`, and therefore every scope-cell chip print `sql_tables` and
            // `destinations.emails`, while this list shows the friendly label ("SQL tables"). Searching
            // only the label meant the name the operator just read on a chip matched nothing, and the
            // empty state then told them it "was never declared" — the picker denying a control that is
            // two rows below the box they typed into.
            o.id.toLowerCase().includes(q) ||
            // ...and the names it is known by elsewhere: an argument's option id is the bare path, while
            // its chip and its rego line both read `param_paths.<path>`. Same defect as the line above,
            // one vocabulary along.
            (o.aliases ?? []).some((a) => a.toLowerCase().includes(q)) ||
            o.label.toLowerCase().includes(q) ||
            (o.meta ?? "").toLowerCase().includes(q) ||
            (o.hint ?? "").toLowerCase().includes(q)
        )
      }))
      // A group that matched nothing is dropped; a group that is empty to begin with keeps its `sub`,
      // because "this tool declares no arguments" is an answer the search should not swallow. That
      // second half has to be asked of the ORIGINAL group: the old `!g.options.length && !q` tested a
      // `q` that `if (!q) return groups` above has already guaranteed to be non-empty, so it was
      // constant-false and the explanation vanished on the first keystroke.
      .filter(({ group, options }) => options.length > 0 || group.options.length === 0)
      .map(({ group, options }) => ({ ...group, options }));
  }, [groups, query]);

  const nothingMatched = query.trim().length > 0 && filtered.every((g) => g.options.length === 0);

  if (!open) {
    return (
      <button
        type="button"
        className="btn btn-outline"
        data-testid={`${testId}-open`}
        onClick={() => {
          setOpen(true);
          setQuery("");
          // Focus the search on open — with thirty arguments, typing is the fastest path in, and the
          // keyboard user should not have to tab past the whole list to reach it.
          window.setTimeout(() => searchRef.current?.focus(), 0);
        }}
      >
        <Plus size={15} /> Add a condition
      </button>
    );
  }

  return (
    <div
      data-testid={testId}
      style={{
        maxWidth: 560,
        width: "100%",
        border: "1px solid var(--border-active)",
        borderRadius: 12,
        background: "var(--bg-elevated)",
        overflow: "hidden",
        boxShadow: "0 8px 24px rgba(0, 0, 0, 0.45)"
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 12px",
          borderBottom: "1px solid var(--border)"
        }}
      >
        <Search size={14} style={{ flex: "none", color: "var(--text-muted)" }} aria-hidden />
        <input
          ref={searchRef}
          data-testid={`${testId}-search`}
          className="input"
          aria-label="Search arguments and facts"
          placeholder="Search arguments and facts…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") setOpen(false);
          }}
          style={{ flex: 1, height: 30, fontSize: 13 }}
        />
        <button
          type="button"
          className="icon-btn"
          data-testid={`${testId}-close`}
          aria-label="Close the condition picker"
          onClick={() => setOpen(false)}
          style={{ width: 28, height: 28 }}
        >
          <X size={14} />
        </button>
      </div>

      <div role="listbox" aria-label="Conditions you can add" style={{ maxHeight: 340, overflowY: "auto" }}>
        {filtered.map((group, gi) => (
          <div key={group.key} style={{ borderTop: gi > 0 ? "1px solid var(--border)" : undefined }}>
            <div style={{ padding: gi > 0 ? "8px 12px 4px" : "10px 12px 4px" }}>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: ".07em",
                  textTransform: "uppercase",
                  color: TONE[group.tone]
                }}
              >
                {group.label}
              </div>
              {group.sub && (
                <div style={{ fontSize: 11.5, color: "var(--text-muted)", marginTop: 3 }}>{group.sub}</div>
              )}
            </div>

            <div style={{ padding: "4px 8px 8px", display: "flex", flexDirection: "column", gap: 2 }}>
              {group.options.map((o) => {
                const reasonId = o.disabled ? `${testId}-${o.id}-reason` : undefined;
                return (
                  <div
                    key={o.id}
                    role="option"
                    tabIndex={o.disabled ? -1 : 0}
                    aria-selected={false}
                    // `aria-disabled`, NOT `disabled`: a screen reader must still be able to land on
                    // this and hear why it cannot be used. `disabled` would remove it from the tree,
                    // which is the same as hiding it.
                    aria-disabled={o.disabled || undefined}
                    aria-describedby={reasonId}
                    data-testid={`${testId}-option-${o.id}`}
                    data-disabled={o.disabled ? "true" : undefined}
                    onClick={() => {
                      if (o.disabled) return;
                      onPick(group.key, o.id);
                      setOpen(false);
                    }}
                    onKeyDown={(e) => {
                      if (o.disabled) return;
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onPick(group.key, o.id);
                        setOpen(false);
                      }
                    }}
                    style={{
                      display: "flex",
                      alignItems: "baseline",
                      gap: 8,
                      flexWrap: "wrap",
                      padding: "8px 10px",
                      borderRadius: 9,
                      cursor: o.disabled ? "default" : "pointer",
                      background: o.disabled ? "var(--bg-surface-hover)" : undefined
                    }}
                  >
                    <span
                      className={group.tone === "accent" ? "mono" : undefined}
                      style={{ fontSize: 13, color: o.disabled ? "var(--text-muted)" : "var(--text-primary)" }}
                    >
                      {o.label}
                    </span>
                    {o.required && (
                      <span style={{ color: "var(--block)" }} title="Required by the tool's schema">
                        *
                      </span>
                    )}
                    {o.meta && (
                      <span style={{ fontSize: 11.5, color: o.disabled ? "var(--text-faint)" : "var(--text-muted)" }}>
                        {o.meta}
                      </span>
                    )}
                    {o.hint && <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{o.hint}</span>}
                    <span style={{ flex: 1 }} />
                    {o.used && !o.disabled && (
                      <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>already used</span>
                    )}
                    {o.disabled && o.reason && (
                      <div
                        id={reasonId}
                        style={{ flex: "1 1 100%", fontSize: 11.5, lineHeight: 1.5, color: "var(--text-muted)" }}
                      >
                        {o.reason}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {nothingMatched && (
          <div
            data-testid={`${testId}-empty`}
            style={{ padding: "14px 12px", fontSize: 12.5, color: "var(--text-muted)" }}
          >
            Nothing matches “{query.trim()}”. Argument paths come from the tool&rsquo;s declared schema —
            if the path you want is not listed, it was never declared, and you can still scope it with{" "}
            <span className="mono" style={{ color: "var(--text-secondary)" }}>any parameter value</span>.
          </div>
        )}
      </div>
    </div>
  );
}
