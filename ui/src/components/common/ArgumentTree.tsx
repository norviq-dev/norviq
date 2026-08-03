// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import type { CSSProperties } from "react";
import { schemaPaths, type SchemaPath } from "../../lib/toolSchema";

/**
 * A tool's arguments, and — for each — whether a policy can actually address it.
 *
 * This is the component the whole redesign turns on. Norviq's claim is that an allowlist of tool NAMES
 * is not a security control; the control is scoping a tool's ARGUMENTS. Until an operator can see the
 * arguments, that capability may as well not exist.
 *
 * TWO RULES, both of which are easy to get backwards.
 *
 * 1. NEVER HIDE A NON-ADDRESSABLE ARGUMENT. Omitting one teaches the operator the argument does not
 *    exist, which is the capability-fragment bug wearing different clothes — the old builder suggested
 *    names that could not exist; hiding these would conceal names that do. Show them disabled, with the
 *    reason rendered verbatim.
 *
 * 2. THE REASON IS THE POINT. `SchemaPath.note` explains why an argument cannot be used
 *    ("integer arguments never appear in param_paths — only text does"). Without it the row is just a
 *    greyed-out mystery, and an operator will reasonably conclude the product is broken. It is rendered
 *    in the accessible name too, so it is not a sighted-only affordance.
 *
 * Why type matters at all, since it looks like pedantry: the evaluator records STRING leaves only. A
 * policy written against a numeric argument compiles fine and then compares against `""` forever — a
 * permanent block inside a deny-by-default grant, and a rule that never fires in tighten-only mode.
 * Offering it would be offering a control that silently cannot work.
 *
 * BRANCH NODES ARE SYNTHESISED HERE. `schemaPaths()` emits leaves only — `{filters:{customer}}` yields
 * `filters.customer` and never `filters` — and that is deliberate, pinned by its tests, because the
 * compiler consumes the same list and an intermediate object is not an addressable path. A *tree* still
 * needs the branch to hang children from, so this component derives it from the dotted path rather than
 * changing a contract the compiler depends on.
 */
export interface ArgumentTreeProps {
  /** A tool's `input_schema` from the registry. */
  schema: unknown;
  /** Called with the dotted path when an addressable row is chosen. Omit for a read-only tree. */
  onPick?: (path: SchemaPath) => void;
  /** Dotted paths already used, rendered as `already used` and not re-pickable. */
  used?: string[];
  /**
   * Suppress every `description`.
   *
   * Set this when the tool's `description_withheld` is true. The API nulls the tool-level description
   * when the definition scanner condemns it, but ships `input_schema` whole — it has to, since paths,
   * types and enums all come from it. So the schema's own property descriptions carry the same
   * attacker-authored provenance and the same scanner findings point at them
   * (`inputSchema.properties.*.description`). Honouring the withholding is the renderer's job.
   */
  suppressDescriptions?: boolean;
  emptyLabel?: string;
}

interface TreeRow {
  path: string;
  /** The last dotted segment — what the row displays. */
  leaf: string;
  depth: number;
  /** Absent on a synthesised branch node. */
  spec?: SchemaPath;
}

/**
 * Leaves in, rows out — with the intermediate objects put back.
 *
 * Order is preserved from `schemaPaths` (schema declaration order), and a branch appears immediately
 * before its first child so the tree reads top-down.
 */
export function toTreeRows(paths: SchemaPath[]): TreeRow[] {
  const rows: TreeRow[] = [];
  const emitted = new Set<string>();
  for (const spec of paths) {
    const segments = spec.path.split(".");
    for (let i = 0; i < segments.length - 1; i++) {
      const branch = segments.slice(0, i + 1).join(".");
      if (emitted.has(branch)) continue;
      emitted.add(branch);
      rows.push({ path: branch, leaf: segments[i], depth: i });
    }
    emitted.add(spec.path);
    rows.push({ path: spec.path, leaf: segments[segments.length - 1], depth: segments.length - 1, spec });
  }
  return rows;
}

const PILL_ADDRESSABLE: CSSProperties = { background: "#00e5a015", color: "#00e5a0", borderColor: "#00e5a030" };
const PILL_DISABLED: CSSProperties = { background: "var(--bg-surface)", color: "var(--text-muted)", borderColor: "var(--border)" };

export function ArgumentTree({
  schema,
  onPick,
  used = [],
  suppressDescriptions = false,
  emptyLabel = "This tool declares no arguments."
}: ArgumentTreeProps) {
  const rows = toTreeRows(schemaPaths(schema));
  const usedSet = new Set(used);

  if (rows.length === 0) {
    return (
      <div data-testid="argument-tree-empty" className="muted" style={{ fontSize: 12.5 }}>
        {emptyLabel}
      </div>
    );
  }

  return (
    <div role="tree" aria-label="Arguments a policy can address" data-testid="argument-tree"
         style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {rows.map((row) => {
        const spec = row.spec;
        const isBranch = !spec;
        const addressable = !!spec?.addressable;
        const alreadyUsed = usedSet.has(row.path);
        const pickable = addressable && !alreadyUsed && !!onPick;
        const note = spec?.note;

        return (
          <div
            key={row.path}
            role="treeitem"
            aria-level={row.depth + 1}
            // `aria-disabled`, never the `disabled` attribute: a disabled option drops out of the
            // accessibility tree entirely, and a skipped option teaches exactly the thing rule 1 above
            // exists to prevent — that the argument does not exist.
            aria-disabled={isBranch || !addressable || alreadyUsed ? true : undefined}
            aria-label={note ? `${row.path}, ${note}` : row.path}
            data-testid={`argument-row-${row.path}`}
            tabIndex={pickable ? 0 : -1}
            onClick={pickable ? () => onPick(spec) : undefined}
            onKeyDown={
              pickable
                ? (e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onPick(spec);
                    }
                  }
                : undefined
            }
            style={{
              padding: row.depth > 0 ? "9px 11px 9px 22px" : "9px 11px",
              marginLeft: row.depth > 1 ? (row.depth - 1) * 14 : 0,
              position: "relative",
              borderRadius: 10,
              border: "1px solid var(--border)",
              background: addressable && !isBranch ? "var(--bg-elevated)" : "var(--bg-surface-hover)",
              cursor: pickable ? "pointer" : "default"
            }}
          >
            {row.depth > 0 && (
              // The elbow that makes nesting legible without an indent guide per level.
              <span
                aria-hidden
                style={{
                  position: "absolute", left: 11, top: 13, width: 5, height: 5,
                  borderLeft: "1px solid var(--border-active)", borderBottom: "1px solid var(--border-active)"
                }}
              />
            )}
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span className="mono" style={{ fontSize: 13, color: addressable && !isBranch ? "var(--text-primary)" : "var(--text-muted)" }}>
                {row.leaf}
              </span>
              {spec?.required && (
                <span title="required" style={{ color: "var(--block)", fontSize: 13 }}>*</span>
              )}
              <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>{isBranch ? "object" : spec?.type}</span>
              <span style={{ flex: 1 }} />
              {alreadyUsed ? (
                <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>already used</span>
              ) : isBranch ? null : (
                <span className="pill" style={addressable ? PILL_ADDRESSABLE : PILL_DISABLED}>
                  {addressable ? "Addressable" : "Not addressable"}
                </span>
              )}
            </div>
            {note && (
              <div style={{ marginTop: 4, fontSize: 12, lineHeight: 1.45, color: "var(--text-muted)" }}>{note}</div>
            )}
            {!suppressDescriptions && spec?.description && (
              <div style={{ marginTop: 4, fontSize: 12, color: "var(--text-muted)" }}>{spec.description}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}
