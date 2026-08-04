// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * One number with a label, and optionally the UNIT that number counts.
 *
 * `sub` exists because a bare count invites the reader to compare it with a count elsewhere that
 * happens to share a name. Propose from traffic showed "Rules: 2" while the Attack Graph showed three
 * paths for the same class in the same namespace, and both were correct: the proposer groups by
 * OPERATION (read → http_get + vector_search, send → send_email) and the graph counts by TOOL. Three
 * tools, two rules. Nothing on either screen said so, so the only available reading was that a tool
 * had been dropped — the more alarming of the two interpretations, and the wrong one.
 */
export function StatTile({
  label,
  value,
  color,
  sub
}: {
  label: string;
  value: number;
  color?: string;
  /** What the number counts, when the unit is not the one a reader would assume. */
  sub?: string;
}) {
  return (
    <div className="panel panel-pad">
      <div className="kpi-label">{label}</div>
      <div
        style={{
          fontSize: 24,
          fontWeight: 600,
          marginTop: 6,
          color: color || "var(--text-primary)",
          fontVariantNumeric: "tabular-nums"
        }}
      >
        {value.toLocaleString()}
      </div>
      {sub ? (
        <div style={{ fontSize: 11.5, lineHeight: 1.45, color: "var(--text-muted)", marginTop: 3 }}>{sub}</div>
      ) : null}
    </div>
  );
}
