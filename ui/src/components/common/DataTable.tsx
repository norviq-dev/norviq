// DataTable — a small generic table: typed Column<T> config (custom cell render + responsive
// hide-at-breakpoint columns), an optional client-side text filter over the COLUMNS THE TABLE SHOWS,
// and row selection/click. No sorting or paging — callers supply already-ordered rows.

import { CSSProperties, ReactNode, useMemo, useState } from "react";

export type Column<T> = {
  key: keyof T & string;
  title: string;
  render?: (value: T[keyof T], row: T) => ReactNode;
  thStyle?: CSSProperties;
  tdStyle?: CSSProperties;
  thTitle?: string;
  thClassName?: string;
  tdClassName?: string;
  /**
   * Text this column contributes to the quick filter, when the raw field value is not what the cell
   * shows (a `render` that formats, or a field holding an object). Default: the field value itself,
   * stringified, and nothing at all for a non-primitive.
   *
   * This is the ONLY way to make a value searchable that is not the column's own field — deliberately,
   * so that a caller has to state the intent. See `cellFilterText` for why.
   *
   * Supplying it ALSO tells the table it may stop hedging about this column: a column with a `render`
   * and no `filterText` is one whose displayed text the filter provably cannot read, and the filter
   * says so out loud rather than reporting a confident zero. Pass `filterText` — even the identity
   * `(r) => String(r.field)` when the cell shows the field verbatim — to take the column off that list.
   */
  filterText?: (row: T) => string;
};

/**
 * Columns whose ON-SCREEN text this filter cannot read.
 *
 * A `render` may turn `health: "quarantined"` into the pill “awaiting approval” (McpServers.tsx:87-92)
 * or `trust_score: 0.31` into the badge “low” (AuditLog.tsx:410-414). The haystack is the value BEHIND
 * the cell, so those words are unsearchable — and the table has no way to read a ReactNode back into
 * text, so it cannot quietly fix it. What it must not do is hide the gap: an operator who types a word
 * they are literally reading off the screen and is told “No rows match” has been given a measurement
 * the code never made. Naming the columns turns a false denial into a true, actionable one.
 */
function opaqueColumnTitles<T extends Record<string, unknown>>(columns: Array<Column<T>>): string[] {
  return columns.filter((c) => c.render && !c.filterText).map((c) => c.title);
}

/** "Status", "Status and Trust", "Status, Trust and 4 more" — kept to one line whatever the column count. */
function namedList(titles: string[]): string {
  if (titles.length <= 2) return titles.join(" and ");
  return `${titles.slice(0, 2).join(", ")} and ${titles.length - 2} more`;
}

/**
 * What one cell contributes to the quick-filter haystack.
 *
 * It used to be `JSON.stringify(row)`, i.e. every field of the record plus every KEY NAME. That made
 * the filter lie in two directions on the Audit Log. Typing `block` returned rows whose visible
 * Decision badge said ALLOW, because the invisible `reason` field said "no block rule matched" — the
 * operator is looking at a row that contradicts the term they typed. And typing any field name at all
 * (`session`, `reason`, `params`, `mcp`) returned EVERY row, because `JSON.stringify` serialises keys:
 * `"mcp"` matched rows whose `mcp` is null.
 *
 * Worse, the invisible half of the haystack is attacker-controlled. An audit record carries
 * `tool_params` — the agent's own call arguments — and `mcp.server`; neither is a column, so a hostile
 * agent could name a parameter after whatever an operator was about to filter for and surface its own
 * calls in the result. Restricting the haystack to the columns closes that: nothing an agent writes
 * reaches the filter unless a column puts it on screen.
 *
 * It does NOT make the filter a search of what is on screen, and the empty state must not imply that it
 * is. What a cell DISPLAYS is a ReactNode produced by `render`, which this cannot read back — so the
 * match is on the value behind the cell. Where the two differ (`health: "quarantined"` shown as
 * “awaiting approval”), a term the operator can see matches nothing. That is why the columns this
 * cannot read are named in the filter's own copy; see `opaqueColumnTitles`.
 */
function cellFilterText<T extends Record<string, unknown>>(column: Column<T>, row: T): string {
  if (column.filterText) return column.filterText(row);
  const value = row[column.key];
  if (value == null) return "";
  // Objects and arrays are stringified by their `render`, if at all; `[object Object]` is not text an
  // operator can see, and JSON of them is how the key-name match got in. Callers pass `filterText`.
  if (typeof value === "object") return "";
  return String(value);
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  rows,
  onRowClick,
  selectedKey,
  rowKey,
  filterable = true,
  placeholder = "Filter rows…"
}: {
  columns: Array<Column<T>>;
  rows: T[];
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  /**
   * How to identify a row. A field name works when one field is unique; a function is required when
   * identity is COMPOSITE — MCP pins are keyed `(namespace, server_id, tool_name)`, so two servers
   * serving one `read_file` collided under `rowKey="tool_name"`: React saw duplicate keys, and
   * `selectedKey` (a `server/tool` string) could never equal `row.tool_name`, so the highlight was
   * unreachable. The type is what made the bug possible; widening it is the actual fix.
   */
  rowKey?: (keyof T & string) | ((row: T) => string);
  filterable?: boolean;
  placeholder?: string;
}) {
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (!needle) return rows;
    return rows.filter((row) =>
      columns.some((c) => cellFilterText(c, row).toLowerCase().includes(needle))
    );
  }, [needle, rows, columns]);
  // Filtered everything away. Saying so matters more here than in most tables: a header row over an
  // empty body reads as "nothing exists", and the operator cannot tell it apart from a table that
  // legitimately has no rows. The callers' own empty states cover the SERVER-side case only.
  const filteredEmpty = needle !== "" && filtered.length === 0 && rows.length > 0;
  // …but "no rows match" is itself a measurement, and it is only true of the columns this can read.
  // With any custom-rendered column in play the honest claim is narrower, and the difference is not
  // pedantry: it is the difference between "there are no calls awaiting approval" and "I did not look
  // at the words in that cell".
  const unreadable = useMemo(() => opaqueColumnTitles(columns), [columns]);

  return (
    <div className="panel" style={{ paddingBottom: 6 }}>
      {filterable && (
        <div className="tbl-toolbar">
          <input
            className="input"
            placeholder={placeholder}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {/* Shown while a filter is active, whether or not it matched. A result set that is SHORT for
              the same reason an empty one is empty is the quieter half of the same lie — the operator
              reads the rows that came back as "all of them". */}
          {needle !== "" && unreadable.length > 0 && (
            <span
              data-testid="table-filter-scope"
              style={{ display: "block", marginTop: 6, fontSize: 12, color: "var(--text-muted)", lineHeight: 1.5 }}
            >
              Matching the value behind each cell. {namedList(unreadable)}{" "}
              {unreadable.length === 1 ? "renders a custom cell" : "render custom cells"}, so the text shown there is
              not searched.
            </span>
          )}
        </div>
      )}
      <div style={{ overflowX: "auto", marginTop: filterable ? 12 : 0 }}>
        <table className="tbl">
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c.key}
                  style={c.thStyle}
                  title={c.thTitle}
                  className={`${c.thClassName ?? ""}${c.key === "session_id" ? " hide-laptop" : ""}${
                    c.key === "latency_ms" ? " hide-tablet" : ""
                  }`}
                >
                  {c.title}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredEmpty && (
              <tr data-testid="table-no-matches">
                <td
                  colSpan={columns.length}
                  style={{ padding: "22px 12px", textAlign: "center", color: "var(--text-secondary)", fontSize: 13 }}
                >
                  {unreadable.length === 0 ? (
                    <>No rows match “{query.trim()}”.</>
                  ) : (
                    <>
                      No match for “{query.trim()}” in the values this filter reads. {namedList(unreadable)}{" "}
                      {unreadable.length === 1 ? "renders a custom cell" : "render custom cells"}, so a row
                      displaying “{query.trim()}” there is hidden too.
                    </>
                  )}{" "}
                  Clearing the filter shows{" "}
                  {rows.length === 1 ? "the 1 loaded row" : `all ${rows.length} loaded rows`}.
                </td>
              </tr>
            )}
            {filtered.map((row, i) => {
              const key = rowKey
                ? typeof rowKey === "function"
                  ? rowKey(row)
                  : (row[rowKey] as unknown as string | number)
                : i;
              const isSelected = selectedKey != null && selectedKey === key;
              return (
                <tr
                  key={key}
                  // Only a row that DOES something may look like it does. `index.css` sets
                  // `cursor: pointer` on every `.tbl` row, so read-only tables invited a click that
                  // was never wired — the class is applied here, gated on the handler existing.
                  className={`${onRowClick ? "row-clickable" : ""}${isSelected ? " selected" : ""}`}
                  data-row-key={String(key)}
                  onClick={() => onRowClick && onRowClick(row)}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      style={c.tdStyle}
                      className={`${c.tdClassName ?? ""}${c.key === "session_id" ? " hide-laptop" : ""}${
                        c.key === "latency_ms" ? " hide-tablet" : ""
                      }`}
                    >
                      {c.render
                        ? c.render(row[c.key], row)
                        : row[c.key] != null
                        ? String(row[c.key])
                        : "—"}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
