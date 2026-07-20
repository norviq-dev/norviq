// DataTable — a small generic table: typed Column<T> config (custom cell render + responsive
// hide-at-breakpoint columns), an optional client-side text filter across all fields, and row
// selection/click. No sorting or paging — callers supply already-ordered rows.

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
};

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
  rowKey?: keyof T & string;
  filterable?: boolean;
  placeholder?: string;
}) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    if (!query) return rows;
    const needle = query.toLowerCase();
    return rows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle));
  }, [query, rows]);

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
            {filtered.map((row, i) => {
              const key = rowKey ? (row[rowKey] as unknown as string | number) : i;
              const isSelected = selectedKey != null && selectedKey === key;
              return (
                <tr
                  key={key}
                  className={isSelected ? "selected" : ""}
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
