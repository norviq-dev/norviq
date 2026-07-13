// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-46: small CSV export helper. The Dashboard "Export" button and the Report ▼ "Export CSV" item were both dead
// (no handler, and no CSV logic existed anywhere). This builds a CSV from a list of row objects and triggers a
// browser download — no dependency, RFC-4180 quoting.
//
// SEC-CSV-INJECTION: exported columns include attacker-influenceable strings (tool names, policy
// reason/rule_id, agent classes). A cell starting with = + - @ (or a leading tab/CR) is interpreted as
// a formula by Excel/Sheets when the file is opened — the standard mitigation is to prefix such cells
// with a single quote so the spreadsheet app treats them as literal text, applied BEFORE the existing
// RFC-4180 quote/escape logic so the two compose (a formula-lead cell that also needs RFC quoting, e.g.
// it contains a comma, still gets both).

/** Cells starting with one of these are formula/DDE injection vectors in Excel/Sheets. */
const FORMULA_INJECTION_LEAD = /^[=+\-@\t\r]/;

/** RFC-4180 quote: wrap in double-quotes and double any embedded quotes when the cell needs it. */
export function csvCell(value: unknown): string {
  let s = value == null ? "" : String(value);
  if (FORMULA_INJECTION_LEAD.test(s)) {
    s = `'${s}`; // neutralize: force Excel/Sheets to treat this as text, not a formula/DDE trigger
  }
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Serialize rows to a CSV string using the given ordered columns. */
export function toCsv<T extends Record<string, unknown>>(rows: T[], columns: Array<keyof T>): string {
  const header = columns.map((c) => csvCell(String(c))).join(",");
  const body = rows.map((r) => columns.map((c) => csvCell(r[c])).join(",")).join("\n");
  return body ? `${header}\n${body}` : header;
}

/** Trigger a client-side download of `content` as `filename` (no-op return of the blob URL for tests). */
export function downloadCsv(filename: string, content: string): string {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // revoke on the next tick so the click is processed first
  setTimeout(() => URL.revokeObjectURL(url), 0);
  return url;
}

/** Build + download a CSV from rows and ordered columns in one call. */
export function exportCsv<T extends Record<string, unknown>>(filename: string, rows: T[], columns: Array<keyof T>): void {
  downloadCsv(filename, toCsv(rows, columns));
}
