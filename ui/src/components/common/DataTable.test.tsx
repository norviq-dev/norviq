// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The quick filter must not return a row that contradicts what was typed.
 *
 * DataTable is a shared primitive — Audit Log, Agent Monitor and both MCP Servers tables all render it
 * — so a filter that matches invisible text is wrong on every one of them at once. The Audit Log is the
 * sharpest case because its records carry fields that are neither columns nor product-authored:
 * `reason` (engine prose that contains the word "block" on ALLOW rows), `tool_params` (the agent's own
 * call arguments) and `mcp.server`. The old haystack was `JSON.stringify(row)`, which searched all of
 * them plus every JSON KEY NAME.
 *
 * The fixture below is deliberately AuditLog-shaped: same columns (AuditLog.tsx:314-344), same record
 * fields (AuditLog.tsx:21-55), including the two attacker-controlled ones.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { DataTable, type Column } from "./DataTable";

type AuditRow = Record<string, unknown> & {
  id: string;
  timestamp: string;
  tool_name: string;
  decision: string;
  rule_id: string;
  agent_class: string;
  framework: string;
  latency_ms: number;
  session_id: string;
  reason: string;
  tool_params: Record<string, unknown>;
  mcp: { server: string } | null;
};

const COLUMNS: Array<Column<AuditRow>> = [
  { key: "timestamp", title: "Time" },
  { key: "tool_name", title: "Tool" },
  { key: "decision", title: "Decision", render: (v) => <span>{String(v).toUpperCase()}</span> },
  { key: "rule_id", title: "Rule" },
  { key: "agent_class", title: "Agent Class" },
  { key: "framework", title: "Source" },
  { key: "latency_ms", title: "Latency" }
];

const ALLOWED: AuditRow = {
  id: "a-1",
  timestamp: "2026-08-02T05:31:52Z",
  tool_name: "send_email",
  decision: "allow",
  rule_id: "R-1",
  agent_class: "mailer",
  framework: "sidecar",
  latency_ms: 12,
  session_id: "s-1",
  // Engine prose, not a column. Contains the word an operator types to find BLOCKED calls.
  reason: "no block rule matched",
  tool_params: { to: "ops@example.com" },
  mcp: null
};

const BLOCKED: AuditRow = {
  id: "a-2",
  timestamp: "2026-08-02T05:32:10Z",
  tool_name: "http_get",
  decision: "block",
  rule_id: "R-2",
  agent_class: "scraper",
  framework: "sidecar",
  latency_ms: 40,
  session_id: "s-2",
  reason: "denied by R-2",
  tool_params: { url: "https://evil.test" },
  mcp: { server: "web-tools" }
};

const bodyRowKeys = () =>
  Array.from(document.querySelectorAll("tbody tr[data-row-key]")).map((tr) => tr.getAttribute("data-row-key"));

const renderTable = (rows: AuditRow[] = [ALLOWED, BLOCKED], extra: Record<string, unknown> = {}) =>
  render(<DataTable<AuditRow> columns={COLUMNS} rows={rows} rowKey="id" placeholder="Quick filter rows…" {...extra} />);

const type = async (user: ReturnType<typeof userEvent.setup>, text: string) => {
  const box = screen.getByPlaceholderText("Quick filter rows…");
  await user.clear(box);
  await user.type(box, text);
};

describe("DataTable quick filter — only what the table actually shows", () => {
  it("does not return an ALLOW row for the query 'block'", async () => {
    // The lie that started this: `reason` says "no block rule matched" on an allowed call, so the
    // operator filtering for blocked traffic got back a row whose Decision cell reads ALLOW.
    const user = userEvent.setup();
    renderTable();
    await type(user, "block");
    expect(bodyRowKeys()).toEqual(["a-2"]);
    expect(screen.queryByText("ALLOW")).not.toBeInTheDocument();
  });

  it("does not match JSON key names, so a field name is not a match-everything query", async () => {
    // `JSON.stringify` serialises keys: typing any field name returned EVERY row, and "mcp" matched a
    // row whose mcp is null — i.e. the exact rows that are NOT MCP-sourced.
    const user = userEvent.setup();
    renderTable();
    // ("id" is deliberately absent: "sidecar" genuinely contains it, and a substring of VISIBLE text is
    // a legitimate match — the defect was matching text no cell shows.)
    for (const fieldName of ["session", "reason", "params", "latency", "framework", "mcp", "decision", "timestamp"]) {
      await type(user, fieldName);
      expect(bodyRowKeys(), `"${fieldName}" is a key name, not visible text`).toEqual([]);
    }
  });

  it("cannot be steered by an agent's own call arguments", async () => {
    // tool_params and mcp.server are attacker-controlled and are not columns. A hostile agent naming a
    // parameter after whatever an operator filters for must not surface its calls.
    const user = userEvent.setup();
    const hostile: AuditRow = {
      ...ALLOWED,
      id: "a-3",
      tool_name: "exfil",
      tool_params: { note: "scraper mailer http_get R-2 block" },
      mcp: { server: "scraper" }
    };
    renderTable([ALLOWED, BLOCKED, hostile]);
    await type(user, "scraper");
    expect(bodyRowKeys()).toEqual(["a-2"]); // the real scraper row, by its Agent Class cell
  });

  it("still finds rows by every visible column, including numbers", async () => {
    const user = userEvent.setup();
    renderTable();
    await type(user, "http_get");
    expect(bodyRowKeys()).toEqual(["a-2"]);
    await type(user, "MAILER"); // case-insensitive
    expect(bodyRowKeys()).toEqual(["a-1"]);
    await type(user, "40");
    expect(bodyRowKeys()).toEqual(["a-2"]);
    await type(user, "sidecar");
    expect(bodyRowKeys()).toEqual(["a-1", "a-2"]);
  });

  it("lets a caller opt a formatted or nested value back in, explicitly", async () => {
    // The escape hatch for a cell whose `render` shows something the field does not literally contain.
    const user = userEvent.setup();
    const columns: Array<Column<AuditRow>> = [
      ...COLUMNS,
      {
        key: "mcp",
        title: "MCP server",
        render: (v) => <span>{(v as AuditRow["mcp"])?.server ?? "—"}</span>,
        filterText: (r) => r.mcp?.server ?? ""
      }
    ];
    render(<DataTable<AuditRow> columns={columns} rows={[ALLOWED, BLOCKED]} rowKey="id" placeholder="Quick filter rows…" />);
    await type(user, "web-tools");
    expect(bodyRowKeys()).toEqual(["a-2"]);
  });

  it("does not render '[object Object]' as searchable text for an object column with no accessor", async () => {
    const user = userEvent.setup();
    const columns: Array<Column<AuditRow>> = [...COLUMNS, { key: "tool_params", title: "Params", render: () => <span>…</span> }];
    render(<DataTable<AuditRow> columns={columns} rows={[ALLOWED, BLOCKED]} rowKey="id" placeholder="Quick filter rows…" />);
    await type(user, "object");
    expect(bodyRowKeys()).toEqual([]);
  });

  it("says so when the filter matched nothing, instead of a header over an empty body", async () => {
    // The caller's own no-results panel covers the SERVER-side empty case only (AuditLog.tsx:404-415).
    // Without this the operator cannot tell "your term matched no row" from "there is nothing here".
    //
    // The flat "No rows match X" wording this used to assert was itself a claim the code cannot make
    // whenever a column renders a custom cell — see the describe block below — so it is asserted here
    // only for a table where it IS true: every column plain, nothing unread.
    const user = userEvent.setup();
    render(
      <DataTable<AuditRow>
        columns={[{ key: "tool_name", title: "Tool" }, { key: "agent_class", title: "Agent Class" }]}
        rows={[ALLOWED, BLOCKED]}
        rowKey="id"
        placeholder="Quick filter rows…"
      />
    );
    await type(user, "zzz-nothing");
    const note = screen.getByTestId("table-no-matches");
    expect(note).toHaveTextContent("No rows match “zzz-nothing”");
    expect(note).toHaveTextContent("all 2 loaded rows");
    expect(bodyRowKeys()).toEqual([]);
    // Nothing to hedge about, so no hedge.
    expect(screen.queryByTestId("table-filter-scope")).not.toBeInTheDocument();
  });

  it("keeps the no-matches note out of the way when rows are showing, or when there are no rows at all", async () => {
    const user = userEvent.setup();
    const { unmount } = renderTable();
    expect(screen.queryByTestId("table-no-matches")).not.toBeInTheDocument();
    await type(user, "http_get");
    expect(screen.queryByTestId("table-no-matches")).not.toBeInTheDocument();
    unmount();

    // Zero rows from the server is the caller's story to tell, not ours — we must not overwrite it.
    renderTable([]);
    await type(userEvent.setup(), "anything");
    expect(screen.queryByTestId("table-no-matches")).not.toBeInTheDocument();
  });
});

/**
 * Narrowing the haystack to the columns fixed the false POSITIVE and created a false NEGATIVE, then put
 * a confident sentence on top of it.
 *
 * What a cell displays is a ReactNode from `render`, which the filter cannot read back — so it matches
 * the value BEHIND the cell. On MCP Servers `health: "quarantined"` is displayed as the pill “awaiting
 * approval” (McpServers.tsx:87-92); on the Audit Log `trust_score: 0.31` is displayed as the badge “low”
 * (AuditLog.tsx:410-414). Type the word you are reading off the screen and every one of those rows
 * disappears — under “No rows match “awaiting”. Clearing the filter shows all 6 loaded rows.”
 *
 * That sentence is a measurement the code never made, on the screen whose job is to let someone decide
 * whether anything is awaiting approval. It cannot be made true without rendering every cell to text, so
 * it is made HONEST instead: the filter names the columns it could not read.
 */
describe("DataTable quick filter — it must not deny what it never searched", () => {
  // McpServers.tsx:87-92 verbatim: the field is a code, the cell is a phrase, and they share no letters.
  const HEALTH_LABEL: Record<string, string> = { quarantined: "awaiting approval", ok: "healthy" };
  const withStatus: Array<Column<AuditRow>> = [
    { key: "tool_name", title: "Tool" },
    { key: "agent_class", title: "Agent Class" },
    { key: "health", title: "Status", render: (v) => <span>{HEALTH_LABEL[String(v)]}</span> },
    { key: "trust_score", title: "Trust", render: (v) => <span>{Number(v) >= 0.7 ? "high" : "low"}</span> }
  ];
  const SERVERS: AuditRow[] = [
    { ...ALLOWED, id: "s-a", health: "quarantined", trust_score: 0.31 },
    { ...BLOCKED, id: "s-b", health: "ok", trust_score: 0.9 }
  ];
  const renderServers = () =>
    render(<DataTable<AuditRow> columns={withStatus} rows={SERVERS} rowKey="id" placeholder="Quick filter rows…" />);

  it("the word on the screen really is unsearchable — the premise of everything below", async () => {
    const user = userEvent.setup();
    renderServers();
    expect(screen.getByText("awaiting approval")).toBeInTheDocument();
    await type(user, "awaiting");
    expect(bodyRowKeys(), "the row displaying the term is filtered out").toEqual([]);
  });

  it("does not report a bare 'No rows match' for a term it could not look for", async () => {
    const user = userEvent.setup();
    renderServers();
    await type(user, "awaiting");
    const note = screen.getByTestId("table-no-matches");
    // The claim has to be scoped to what was actually searched...
    expect(note).toHaveTextContent("No match for “awaiting” in the values this filter reads");
    expect(note.textContent).not.toMatch(/No rows match/);
    // ...it has to name the columns it could not read...
    expect(note).toHaveTextContent("Status");
    expect(note).toHaveTextContent("Trust");
    // ...and it has to say what that means for the operator staring at an empty table.
    expect(note).toHaveTextContent("a row displaying “awaiting” there is hidden too");
    expect(note).toHaveTextContent("all 2 loaded rows");
  });

  it("warns while the filter is active even when some rows DID come back", async () => {
    // The quieter half of the same lie. `high` matches nothing, `s-b` shows it, and the operator reads
    // the one row that came back on another column as the complete answer.
    const user = userEvent.setup();
    renderServers();
    await type(user, "scraper"); // matches s-b by Agent Class
    expect(bodyRowKeys()).toEqual(["s-b"]);
    expect(screen.queryByTestId("table-no-matches")).not.toBeInTheDocument();
    const scope = screen.getByTestId("table-filter-scope");
    expect(scope).toHaveTextContent("Matching the value behind each cell");
    expect(scope).toHaveTextContent("Status and Trust");
    expect(scope).toHaveTextContent("the text shown there is not searched");
  });

  it("keeps the caveat off the screen until there is a filter to caveat", async () => {
    const user = userEvent.setup();
    renderServers();
    expect(screen.queryByTestId("table-filter-scope")).not.toBeInTheDocument();
    await type(user, "scraper");
    expect(screen.getByTestId("table-filter-scope")).toBeInTheDocument();
    const box = screen.getByPlaceholderText("Quick filter rows…");
    await user.clear(box);
    expect(screen.queryByTestId("table-filter-scope")).not.toBeInTheDocument();
  });

  it("stops hedging about a column the moment the caller says what it shows", async () => {
    // `filterText` is both the fix and the retraction: supply it and the column is searched by its
    // displayed text AND drops off the unread list. Nothing else can take it off that list.
    const user = userEvent.setup();
    const columns = withStatus.map((c) =>
      c.key === "health" ? { ...c, filterText: (r: AuditRow) => HEALTH_LABEL[String(r.health)] ?? "" } : c
    );
    render(<DataTable<AuditRow> columns={columns} rows={SERVERS} rowKey="id" placeholder="Quick filter rows…" />);
    await type(user, "awaiting");
    expect(bodyRowKeys()).toEqual(["s-a"]);
    expect(screen.getByTestId("table-filter-scope")).toHaveTextContent("Trust");
    expect(screen.getByTestId("table-filter-scope").textContent).not.toMatch(/Status/);
  });

  it("keeps the list to one line however many columns it cannot read", async () => {
    const user = userEvent.setup();
    const many: Array<Column<AuditRow>> = [
      { key: "tool_name", title: "Tool" },
      ...["Time", "Decision", "Rule", "Source", "Latency"].map((title, i) => ({
        key: ["timestamp", "decision", "rule_id", "framework", "latency_ms"][i] as keyof AuditRow & string,
        title,
        render: () => <span>·</span>
      }))
    ];
    render(<DataTable<AuditRow> columns={many} rows={SERVERS} rowKey="id" placeholder="Quick filter rows…" />);
    await type(user, "zzz");
    expect(screen.getByTestId("table-no-matches")).toHaveTextContent("Time, Decision and 3 more");
  });
});

describe("DataTable — the rest of the contract this primitive owes every page", () => {
  it("marks a row clickable only when a handler exists, since .tbl sets cursor:pointer on all rows", async () => {
    const user = userEvent.setup();
    const onRowClick = vi.fn();
    const { unmount } = renderTable([ALLOWED], { onRowClick });
    const row = document.querySelector("tbody tr[data-row-key='a-1']")!;
    expect(row.className).toContain("row-clickable");
    await user.click(row);
    expect(onRowClick).toHaveBeenCalledWith(ALLOWED);
    unmount();

    renderTable([ALLOWED]);
    expect(document.querySelector("tbody tr[data-row-key='a-1']")!.className).not.toContain("row-clickable");
  });

  it("supports a composite rowKey, which is what makes an MCP pin's highlight reachable", () => {
    // Two servers serving one `read_file`: keyed on tool_name alone the rows collide and selectedKey
    // ("server/tool") can never equal the row key, so the selection is unreachable.
    type Pin = Record<string, unknown> & { server_id: string; tool_name: string };
    const pins: Pin[] = [
      { server_id: "web", tool_name: "read_file" },
      { server_id: "fs", tool_name: "read_file" }
    ];
    render(
      <DataTable<Pin>
        columns={[{ key: "server_id", title: "Server" }, { key: "tool_name", title: "Tool" }]}
        rows={pins}
        rowKey={(r) => `${r.server_id}/${r.tool_name}`}
        selectedKey="fs/read_file"
        onRowClick={() => {}}
      />
    );
    const selected = document.querySelectorAll("tbody tr.selected");
    expect(selected).toHaveLength(1);
    expect(within(selected[0] as HTMLElement).getByText("fs")).toBeInTheDocument();
  });

  it("renders a missing cell value as an em dash rather than the word 'null'", () => {
    render(
      <DataTable<AuditRow>
        columns={[{ key: "rule_id", title: "Rule" }]}
        rows={[{ ...ALLOWED, rule_id: null as unknown as string }]}
        rowKey="id"
      />
    );
    expect(screen.getByRole("cell")).toHaveTextContent("—");
  });
});
