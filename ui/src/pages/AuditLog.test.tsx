// SPDX-License-Identifier: Apache-2.0
import { act, fireEvent, render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditLog } from "./AuditLog";
import { AppProvider } from "../store/AppContext";

// A socket that never opens → useWebSocket.connected stays false → AuditLog must poll.
class DisconnectedWS {
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  constructor(_url: string) {}
  close() {}
}

const server = setupServer();
let recordCalls = 0;

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => {
  recordCalls = 0;
  vi.stubGlobal("WebSocket", DisconnectedWS as unknown as typeof WebSocket);
  vi.useFakeTimers();
  server.use(
    http.get("/api/v1/audit/records", () => {
      recordCalls += 1;
      return HttpResponse.json([]);
    })
  );
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  server.resetHandlers();
});
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AuditLog />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("AuditLog live feed (#5)", () => {
  it("polls /audit/records on an interval when the socket is disconnected", async () => {
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200); // mount fetches + immediate poll
    });
    const initial = recordCalls;
    expect(initial).toBeGreaterThan(0);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5200); // interval poll window elapses
    });
    expect(recordCalls).toBeGreaterThan(initial);
  });
});

describe("AuditLog live tail respects the active filters", () => {
  /**
   * The live tail is prepended to the server page on page 0. It used to mirror only `realOnly`, so the
   * decision / tool / agent / rule filters applied server-side to the fetched page were absent from the
   * streamed rows above it. Selecting "Block" on a namespace whose recent traffic is all allows rendered
   * six ALLOW rows under a header reading "Showing 6 of 0 records" — six live rows over a server count of
   * zero. In an audit tool that is not cosmetic: someone filtering to Block during an incident sees rows
   * and reasonably reads them as blocks.
   */
  const ALLOW_ROW = {
    id: "live-1",
    timestamp: new Date().toISOString(),
    tool_name: "search_kb",
    decision: "allow",
    rule_id: "moderate_default_allow",
    agent_class: "finance-ops",
    agent_id: "spiffe://norviq/ns/analytics/sa/default",
    namespace: "analytics",
    framework: "sidecar",
    latency_ms: 21
  };

  it("does not show a streamed ALLOW row while the Block filter is active", async () => {
    // The poll feeds the live tail; the filtered page itself is empty (no blocks).
    server.use(
      http.get("/api/v1/audit/records", ({ request }) => {
        const url = new URL(request.url);
        // the live-tail poll is the unfiltered one; the page query carries decision=block
        return HttpResponse.json(url.searchParams.get("decision") === "block" ? [] : [ALLOW_ROW]);
      })
    );
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    fireEvent.click(screen.getByRole("button", { name: /^block$/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300);
    });
    // No ALLOW decision may survive a Block filter, from either source.
    expect(screen.queryByText("ALLOW")).toBeNull();
    expect(screen.queryByText("moderate_default_allow")).toBeNull();
  });
});

describe("AuditLog pagination beyond the 500-offset cap", () => {
  // FAIL-ON-BUG: with a full count-probe (server caps limit at 500) and full pages, the pager must let
  // the user advance past page 10 / offset 500. Old code disabled Next at page 10 (totalPages-1), so
  // offset 500 was never fetched and records beyond it were unreachable.
  it("keeps Next enabled past page 10 and fetches offset >= 500", async () => {
    const pageOffsets: number[] = [];
    const makeRecords = (n: number, offset: number) =>
      Array.from({ length: n }, (_v, i) => ({
        id: `rec-${offset + i}`,
        timestamp: "2026-07-03T12:00:00Z",
        tool_name: "shell_exec",
        decision: "allow" as const
      }));
    server.use(
      http.get("/api/v1/audit/records", ({ request }) => {
        const url = new URL(request.url);
        const limit = Number(url.searchParams.get("limit") ?? "50");
        const offset = Number(url.searchParams.get("offset") ?? "0");
        // The count probe (limit=500) comes back full → there are more rows than it can see.
        if (limit === 500) return HttpResponse.json(makeRecords(500, 0));
        // Every 50-row page is full → paging must not stop.
        if (limit === 50) {
          pageOffsets.push(offset);
          return HttpResponse.json(makeRecords(50, offset));
        }
        return HttpResponse.json(makeRecords(Math.min(limit, 10), offset)); // live-poll probe
      })
    );
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    // Click Next 10 times: page 0 → 10 (offset 500). Old code disabled Next at page 9 (offset 450).
    for (let i = 0; i < 10; i += 1) {
      const next = screen.getByRole("button", { name: /Next/i });
      await act(async () => {
        fireEvent.click(next);
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300);
      });
    }

    expect(Math.max(...pageOffsets)).toBeGreaterThanOrEqual(500);
    expect(screen.getByRole("button", { name: /Next/i })).not.toBeDisabled();
  });
});

describe("AuditLog structured event detail (E2b)", () => {
  it("renders structured fields + the engine-fault note for evaluator_error rows", async () => {
    server.use(
      http.get("/api/v1/audit/records", () =>
        HttpResponse.json([
          {
            id: "rec-1",
            timestamp: "2026-07-03T12:00:00Z",
            tool_name: "shell_exec",
            decision: "block",
            rule_id: "evaluator_error",
            reason: "engine timed out",
            agent_id: "spiffe://norviq/ns/finance/sa/support-bot",
            session_id: "sess-42",
            trust_score: 40,
            latency_ms: 12,
            tool_params: { cmd: "rm -rf /" }
          }
        ])
      )
    );
    renderPage();
    // let mount fetches settle (fake timers → advance instead of waitFor)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    // click the row to open the detail panel
    const cell = screen.getByText("shell_exec");
    const row = cell.closest("tr")!;
    await act(async () => {
      fireEvent.click(row);
    });

    // Wave-2 engine-fault note distinguishes evaluator_error from a real policy block
    expect(screen.getByText(/Engine fault \(fail-closed\)/i)).toBeInTheDocument();
    // structured SPIFFE parsing → namespace + agent class
    expect(screen.getByText("finance")).toBeInTheDocument();
    expect(screen.getByText("support-bot")).toBeInTheDocument();
    // labeled fields + tool params rendered
    expect(screen.getByText("Session")).toBeInTheDocument();
    expect(screen.getByText(/sess-42/)).toBeInTheDocument();
    expect(screen.getByText(/rm -rf/)).toBeInTheDocument();
    expect(screen.getByText("engine timed out")).toBeInTheDocument();
  });
});

// ------------------------------------------------------------------------------------------------
// THE RED-TEAM EVIDENCE LINK.
//
// Red Team's per-attack link is `/audit?rule=<rule_id>&framework=redteam`, titled "Audit rows for
// this rule, scoped to red-team traffic". `framework` was never read from the URL, while
// `exclude_synthetic` was sent true by default and the server's exclusion IS `framework ==
// "redteam"` (norviq/api/synthetic.py) — the exact tag norviq/api/routers/redteam.py writes. So the
// rows the link exists to show were the only rows guaranteed to be hidden, and either:
//
//   * nothing else is on that rule → "Showing 0 of 0 records" and a flat "No matching records in the
//     last 24h." (a full stop: `hasFilter` omitted `rule`, so even the generic hint was suppressed),
//     read as "the attack left no audit trail"; or
//   * unrelated production traffic shares the rule_id → the link labelled "scoped to red-team
//     traffic" shows EXACTLY that production row. That is the failure redteam.py documents as fixed.
//
// The active `rule` filter was also printed nowhere and had no control to clear it.
// ------------------------------------------------------------------------------------------------
describe("AuditLog red-team evidence deep-link", () => {
  const REDTEAM_ROW = {
    id: "rt-1",
    timestamp: "2026-07-03T12:00:00Z",
    tool_name: "send_email",
    decision: "block",
    rule_id: "mcp_tool_poisoning",
    agent_class: "redteam-probe",
    framework: "redteam",
    non_real: true,
    latency_ms: 9
  };
  const PRODUCTION_ROW = {
    id: "prod-1",
    timestamp: "2026-07-03T11:00:00Z",
    tool_name: "fetch_url",
    decision: "block",
    rule_id: "mcp_tool_poisoning",
    agent_class: "report-gen",
    framework: "sidecar",
    non_real: false,
    latency_ms: 14
  };

  /** The ledger, filtered exactly as norviq/api/routers/audit.py filters it. */
  function serveLedger(onQuery?: (q: URLSearchParams) => void) {
    server.use(
      http.get("/api/v1/audit/records", ({ request }) => {
        const q = new URL(request.url).searchParams;
        onQuery?.(q);
        let out = [REDTEAM_ROW, PRODUCTION_ROW] as Array<Record<string, unknown>>;
        const ruleId = q.get("rule_id");
        if (ruleId) out = out.filter((r) => r.rule_id === ruleId);
        const fw = q.get("framework");
        if (fw) out = out.filter((r) => r.framework === fw); // exact equality, as the server does
        if (q.get("exclude_synthetic") === "true") out = out.filter((r) => r.framework !== "redteam");
        return HttpResponse.json(out);
      })
    );
  }

  function renderAt(url: string) {
    return render(
      <MemoryRouter initialEntries={[url]}>
        <AppProvider>
          <AuditLog />
        </AppProvider>
      </MemoryRouter>
    );
  }

  it("sends framework=redteam and shows the red-team row, not the production row sharing the rule", async () => {
    const queries: URLSearchParams[] = [];
    serveLedger((q) => queries.push(q));
    renderAt("/audit?rule=mcp_tool_poisoning&framework=redteam");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    const pageQuery = queries.find((q) => q.get("limit") === "50")!;
    expect(pageQuery.get("rule_id")).toBe("mcp_tool_poisoning");
    expect(pageQuery.get("framework")).toBe("redteam");
    // The exclusion the link would otherwise cancel itself with.
    expect(pageQuery.get("exclude_synthetic")).toBeNull();

    // The evidence is on screen…
    expect(screen.getAllByText("send_email").length).toBeGreaterThan(0);
    // …and the unrelated production row that merely shares the rule_id is NOT presented as it.
    expect(screen.queryByText("fetch_url")).toBeNull();
  });

  it("prints the deep-linked rule as a chip the operator can clear", async () => {
    serveLedger();
    renderAt("/audit?rule=mcp_tool_poisoning&framework=redteam");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    const chips = screen.getByTestId("audit-active-filters");
    expect(chips).toHaveTextContent("mcp_tool_poisoning");
    expect(chips).toHaveTextContent("redteam");

    await act(async () => {
      fireEvent.click(screen.getByTestId("audit-chip-clear-rule"));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.queryByTestId("audit-chip-rule")).toBeNull();
  });

  it("says so when Real-traffic-only and framework=redteam cancel each other out", async () => {
    // Reachable by toggling the button back on after arriving from the link. An empty table under two
    // filters with an empty intersection says nothing about whether the attack wrote rows.
    serveLedger();
    renderAt("/audit?rule=mcp_tool_poisoning&framework=redteam");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.queryByTestId("audit-redteam-conflict")).toBeNull();

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Showing all \(incl\. test\)/i }));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.getByTestId("audit-redteam-conflict")).toHaveTextContent(/cannot both hold/i);
    expect(screen.queryByText("send_email")).toBeNull();
  });

  it("names the rule filter in the empty state instead of stopping at a full stop", async () => {
    server.use(http.get("/api/v1/audit/records", () => HttpResponse.json([])));
    renderAt("/audit?rule=mcp_tool_poisoning&framework=redteam");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    // The filter responsible for the emptiness is visible, and the hint is not suppressed.
    expect(screen.getByTestId("audit-active-filters")).toHaveTextContent("mcp_tool_poisoning");
    expect(screen.getByText(/for these filters/i)).toBeInTheDocument();
  });
});

describe("AuditLog Params row", () => {
  it("distinguishes 'we never asked for the arguments' from 'there were none'", async () => {
    // `/audit/records`'s `_to_dict` emits no `tool_params` key at all, so this row could NEVER
    // populate — and a bare em-dash sitting between a real Tool row and a real Trust row reads as
    // captured-and-empty. An operator who switched `audit_capture_masked_params` ON for PCI 10.3
    // event reconstruction saw the same em-dash while the masked values sat in the database.
    server.use(
      http.get("/api/v1/audit/records", () =>
        HttpResponse.json([
          {
            id: "rec-np",
            timestamp: "2026-07-03T12:00:00Z",
            tool_name: "send_email",
            decision: "block",
            rule_id: "egress_block",
            agent_id: "spiffe://norviq/ns/finance/sa/support-bot",
            session_id: "sess-7",
            trust_score: 40,
            latency_ms: 12,
            framework: "sidecar"
            // no tool_params — exactly what the serializer emits
          }
        ])
      )
    );
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    await act(async () => {
      fireEvent.click(screen.getByText("send_email").closest("tr")!);
    });

    const row = screen.getByTestId("audit-params-uncaptured");
    expect(row).toHaveTextContent(/does not return call arguments/i);
    expect(row).toHaveTextContent(/Not evidence the call carried none/i);
  });

  it("still says 'captured, none' for a record that really carries an empty argument set", async () => {
    server.use(
      http.get("/api/v1/audit/records", () =>
        HttpResponse.json([
          {
            id: "rec-empty",
            timestamp: "2026-07-03T12:00:00Z",
            tool_name: "list_matters",
            decision: "allow",
            latency_ms: 4,
            tool_params: {}
          }
        ])
      )
    );
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    await act(async () => {
      fireEvent.click(screen.getByText("list_matters").closest("tr")!);
    });
    expect(screen.getByTestId("audit-params-empty")).toHaveTextContent(/carried no arguments/i);
    expect(screen.queryByTestId("audit-params-uncaptured")).toBeNull();
  });
});

describe("a failed read is not an empty audit log", () => {
  it("never prints a record count or 'No matching records' when the query failed", async () => {
    // This file installs fake timers globally for the poll tests; a real awaited find needs real ones.
    vi.useRealTimers();
    // The reading an operator takes from "No matching records in the last 24h" while triaging is the
    // one this file's own comments name: the attack left no audit trail. It must never be produced by
    // a failed read — "we could not look" and "we looked and it is clean" are opposite facts.
    server.use(
      http.get("/api/v1/audit/records", () => new HttpResponse(null, { status: 500 }))
    );
    renderPage();
    const band = await screen.findByTestId("audit-unreadable", {}, { timeout: 5000 });
    expect(band).toHaveTextContent(/Couldn.t read the audit log/i);
    expect(band).toHaveTextContent(/NOT .no records./i);
    expect(screen.queryByText(/No matching records/i)).toBeNull();
    expect(screen.queryByText(/Showing \d+ of \d+ record/i)).toBeNull();
  });
});
