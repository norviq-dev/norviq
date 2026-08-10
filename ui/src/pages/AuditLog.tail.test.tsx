// SPDX-License-Identifier: Apache-2.0
// The live tail's POLL fallback must not outlive the filter it was fetched under.
//
// When /ws/audit is not connected (an ingress that does not upgrade the socket, or any drop) the tail
// is fed by fetchAuditRecords instead. Those rows were only ever cleared when Live was switched OFF —
// never on a filter change — so a red-team probe fetched with "Real traffic only" OFF stayed in the
// tail after it was switched back ON. And it could not be filtered out on the way through: the guard
// is `realOnly && r.non_real`, but `non_real` is produced ONLY by the websocket payload
// (norviq/api/audit_hub.py); `/audit/records` `_to_dict` (norviq/api/routers/audit.py) does not emit
// it, so every polled row carries `non_real === undefined` and the guard is inert for them.
//
// Result: a synthetic red-team row rendered as live governed traffic beneath a toggle reading
// "✓ Real traffic only" and a header reading "Showing 1 of 0 records … red-team & synthetic/probe
// rows hidden" — the same "N of 0" shape this page's own comment calls out as "not a cosmetic slip".
//
// `non_real` is deliberately NOT re-derived client-side: the server's predicate is
// `framework == "redteam" OR is_synthetic_identity(agent_class, spiffe_id)`, and forking that
// class-prefix list into TypeScript is exactly the drift audit_hub.py's comment exists to prevent.
// The fix is to drop the fetched tail when the filter set changes and let the server — which DOES
// apply `exclude_synthetic` to this endpoint — decide what the new filters admit.
import { act, fireEvent, render, screen } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditLog } from "./AuditLog";
import { AppProvider, useApp } from "../store/AppContext";

// A socket that never opens → useWebSocket.connected stays false → the poll fallback runs.
class DisconnectedWS {
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  constructor(_url: string) {}
  close() {}
}

/**
 * A socket that DOES open, and hands out its live instances so a test can push frames.
 *
 * Needed because clearing `polled` closes only half of the scope leak. `useWebSocket` keeps its
 * `messages` across a url change — the hook exposes `clear()` and nothing calls it — so switching
 * namespace closes the old socket, opens one scoped to the new namespace (main.py `ws_audit` filters
 * server-side), and leaves up to 100 rows from the OLD namespace in state. Six of them render above a
 * table with no Namespace column, flagged `_live`, under a header that says the page is scoped
 * elsewhere. Only a socket that actually connects can reproduce that.
 */
class OpenWS {
  static instances: OpenWS[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  url: string;
  constructor(url: string) {
    this.url = url;
    OpenWS.instances.push(this);
    setTimeout(() => this.onopen?.(), 0);
  }
  send(data: string) {
    this.onmessage?.({ data });
  }
  close() {}
}

/** The socket the hook most recently opened. `.at(-1)` is past this project's TS lib target. */
function latestWS(): OpenWS {
  const last = OpenWS.instances[OpenWS.instances.length - 1];
  if (!last) throw new Error("no WebSocket was opened — the hook never connected");
  return last;
}

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => {
  // `setNamespace` PERSISTS to localStorage (nrvq_namespace), and `initialNamespace()` reads it back
  // at mount — so a test that rescopes the console silently seeds the scope of every test after it.
  // Without this, the socket cases below started on "payments" and the fixture could not produce the
  // state its name claims: the row they push is dropped before the assertion it is meant to prove.
  localStorage.clear();
  vi.stubGlobal("WebSocket", DisconnectedWS as unknown as typeof WebSocket);
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals(); // restoreAllMocks does NOT undo stubGlobal
  server.resetHandlers();
});
afterAll(() => server.close());

// A red-team probe row, exactly as `/audit/records` serialises it: `framework` present,
// and NO `non_real` — that field only exists on the websocket payload.
const REDTEAM_ROW = {
  id: "rt-1",
  event_id: "rt-1",
  timestamp: new Date().toISOString(),
  tool_name: "exec_shell",
  decision: "block" as const,
  rule_id: "deny_shell",
  agent_class: "redteam",
  agent_id: "spiffe://norviq/ns/default/sa/redteam-probe",
  namespace: "default",
  framework: "redteam",
  trust_score: 0.1,
  latency_ms: 4
};

/** Drives the GLOBAL namespace scope the way the app header's selector does. */
function NamespaceSwitcher() {
  const { setNamespace } = useApp();
  return (
    <button type="button" onClick={() => setNamespace("payments")}>
      switch-ns
    </button>
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AuditLog />
      </AppProvider>
    </MemoryRouter>
  );
}

/** The real server contract: exclude_synthetic=true drops the red-team row; absent returns it. */
function honestServer() {
  server.use(
    http.get("/api/v1/audit/records", ({ request }) => {
      const url = new URL(request.url);
      return HttpResponse.json(url.searchParams.get("exclude_synthetic") === "true" ? [] : [REDTEAM_ROW]);
    })
  );
}

describe("a polled tail row cannot survive the filter it was fetched under", () => {
  it("drops the red-team row from the live tail when Real-traffic-only is switched back ON", async () => {
    honestServer();
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    // Default is real-traffic-only: nothing synthetic on screen.
    expect(screen.queryByText("exec_shell")).toBeNull();

    // Operator switches the filter OFF to inspect the full ledger — the probe legitimately appears.
    fireEvent.click(screen.getByRole("button", { name: /Real traffic only/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.getAllByText("exec_shell").length).toBeGreaterThan(0);

    // …and switches it back ON.
    fireEvent.click(screen.getByRole("button", { name: /Showing all \(incl\. test\)/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    // FAIL-ON-BUG: pre-fix the row is still there — `polled` was never cleared on a filter change and
    // the `non_real` guard sees `undefined` on every polled row.
    expect(screen.getByRole("button", { name: /✓ Real traffic only/i })).toBeInTheDocument();
    expect(screen.queryByText("exec_shell")).toBeNull();
    expect(screen.queryByText("deny_shell")).toBeNull();
  });

  it("does not print 'Showing 1 of 0 records' under the real-traffic-only promise", async () => {
    honestServer();
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    fireEvent.click(screen.getByRole("button", { name: /Real traffic only/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    fireEvent.click(screen.getByRole("button", { name: /Showing all \(incl\. test\)/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });

    // FAIL-ON-BUG: pre-fix the count line read "Showing 1 of 0 records … red-team & synthetic/probe
    // rows hidden" — a visible row contradicting the count directly above it.
    expect(screen.getByText(/Showing 0 of 0 records/)).toBeInTheDocument();
  });

  it("never prints more rows than its own total — the live tail counts too", async () => {
    // Observed live while driving the chatbot: "Showing 41 of 39 records". The count comes from a
    // SEPARATE probe fetch, and the live tail keeps prepending rows after that probe ran, so the
    // numerator grew past a frozen denominator. Sibling of the "Showing 1 of 0" case above, and it
    // lands in the same place: on an audit surface, a header that visibly cannot do arithmetic is a
    // reason to distrust every other number on the page.
    let served = 0;
    server.use(
      http.get("/api/v1/audit/records", ({ request }) => {
        const url = new URL(request.url);
        // The count probe asks for a big limit; the page asks for pageSize. Serve the page a row the
        // probe never saw, which is exactly what a live tail does.
        const limit = Number(url.searchParams.get("limit") ?? "0");
        served += 1;
        if (limit >= 500) return HttpResponse.json([]);        // probe: nothing counted yet
        return HttpResponse.json([REDTEAM_ROW]);                // page: one row on screen
      })
    );
    renderPage();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(served).toBeGreaterThan(0);
    const m = (document.body.textContent ?? "").match(/Showing (\d+) of (\d+)/);
    expect(m, "the count line must render at all").not.toBeNull();
    expect(Number(m![1])).toBeLessThanOrEqual(Number(m![2]));
  });

  it("drops a tail row fetched under a different namespace", async () => {
    // The tail has no Namespace column, so a row left over from the namespace the operator just left
    // reads as this namespace's traffic — the same defect `offScope` suppresses for the fetched page.
    server.use(
      http.get("/api/v1/audit/records", ({ request }) => {
        const url = new URL(request.url);
        const ns = url.searchParams.get("namespace");
        // `payments` is quiet; the previous (unscoped) view had one sidecar row.
        return HttpResponse.json(ns === "payments" ? [] : [{ ...REDTEAM_ROW, framework: "sidecar", agent_class: "ops" }]);
      }),
      http.get("/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["default", "payments"] })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <NamespaceSwitcher />
          <AuditLog />
        </AppProvider>
      </MemoryRouter>
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(500);
    });
    expect(screen.getAllByText("exec_shell").length).toBeGreaterThan(0);

    // Switch the GLOBAL console scope, the way the header selector does.
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "switch-ns" }));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000); // let the scoped read settle so `stale` clears
    });

    // FAIL-ON-BUG: pre-fix the previous scope's row stayed in the tail, with no Namespace column to
    // contradict it. (Guard against a vacuous pass: the page must be showing the table, not the
    // off-scope panel that hides everything anyway.)
    expect(screen.queryByTestId("audit-unreadable")).toBeNull();
    expect(screen.queryByText("exec_shell")).toBeNull();
  });
});

describe("the SOCKET half of the same leak", () => {
  it("drops a websocket row from the namespace the operator just left", async () => {
    OpenWS.instances = [];
    vi.stubGlobal("WebSocket", OpenWS as unknown as typeof WebSocket);
    server.use(
      http.get("/api/v1/audit/records", () => HttpResponse.json([])),
      http.get("/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["default", "payments"] })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <NamespaceSwitcher />
          <AuditLog />
        </AppProvider>
      </MemoryRouter>
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(50);
    });

    // A real, ordinary governed call streams in while the console is scoped to `default`. Nothing
    // about it is synthetic — `non_real` is false — so no other guard can drop it.
    const DEFAULT_ROW = {
      id: "ws-1",
      timestamp: new Date().toISOString(),
      tool_name: "get_customer",
      decision: "allow" as const,
      rule_id: "allow_reads",
      agent_class: "ops",
      agent_id: "spiffe://norviq/ns/default/sa/support",
      namespace: "default",
      framework: "sidecar",
      trust_score: 0.9,
      latency_ms: 3,
      non_real: false
    };
    await act(async () => {
      latestWS().send(JSON.stringify(DEFAULT_ROW));
    });
    expect(screen.getAllByText("get_customer").length).toBeGreaterThan(0);

    // Operator rescopes the console to `payments`.
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "switch-ns" }));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });

    // FAIL-ON-BUG: `useWebSocket` never clears `messages` on a url change, so the `default` row is
    // still in the tail — rendered as this namespace's live traffic, with no Namespace column to
    // contradict it. (Anti-vacuous guard: the page must be showing the table, not the off-scope panel.)
    expect(screen.queryByTestId("audit-unreadable")).toBeNull();
    expect(screen.queryByText("get_customer")).toBeNull();
  });

  it("keeps streaming rows at the aggregate scope, and rows the server sent without a namespace", async () => {
    // The predicate mirrors main.py's ws_audit filter INCLUDING its edge cases: "all" is the
    // aggregate sentinel and filters nothing, and `record.get("namespace") not in (namespace, "",
    // None)` passes a row whose namespace is empty/absent. A stricter client-side rule would hide
    // rows the server deliberately delivered — "we could not tell" rendered as "nothing happened".
    OpenWS.instances = [];
    vi.stubGlobal("WebSocket", OpenWS as unknown as typeof WebSocket);
    server.use(http.get("/api/v1/audit/records", () => HttpResponse.json([])));
    renderPage(); // default scope is "all"
    await act(async () => {
      await vi.advanceTimersByTimeAsync(50);
    });

    const base = {
      timestamp: new Date().toISOString(),
      decision: "allow" as const,
      rule_id: "allow_reads",
      agent_class: "ops",
      framework: "sidecar",
      trust_score: 0.9,
      latency_ms: 3,
      non_real: false
    };
    await act(async () => {
      latestWS().send(JSON.stringify({ ...base, id: "ws-a", tool_name: "get_order", namespace: "payments" }));
      latestWS().send(JSON.stringify({ ...base, id: "ws-b", tool_name: "search_kb", namespace: "" }));
    });

    expect(screen.getAllByText("get_order").length).toBeGreaterThan(0);
    expect(screen.getAllByText("search_kb").length).toBeGreaterThan(0);
  });
});
