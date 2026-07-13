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
