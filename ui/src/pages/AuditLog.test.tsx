// SPDX-License-Identifier: Apache-2.0
import { act, render } from "@testing-library/react";
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
