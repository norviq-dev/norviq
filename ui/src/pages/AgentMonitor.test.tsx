// SPDX-License-Identifier: Apache-2.0
// UI-1 smoke test: Agents page mounts without React #130 (renders DonutChart/VolumeChart/CategoryBars).
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({ default: () => null }));

import { AgentMonitor } from "./AgentMonitor";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

describe("UI-1: AgentMonitor mounts", () => {
  it("renders the Agent Monitor page without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Agent Monitor")).toBeInTheDocument());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });

  it("B4: populates Namespace / Class / Last Seen columns from the /agents response", async () => {
    const recent = new Date(Date.now() - 3 * 60_000).toISOString();
    server.use(
      http.get("/api/v1/agents", () =>
        HttpResponse.json([
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/deploy-bot",
            namespace: "default", agent_class: "deploy-bot", last_seen: recent,
            score: 0.82, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: ""
          }
        ])
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    // ns + class parsed from the SVID (were "–"); last_seen humanized (not raw ISO / "–").
    expect(await screen.findByText("deploy-bot")).toBeInTheDocument();
    expect(screen.getAllByText("default").length).toBeGreaterThan(0);
    expect(screen.getByText(/ago|just now/i)).toBeInTheDocument();
  });

  it("P5: clicking an agent row opens the detail panel with freeze/trust actions", async () => {
    server.use(
      http.get("/api/v1/agents", () =>
        HttpResponse.json([
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/deploy-bot",
            namespace: "default", agent_class: "deploy-bot", last_seen: new Date().toISOString(),
            score: 0.82, category: "high", violation_count: 0, signals: { violation_rate: 0.1 }, dominant_signal: "violation_rate", recommendation: "allow"
          }
        ])
      ),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([]))
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByText("deploy-bot"));
    // The detail panel opens with the audited actions (was rendered off-screen / not opening per the reviewer).
    expect(await screen.findByText("Agent Actions")).toBeInTheDocument();
    expect(screen.getByText("Freeze Agent")).toBeInTheDocument();
    expect(screen.getByText("Reset Trust")).toBeInTheDocument();
  });
});
