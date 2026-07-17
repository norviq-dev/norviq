// SPDX-License-Identifier: Apache-2.0
// UI-1 smoke test: Agents page mounts without React #130 (renders DonutChart/VolumeChart/CategoryBars).
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, useNavigate } from "react-router-dom";
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

  it("DEF-040: a freeze that fails (403) surfaces an error instead of silently no-op'ing", async () => {
    server.use(
      http.get("/api/v1/agents", () =>
        HttpResponse.json([
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/deploy-bot",
            namespace: "default", agent_class: "deploy-bot", last_seen: new Date().toISOString(),
            score: 0.82, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow"
          }
        ])
      ),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      // Backend requires admin — a viewer's freeze is a 403; apiSend throws on !ok.
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => new HttpResponse("Admin role required", { status: 403 }))
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByText("spiffe://norviq/ns/default/sa/deploy-bot"));
    fireEvent.click(await screen.findByText("Freeze Agent"));
    // Pre-fix the catch was `// ignore` → no alert, no state change: the button looked like a dead control.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Admin role required");
  });

  it("DEF-022: a successful freeze under a ?class= filter keeps the full fleet (doesn't collapse to one class)", async () => {
    server.use(
      http.get("/api/v1/agents", () =>
        HttpResponse.json([
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/report-gen-1",
            namespace: "default", agent_class: "report-gen", last_seen: new Date().toISOString(),
            score: 0.82, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow"
          },
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/report-gen-2",
            namespace: "default", agent_class: "report-gen", last_seen: new Date().toISOString(),
            score: 0.71, category: "medium", violation_count: 1, signals: {}, dominant_signal: "", recommendation: "allow"
          },
          {
            spiffe_id: "spiffe://norviq/ns/default/sa/billing-bot",
            namespace: "default", agent_class: "billing", last_seen: new Date().toISOString(),
            score: 0.9, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow"
          }
        ])
      ),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ score: 0 }))
    );

    // A sibling of AgentMonitor that clears the ?class= filter via the SAME router (no remount of the page),
    // mirroring the Compliance deep-link → "back to all agents" flow.
    function ClearFilterButton() {
      const navigate = useNavigate();
      return (
        <button type="button" onClick={() => navigate("/agents")}>
          clear-filter
        </button>
      );
    }

    render(
      <MemoryRouter initialEntries={["/agents?class=report-gen"]}>
        <AppProvider>
          <ClearFilterButton />
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );

    // Filter active: only the two report-gen agents; billing hidden.
    await screen.findByText("spiffe://norviq/ns/default/sa/report-gen-1");
    expect(screen.queryByText("spiffe://norviq/ns/default/sa/billing-bot")).toBeNull();

    // Freeze one report-gen agent (optimistic setData replaces agents.data).
    fireEvent.click(screen.getByText("spiffe://norviq/ns/default/sa/report-gen-1"));
    fireEvent.click(await screen.findByText("Freeze Agent"));
    // Optimistic update landed and it did NOT error.
    await waitFor(() => {
      const frozenTile = screen.getByText("Frozen").closest(".panel") as HTMLElement;
      expect(within(frozenTile).getByText("1")).toBeInTheDocument();
    });
    expect(screen.queryByRole("alert")).toBeNull();

    // Clear the class filter (no remount → no refetch): the full fleet must still be present.
    fireEvent.click(screen.getByText("clear-filter"));
    await waitFor(() => {
      expect(screen.getByText("spiffe://norviq/ns/default/sa/billing-bot")).toBeInTheDocument();
    });
    // Pre-fix: `next = rows.map(...)` wrote back only the filtered subset, so agents.setData dropped the
    // billing agent — "Agents Tracked" would read 2 here until the 60s refetch. Fixed: still 3.
    const trackedTile = screen.getByText("Agents Tracked").closest(".panel") as HTMLElement;
    expect(within(trackedTile).getByText("3")).toBeInTheDocument();
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
