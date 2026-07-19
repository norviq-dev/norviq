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

  it("a freeze that fails (403) surfaces an error instead of silently no-op'ing", async () => {
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

  it("a successful freeze under a ?class= filter keeps the full fleet (doesn't collapse to one class)", async () => {
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

  it("UX-BACK: freeze → 'Back to all agents' keeps the FULL list and does NOT refetch (frozen stays frozen)", async () => {
    // Reproduces the reported issue: after freezing an agent and pressing "Back to all agents" the list
    // collapsed to just the frozen agent. Root cause was a regression that added `!!selected` to the
    // fetch deps (+ a 60s auto-poll): pressing Back flipped selected→null, re-ran the effect, and the
    // refetch (cache just busted by the freeze) raced the optimistic setData → list collapsed. The fix
    // fetches on mount/namespace only, so Back is a pure setSelected(null) — the full list is untouched.
    let agentsGets = 0;
    const fleet = [
      { spiffe_id: "spiffe://norviq/ns/default/sa/report-gen-1", namespace: "default", agent_class: "report-gen", last_seen: new Date().toISOString(), score: 0.82, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow" },
      { spiffe_id: "spiffe://norviq/ns/default/sa/report-gen-2", namespace: "default", agent_class: "report-gen", last_seen: new Date().toISOString(), score: 0.71, category: "medium", violation_count: 1, signals: {}, dominant_signal: "", recommendation: "allow" },
      { spiffe_id: "spiffe://norviq/ns/default/sa/billing-bot", namespace: "default", agent_class: "billing", last_seen: new Date().toISOString(), score: 0.9, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow" }
    ];
    server.use(
      http.get("/api/v1/agents", () => { agentsGets += 1; return HttpResponse.json(fleet); }),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ score: 0 }))
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );

    // All three agents present on load.
    await screen.findByText("spiffe://norviq/ns/default/sa/report-gen-1");
    expect(screen.getByText("spiffe://norviq/ns/default/sa/report-gen-2")).toBeInTheDocument();
    expect(screen.getByText("spiffe://norviq/ns/default/sa/billing-bot")).toBeInTheDocument();

    // Select an agent and freeze it. Detail swaps Freeze/Reset for the explicit Unfreeze control.
    fireEvent.click(screen.getByText("spiffe://norviq/ns/default/sa/report-gen-1"));
    fireEvent.click(await screen.findByText("Freeze Agent"));
    await screen.findByText("Unfreeze Agent");
    expect(screen.queryByText("Reset Trust")).toBeNull(); // frozen agent → no dead "Reset" path
    await waitFor(() => {
      const frozenTile = screen.getByText("Frozen").closest(".panel") as HTMLElement;
      expect(within(frozenTile).getByText("1")).toBeInTheDocument();
    });

    // Press "Back to all agents": detail closes and the FULL fleet is still there (the reported bug).
    fireEvent.click(screen.getByText("Back to all agents"));
    await waitFor(() => expect(screen.queryByText("Agent Actions")).toBeNull());
    expect(screen.getByText("spiffe://norviq/ns/default/sa/report-gen-1")).toBeInTheDocument();
    expect(screen.getByText("spiffe://norviq/ns/default/sa/report-gen-2")).toBeInTheDocument();
    expect(screen.getByText("spiffe://norviq/ns/default/sa/billing-bot")).toBeInTheDocument();
    const trackedTile = screen.getByText("Agents Tracked").closest(".panel") as HTMLElement;
    expect(within(trackedTile).getByText("3")).toBeInTheDocument();
    // The frozen agent stayed frozen (no auto-refetch un-did the optimistic freeze).
    const stillFrozen = screen.getByText("Frozen").closest(".panel") as HTMLElement;
    expect(within(stillFrozen).getByText("1")).toBeInTheDocument();

    // The core guard: /agents was fetched exactly ONCE (mount). The buggy deps refetched on Back;
    // any auto-poll would push this above 1. Select + freeze + Back trigger no extra fleet fetch.
    expect(agentsGets).toBe(1);
  });

  it("UX-UNFREEZE: a frozen agent can be unfrozen from its detail (restores trust, list intact)", async () => {
    const fleet = [
      { spiffe_id: "spiffe://norviq/ns/default/sa/frozen-bot", namespace: "default", agent_class: "batch", last_seen: new Date().toISOString(), score: 0, category: "frozen", violation_count: 5, signals: {}, dominant_signal: "", recommendation: "block" },
      { spiffe_id: "spiffe://norviq/ns/default/sa/healthy-bot", namespace: "default", agent_class: "web", last_seen: new Date().toISOString(), score: 0.9, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow" }
    ];
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json(fleet)),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ score: 0.8 }))
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    // Select the already-frozen agent → only the Unfreeze action is offered.
    fireEvent.click(await screen.findByText("spiffe://norviq/ns/default/sa/frozen-bot"));
    const unfreeze = await screen.findByText("Unfreeze Agent");
    expect(screen.queryByText("Freeze Agent")).toBeNull();
    // Unfreeze → optimistic restore to trust 0.8: the Frozen tile drops to 0, no error surfaced.
    fireEvent.click(unfreeze);
    await waitFor(() => {
      const frozenTile = screen.getByText("Frozen").closest(".panel") as HTMLElement;
      expect(within(frozenTile).getByText("0")).toBeInTheDocument();
    });
    expect(screen.queryByRole("alert")).toBeNull();
    // Both agents still tracked.
    const trackedTile = screen.getByText("Agents Tracked").closest(".panel") as HTMLElement;
    expect(within(trackedTile).getByText("2")).toBeInTheDocument();
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
    // The detail panel opens with the audited actions.
    expect(await screen.findByText("Agent Actions")).toBeInTheDocument();
    expect(screen.getByText("Freeze Agent")).toBeInTheDocument();
    expect(screen.getByText("Reset Trust")).toBeInTheDocument();
  });
});
