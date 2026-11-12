// SPDX-License-Identifier: Apache-2.0
// Smoke test: Agents page mounts without React #130 (renders DonutChart/VolumeChart/CategoryBars).
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, useNavigate } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({ default: () => null }));

import { AgentMonitor } from "./AgentMonitor";
import { AppProvider } from "../store/AppContext";
import { clearApiCache, peekApiCache, primeApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

describe("AgentMonitor mounts", () => {
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

  it("populates Namespace / Class / Last Seen columns from the /agents response", async () => {
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
    fireEvent.click(await screen.findByTestId("agent-trust-confirm-submit")); // Freeze asks first
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
    fireEvent.click(await screen.findByTestId("agent-trust-confirm-submit")); // Freeze asks first
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
    fireEvent.click(await screen.findByTestId("agent-trust-confirm-submit")); // Freeze asks first
    await screen.findByText("Unfreeze Agent");
    expect(screen.queryByText("Reset Behavior Record")).toBeNull(); // frozen agent → only Unfreeze
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

  it("UX-UNFREEZE: Unfreeze lifts the freeze with score 1.0, adds no cap, and shows the agent's real trust", async () => {
    // It used to send score 0.8, which the API stores as a durable, tighten-only CAP, and paint "high 0.80" —
    // the value of that cap, not the agent's trust (the engine scored it 0.455 and capped it from then on).
    const fleet = [
      { spiffe_id: "spiffe://norviq/ns/default/sa/frozen-bot", namespace: "default", agent_class: "batch", last_seen: new Date().toISOString(), score: 0, category: "frozen", frozen: true, trust_cap: null, violation_count: 5, signals: {}, dominant_signal: "", recommendation: "freeze" },
      { spiffe_id: "spiffe://norviq/ns/default/sa/healthy-bot", namespace: "default", agent_class: "web", last_seen: new Date().toISOString(), score: 0.9, category: "high", frozen: false, trust_cap: null, violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow" }
    ];
    const sent: unknown[] = [];
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json(fleet)),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, async ({ request }) => {
        sent.push(await request.json());
        return HttpResponse.json({ spiffe_id: fleet[0].spiffe_id, frozen: false, trust_cap: null });
      }),
      // The re-read: the agent's trust as the API now reports it.
      http.get(/\/api\/v1\/agents\/spiffe[^/]*frozen-bot$/, () =>
        HttpResponse.json({ spiffe_id: fleet[0].spiffe_id, score: 0.455, category: "medium", frozen: false, trust_cap: null, violation_count: 0, signals: {}, dominant_signal: "", recommendation: "allow" })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByText("spiffe://norviq/ns/default/sa/frozen-bot"));
    const unfreeze = await screen.findByText("Unfreeze Agent");
    expect(screen.queryByText("Freeze Agent")).toBeNull();
    fireEvent.click(unfreeze);
    await waitFor(() => expect(sent).toEqual([{ score: 1.0 }]));
    await waitFor(() => {
      const frozenTile = screen.getByText("Frozen").closest(".panel") as HTMLElement;
      expect(within(frozenTile).getByText("0")).toBeInTheDocument();
    });
    // The real score from the re-read — never the 0.80 the old Unfreeze painted — and no cap on screen.
    expect((await screen.findAllByText("0.46")).length).toBeGreaterThan(0);
    expect(screen.queryByText("0.80")).toBeNull();
    expect(screen.queryByTestId("agent-trust-cap")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
    const trackedTile = screen.getByText("Agents Tracked").closest(".panel") as HTMLElement;
    expect(within(trackedTile).getByText("2")).toBeInTheDocument();
  });

  it("clicking an agent row opens the detail panel with freeze/trust actions", async () => {
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
    expect(screen.getByText("Reset Behavior Record")).toBeInTheDocument();
  });
});

describe("AgentMonitor trust controls", () => {
  const healthy = {
    spiffe_id: "spiffe://norviq/ns/payments/sa/invoice-agent", namespace: "payments", agent_class: "invoice-agent",
    last_seen: new Date().toISOString(), score: 0.455, category: "medium", frozen: false, trust_cap: null,
    violation_count: 6, signals: {}, dominant_signal: "", recommendation: "allow"
  };
  const mount = async () => {
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByText(healthy.spiffe_id));
  };

  it("Freeze asks first, and Cancel sends nothing", async () => {
    const puts: unknown[] = [];
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json([healthy])),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, async ({ request }) => {
        puts.push(await request.json());
        return HttpResponse.json({ spiffe_id: healthy.spiffe_id, frozen: true, trust_cap: null });
      })
    );
    await mount();
    fireEvent.click(await screen.findByText("Freeze Agent"));
    const dialog = await screen.findByTestId("agent-trust-confirm");
    expect(dialog).toHaveTextContent(healthy.spiffe_id);
    fireEvent.click(within(dialog).getByText("Cancel"));
    await waitFor(() => expect(screen.queryByTestId("agent-trust-confirm")).toBeNull());
    expect(puts).toEqual([]);
    expect(screen.queryByText("Unfreeze Agent")).toBeNull();

    fireEvent.click(screen.getByText("Freeze Agent"));
    fireEvent.click(await screen.findByTestId("agent-trust-confirm-submit"));
    await screen.findByText("Unfreeze Agent");
    expect(puts).toEqual([{ score: 0 }]);
  });

  it("Reset Behavior Record calls POST /trust/reset after a confirm, and never PUTs a score", async () => {
    let resets = 0;
    let puts = 0;
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json([healthy])),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => {
        puts += 1;
        return HttpResponse.json({});
      }),
      http.post(/\/api\/v1\/agents\/.*\/trust\/reset$/, () => {
        resets += 1;
        return HttpResponse.json({
          reset: true, spiffe_id: healthy.spiffe_id, score_before: 0.455, violation_count: 6,
          history_entries_cleared: 12, history_blocks_cleared: 6, keys_cleared: [], frozen: false, trust_cap: null
        });
      })
    );
    await mount();
    fireEvent.click(await screen.findByText("Reset Behavior Record"));
    expect(await screen.findByTestId("agent-trust-confirm")).toHaveTextContent(/cannot be undone/);
    expect(resets).toBe(0);
    fireEvent.click(screen.getByTestId("agent-trust-confirm-submit"));
    expect(await screen.findByTestId("agent-action-notice")).toHaveTextContent("12 decisions cleared");
    expect(resets).toBe(1);
    expect(puts).toBe(0);
  });

  it("an active cap is shown, and Remove Cap lifts it with score 1.0 instead of setting another", async () => {
    const capped = { ...healthy, trust_cap: 0.8 };
    const puts: unknown[] = [];
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json([capped])),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([])),
      http.put(/\/api\/v1\/agents\/.*\/trust$/, async ({ request }) => {
        puts.push(await request.json());
        return HttpResponse.json({ spiffe_id: healthy.spiffe_id, frozen: false, trust_cap: null });
      }),
      http.get(/\/api\/v1\/agents\/spiffe[^/]*invoice-agent$/, () => HttpResponse.json({ ...healthy }))
    );
    await mount();
    expect(await screen.findByTestId("agent-trust-cap")).toHaveTextContent("capped at 0.80");
    expect(screen.getByTestId("agent-row-cap")).toHaveTextContent("cap 0.80");
    fireEvent.click(screen.getByText("Remove Cap"));
    await waitFor(() => expect(screen.queryByTestId("agent-trust-cap")).toBeNull());
    expect(puts).toEqual([{ score: 1.0 }]);
    expect(screen.queryByTestId("agent-row-cap")).toBeNull();
    expect(screen.queryByText("Remove Cap")).toBeNull();
  });

  it("a row the API reports frozen offers Unfreeze whatever its category says", async () => {
    // The Unfreeze control keys on the enforced `frozen` flag, not on a category or a score of 0.
    server.use(
      http.get("/api/v1/agents", () =>
        HttpResponse.json([{ ...healthy, frozen: true, score: 0.455, category: "medium" }])
      ),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([]))
    );
    await mount();
    expect(await screen.findByText("Unfreeze Agent")).toBeInTheDocument();
    expect(screen.queryByText("Freeze Agent")).toBeNull();
  });
});

/**
 * Trust state the rest of the console shows, and the states between the four bands.
 *
 * A freeze here only dropped this page's own cache entry, so the Overview's trust donut (its own cache key, a
 * 60 s TTL) kept showing the agent unfrozen. After Remove Cap the score shown was the one the cap had held
 * down. And a row whose freeze the API could not read (trust store down) offered "Freeze" as if the agent were
 * known not to be frozen, while the engine was blocking it.
 */
describe("AgentMonitor — trust state across the console", () => {
  const sid = "spiffe://norviq/ns/payments/sa/invoice-agent";
  const row = {
    spiffe_id: sid, namespace: "payments", agent_class: "invoice-agent", last_seen: new Date().toISOString(),
    score: 0.455, category: "medium", frozen: false, trust_cap: null, controls: "live",
    violation_count: 6, signals: {}, dominant_signal: "", recommendation: "allow"
  };
  const mount = async (rows: unknown[]) => {
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json(rows)),
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
    fireEvent.click(await screen.findByText(sid));
  };

  it("a freeze drops the Overview's cached trust donut too, not only this page's cache", async () => {
    server.use(
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ spiffe_id: sid, frozen: true, trust_cap: null }))
    );
    await mount([row]);
    // What the Overview had cached for every scope it may have been opened on.
    for (const ns of ["default", "payments", "all"]) primeApiCache(`dashboard-agents:${ns}`, [{ ...row }]);
    fireEvent.click(await screen.findByText("Freeze Agent"));
    fireEvent.click(await screen.findByTestId("agent-trust-confirm-submit"));
    await screen.findByText("Unfreeze Agent");
    for (const ns of ["default", "payments", "all"]) expect(peekApiCache(`dashboard-agents:${ns}`)).toBeUndefined();
  });

  it("Remove Cap says the score is not known yet when the API reports it unscored", async () => {
    const capped = { ...row, score: 0.3, category: "low", trust_cap: 0.3 };
    server.use(
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ spiffe_id: sid, frozen: false, trust_cap: null })),
      http.get(/\/api\/v1\/agents\/spiffe[^/]*invoice-agent$/, () =>
        HttpResponse.json({ ...row, score: null, category: "unscored", recommendation: "" })
      )
    );
    await mount([capped]);
    fireEvent.click(await screen.findByText("Remove Cap"));
    expect(await screen.findByTestId("agent-trust-unscored")).toHaveTextContent(/not known until its next call/);
    expect(screen.queryByTestId("agent-trust-cap")).toBeNull();
  });

  it("Remove Cap whose re-read fails does not keep showing the score the cap held down", async () => {
    const capped = { ...row, score: 0.3, category: "low", trust_cap: 0.3 };
    server.use(
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ spiffe_id: sid, frozen: false, trust_cap: null })),
      http.get(/\/api\/v1\/agents\/spiffe[^/]*invoice-agent$/, () => new HttpResponse("boom", { status: 500 }))
    );
    await mount([capped]);
    fireEvent.click(await screen.findByText("Remove Cap"));
    expect(await screen.findByTestId("agent-action-notice")).toHaveTextContent(/Could not re-read/);
    expect(screen.getByTestId("agent-trust-unscored")).toBeInTheDocument();
    expect(screen.queryByText("0.30")).toBeNull();
  });

  it("Remove Cap whose re-read fails keeps a score the cap never held down", async () => {
    const above = { ...row, trust_cap: 0.8 };
    server.use(
      http.put(/\/api\/v1\/agents\/.*\/trust$/, () => HttpResponse.json({ spiffe_id: sid, frozen: false, trust_cap: null })),
      http.get(/\/api\/v1\/agents\/spiffe[^/]*invoice-agent$/, () => new HttpResponse("boom", { status: 500 }))
    );
    await mount([above]);
    fireEvent.click(await screen.findByText("Remove Cap"));
    await screen.findByTestId("agent-action-notice");
    expect(screen.queryByTestId("agent-trust-unscored")).toBeNull();
    expect(screen.getAllByText("0.46").length).toBeGreaterThan(0);
  });

  it("an agent whose freeze could not be read is shown as unknown, never as not frozen", async () => {
    const unknown = { ...row, frozen: null, trust_cap: null, controls: "unavailable", score: null, category: "unknown" };
    await mount([unknown]);
    expect(await screen.findByTestId("agent-controls-unavailable")).toHaveTextContent(/Freeze state unknown/);
    // Neither lift is offered for a state nobody knows; the kill switch still is.
    expect(screen.queryByText("Unfreeze Agent")).toBeNull();
    expect(screen.queryByText("Remove Cap")).toBeNull();
    expect(screen.getByText("Freeze Agent")).toBeInTheDocument();
    const frozenTile = screen.getByText("Frozen").closest(".panel") as HTMLElement;
    expect(frozenTile).toHaveTextContent(/freeze unknown for 1/);
    const legend = screen.getAllByRole("list", { name: /Trust Distribution legend/ })[0];
    expect(within(legend).getByText(/freeze unknown/i).parentElement).toHaveTextContent("1");
  });
});

/**
 * Probes, and the count that used to disagree with the Overview.
 *
 * This page read the SAME /api/v1/agents payload as the Overview donut but never filtered
 * `synthetic`, so "Agents Tracked" counted probe/eval/red-team identities as real agents while the
 * Overview — `Dashboard.tsx`: `.filter((a) => !a.synthetic)` — did not. Two "agents" numbers over one
 * population with nothing on either screen saying which was which.
 *
 * Hidden by DEFAULT so the two reconcile, but never silently: a probe you cannot see is a probe you
 * cannot investigate, and this page is where you would go to investigate one.
 */
describe("AgentMonitor — synthetic identities", () => {
  const REAL = {
    spiffe_id: "spiffe://norviq/ns/default/sa/deploy-bot",
    namespace: "default", agent_class: "deploy-bot", last_seen: new Date().toISOString(),
    score: 0.82, category: "high", violation_count: 0, signals: {}, dominant_signal: "", recommendation: ""
  };
  const PROBE = {
    ...REAL,
    spiffe_id: "spiffe://norviq/ns/default/sa/freeze-bot",
    agent_class: "e2e-bot",
    synthetic: true
  };

  function mount(rows: unknown[]) {
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json(rows)),
      http.get(/\/api\/v1\/agents\/.*\/trust-history/, () => HttpResponse.json([])),
      http.get(/\/api\/v1\/agents\/.*\/tool-usage/, () => HttpResponse.json([]))
    );
    return render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
  }

  it("hides synthetic identities by default, and counts only the real ones", async () => {
    mount([REAL, PROBE]);
    expect(await screen.findByText("deploy-bot")).toBeInTheDocument();
    // The row renders the agent CLASS, which is what the synthetic classifier keys on.
    expect(screen.queryByText("e2e-bot")).not.toBeInTheDocument();
    // The tile must agree with the rows it is sitting above.
    const tile = screen.getByText("Agents Tracked").parentElement!;
    expect(tile).toHaveTextContent("1");
    expect(tile).toHaveTextContent(/1 synthetic\/probe hidden/);
  });

  it("says how many it hid, and the toggle actually reveals them", async () => {
    mount([REAL, PROBE]);
    const toggle = await screen.findByTestId("agents-synthetic-toggle");
    expect(toggle).toHaveTextContent(/1 synthetic\/probe hidden · Show/);
    fireEvent.click(toggle);
    // The hidden identity is reachable — not merely re-counted.
    expect(await screen.findByText("e2e-bot")).toBeInTheDocument();
    expect(toggle).toHaveTextContent(/Hide 1 synthetic\/probe/);
  });

  it("offers no toggle at all when there is nothing hidden", async () => {
    // A control that is always present but usually a no-op teaches an operator to ignore it.
    mount([REAL]);
    expect(await screen.findByText("deploy-bot")).toBeInTheDocument();
    expect(screen.queryByTestId("agents-synthetic-toggle")).not.toBeInTheDocument();
  });
});

// A failed or FORBIDDEN /agents read is not an empty fleet. useApi keeps the last good data on error,
// so a 403 (a viewer with no namespace scope, or a tenant asking for another namespace), a 5xx or a
// network drop rendered "Agents Tracked 0 / Frozen 0 / Low Trust 0 / High Trust 0" — byte-identical
// to a namespace that genuinely has no agents, and an operator would read it as "nothing to govern".
describe("AgentMonitor — an unreadable fleet must not render as an empty one", () => {
  it("shows — rather than 0 when /agents is forbidden", async () => {
    server.use(http.get("/api/v1/agents", () => HttpResponse.json({ detail: "forbidden" }, { status: 403 })));
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Agent Monitor")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/could not read agents/i)).toBeInTheDocument());
    // The zero that used to be here was the whole defect.
    expect(screen.queryByText("Agents Tracked")?.parentElement?.textContent ?? "").not.toMatch(/\b0\b/);
  });

  it("still shows a real 0 for a namespace that genuinely has no agents", async () => {
    server.use(http.get("/api/v1/agents", () => HttpResponse.json([])));
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Agent Monitor")).toBeInTheDocument());
    expect(screen.queryByText(/could not read agents/i)).not.toBeInTheDocument();
  });
});
