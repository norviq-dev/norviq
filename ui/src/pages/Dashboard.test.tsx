// SPDX-License-Identifier: Apache-2.0
// UI-1 smoke test: the Dashboard (default landing route) must mount without throwing React #130.
// echarts core is stubbed so the chart components render without a canvas; the interop-shape guard
// lives in components/common/EChart.test.tsx.
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({
  default: () => null
}));

import { Dashboard } from "./Dashboard";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

describe("UI-1: Dashboard mounts", () => {
  it("renders the Overview page without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });

  it("B5: surfaces an engine_errors signal (distinct from policy blocks) when stats report faults", async () => {
    server.use(
      http.get("/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 1000, blocked: 900, allowed: 100, block_rate_pct: 90, engine_errors: 174 })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // The engine-fault banner appears with the count and is explicitly framed as a fail-closed OPA fault,
    // distinct from a policy block.
    expect(await screen.findByText(/engine error/i)).toBeInTheDocument();
    expect(screen.getByText(/fail-closed OPA-evaluation faults/i)).toBeInTheDocument();
  });

  it("K1/K2: KPI cards bind the /audit/stats numbers (total/blocked/block-rate) + real avg_latency_ms", async () => {
    server.use(
      http.get("/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 1666, blocked: 1500, allowed: 166, block_rate_pct: 90.04, avg_latency_ms: 337 })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // the cards bind the resolved stats (data-value is the raw bound number, independent of the count-up anim).
    const total = await screen.findByTestId("kpi-total-value");
    await waitFor(() => expect(total).toHaveAttribute("data-value", "1666"));
    expect(screen.getByTestId("kpi-blocked-value")).toHaveAttribute("data-value", "1500");
    expect(screen.getByTestId("kpi-blockrate-value")).toHaveAttribute("data-value", "90"); // Math.round(90.04)
    // K2: Avg latency is the real avg_latency_ms from the same call (not the old records-derived 0).
    expect(screen.getByTestId("kpi-latency-value")).toHaveAttribute("data-value", "337");
  });

  it("P4: exactly one export control (Report ▾) — no duplicate standalone Export button", async () => {
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    // The Report ▾ menu remains (houses Export CSV + future PDF/Schedule); the standalone "Export" button is gone.
    expect(screen.getByText(/Report ▼/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Export$/ })).not.toBeInTheDocument();
  });
});

describe("F2: Overview coverage caption reflects Red Team efficacy", () => {
  it("upgrades 'not efficacy-tested' to 'X% proven-blocking (last run)' when a run exists", async () => {
    server.use(
      http.get("*/api/v1/redteam/results/latest", () =>
        HttpResponse.json({ has_run: true, efficacy: { overall: { total: 20, caught: 17, got_through: 3, proven_blocking_pct: 85 } } })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // A4: the gauge caption carries the % (teal-emphasized in its own node) and is the NEUTRAL --text-muted
    // token, not block-red. " (last run)" follows the bold %.
    const gaugeCaption = await screen.findByTestId("score-gauge-caption");
    expect(gaugeCaption).toHaveTextContent(/rules present · 85% proven-blocking \(last run\)/i);
    expect(gaugeCaption.style.color).toBe("var(--text-muted)");
    // The proven-blocking % lives on the GAUGE caption; the coverage card is now color-first (the caption
    // that duplicated this number was removed for a cleaner card — the gauge is the single source).
  });

  it("keeps the honest 'not efficacy-tested' caption before any run", async () => {
    server.use(http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })));
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    expect(await screen.findByText(/not efficacy-tested/i)).toBeInTheDocument();
  });
});
