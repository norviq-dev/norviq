// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F1 — Red Team view. NO-MOCK-DATA proof: every rendered number comes from the MSW-mocked
// /api/v1/redteam/results/latest (+ /results history). Asserts the honest empty state, the
// proven-blocking scorecard, the got-through gap warning + failed row, the per-technique breakdown,
// and the run-history table — all sourced from the API payload, never a hardcoded frontend value.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import RedTeam from "./RedTeam";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <RedTeam />
      </AppProvider>
    </MemoryRouter>
  );
}

function latest(overrides: Record<string, unknown> = {}) {
  return {
    has_run: true,
    run_id: "run-1",
    created_at: new Date().toISOString(),
    namespace: "default",
    targets: ["finance-agent"],
    total: 29,
    passed: 27,
    failed: 2,
    pass_rate: 93.1,
    results: [
      {
        attack_id: "SQL-001", attack_name: "SQL drop table", category: "sql_injection",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "block",
        passed: true, rule_id: "deny_sql_injection", atlas_technique: "AML.T0054",
        atlas_technique_name: "LLM Jailbreak", owasp_control: null, owasp_control_name: null
      },
      {
        attack_id: "PI-001", attack_name: "Ignore instructions", category: "prompt_injection",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "allow",
        passed: false, rule_id: "default_allow", atlas_technique: "AML.T0048",
        atlas_technique_name: "External Harms", owasp_control: "LLM01:2025", owasp_control_name: "Prompt Injection"
      }
    ],
    efficacy: {
      overall: { total: 2, caught: 1, got_through: 1, proven_blocking_pct: 50.0 },
      by_technique: [
        { technique_id: "AML.T0048", technique_name: "External Harms", total: 1, caught: 0, got_through: 1, proven_blocking_pct: 0.0 },
        { technique_id: "AML.T0054", technique_name: "LLM Jailbreak", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 }
      ],
      by_owasp: [
        { control_id: "LLM01:2025", control_name: "Prompt Injection", total: 1, caught: 0, got_through: 1, proven_blocking_pct: 0.0 }
      ],
      non_enforcement: 0,
      excluded_synthetic: 3
    },
    ...overrides
  };
}

function historyPayload() {
  return {
    runs: [
      { run_id: "run-1", created_at: new Date().toISOString(), namespace: "default", targets: ["finance-agent"],
        total: 29, passed: 27, failed: 2, pass_rate: 93.1, proven_blocking_pct: 50.0, caught: 1, got_through: 1 }
    ],
    total: 1
  };
}

function manyResults(n: number, failEvery = 0) {
  const results = Array.from({ length: n }, (_, i) => ({
    attack_id: `A-${i}`, attack_name: `Attack ${i}`, category: "sql_injection",
    agent_class: `class-${i % 5}`, namespace: "default", expected: "block",
    actual: failEvery && i % failEvery === 0 ? "allow" : "block",
    passed: !(failEvery && i % failEvery === 0), rule_id: "deny_sql_injection",
    atlas_technique: "AML.T0054", atlas_technique_name: "LLM Jailbreak", owasp_control: null, owasp_control_name: null
  }));
  const l = latest();
  return { ...l, total: n, results, targets: ["class-0", "class-1", "class-2", "class-3", "class-4"] };
}

const targetsHandler = () =>
  http.get("*/api/v1/redteam/targets", () => HttpResponse.json({ namespace: "default", targets: ["customer-support", "finance-agent"] }));

it("F1: honest empty state before any run (no fabricated efficacy)", async () => {
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json({ runs: [], total: 0 }))
  );
  renderPage();
  expect(await screen.findByTestId("redteam-empty")).toBeInTheDocument();
  expect(screen.getByText(/No red-team run yet/i)).toBeInTheDocument();
  expect(screen.queryByTestId("redteam-scorecard")).toBeNull();
});

it("F1: scorecard renders the API's proven-blocking % + caught/got-through (not a hardcoded number)", async () => {
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(latest())),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  const card = await screen.findByTestId("redteam-scorecard");
  expect(within(card).getByTestId("redteam-proven-pct")).toHaveTextContent("50%");
  expect(within(card).getByTestId("redteam-gotthrough")).toHaveTextContent("1");
  // got-through > 0 surfaces the gap warning
  expect(screen.getByTestId("redteam-gap-warning")).toHaveTextContent(/got through/i);
});

it("A5: the secondary metrics render inside ONE grouped cluster, values mapped from results/latest", async () => {
  const run = latest({ pass_rate: 93.1, total: 29, efficacy: { overall: { total: 27, caught: 24, got_through: 3, proven_blocking_pct: 88.9 }, by_technique: [], by_owasp: [], non_enforcement: 0, excluded_synthetic: 0 } });
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(run)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  const cluster = await screen.findByTestId("redteam-metric-cluster");
  // all four secondary metrics live inside the grouped cluster (not scattered inline)
  expect(within(cluster).getByText("Caught")).toBeInTheDocument();
  expect(within(cluster).getByTestId("redteam-gotthrough")).toBeInTheDocument();
  expect(within(cluster).getByText("Suite pass-rate")).toBeInTheDocument();
  expect(within(cluster).getByText("Attacks × classes")).toBeInTheDocument();
  // it is a grid group (spaced cluster), not a bare flex list
  expect(cluster).toHaveStyle({ display: "grid" });
  // C3: the cluster is UNBOXED — no --bg-surface fill, no --border box, no radius (metrics + spacing kept)…
  expect(cluster.style.background).toBe("");
  expect(cluster.style.border).toBe("");
  expect(cluster.style.borderRadius).toBe("");
  // …and it is nudged RIGHT (a positive left margin) so the left primary "N%" has room.
  expect(parseInt(cluster.style.marginLeft || "0", 10)).toBeGreaterThan(0);
  // values map straight from results/latest (layout change only, no data change)
  expect(within(cluster).getByTestId("redteam-gotthrough")).toHaveTextContent("3");     // got_through
  expect(within(cluster).getByText("Caught").parentElement).toHaveTextContent("24");     // caught
  expect(within(cluster).getByText("Suite pass-rate").parentElement).toHaveTextContent("93.1%");
  expect(within(cluster).getByText("Attacks × classes").parentElement).toHaveTextContent("29");
});

it("B: header shows a target-class COUNT (not the full comma list); names hide behind an expandable toggle", async () => {
  const many = latest({ targets: ["a-bot", "b-bot", "c-bot", "d-bot", "e-bot"] });
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(many)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  const { default: userEvent } = await import("@testing-library/user-event");
  renderPage();
  const summary = await screen.findByTestId("redteam-targets-summary");
  expect(summary).toHaveTextContent(/5 classes · ran/i);
  // the full comma-separated list is NOT rendered inline by default
  expect(screen.queryByTestId("redteam-targets-list")).toBeNull();
  expect(summary.textContent).not.toContain("a-bot, b-bot"); // no wall-of-text
  // expanding the toggle reveals the names on demand
  await userEvent.click(screen.getByTestId("redteam-targets-toggle"));
  expect(screen.getByTestId("redteam-targets-list")).toHaveTextContent("a-bot, b-bot, c-bot, d-bot, e-bot");
});

it("F1: per-technique breakdown + per-attack rows come from the payload, and a miss is flagged", async () => {
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(latest())),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  await screen.findByTestId("redteam-scorecard");
  // technique + owasp breakdown rows
  const tech = screen.getByTestId("redteam-by-technique");
  expect(within(tech).getByText(/AML\.T0048/)).toBeInTheDocument();
  expect(within(tech).getByText(/LLM01:2025/)).toBeInTheDocument();
  // per-attack rows: two, and exactly one is a "got through" miss
  const rows = screen.getAllByTestId("redteam-attack-row");
  expect(rows).toHaveLength(2);
  expect(screen.getAllByTestId("redteam-row-failed")).toHaveLength(1);
  // RT-FRAMEWORK-01: ONE "Frameworks" column of mapped chips (no separate ATLAS + OWASP columns).
  expect(screen.getByRole("columnheader", { name: "Frameworks" })).toBeInTheDocument();
  expect(screen.queryByRole("columnheader", { name: "ATLAS" })).not.toBeInTheDocument();
  expect(screen.queryByRole("columnheader", { name: "OWASP" })).not.toBeInTheDocument();
  // row 0: ATLAS chip only; row 1: both ATLAS + OWASP chips (scales to N frameworks with zero new columns)
  expect(within(rows[0]).getByTestId("fw-chip-atlas")).toHaveTextContent("AML.T0054");
  expect(within(rows[0]).queryByTestId("fw-chip-owasp")).toBeNull();
  expect(within(rows[1]).getByTestId("fw-chip-atlas")).toHaveTextContent("AML.T0048");
  expect(within(rows[1]).getByTestId("fw-chip-owasp")).toHaveTextContent("LLM01:2025");
  // evidence link → Audit
  expect(within(rows[0]).getByRole("link", { name: "Audit" })).toHaveAttribute("href", expect.stringContaining("/audit?rule="));
  // history table shows the durable run
  expect(within(screen.getByTestId("redteam-history")).getAllByTestId("redteam-history-row")).toHaveLength(1);
});

it("D1: a rapid double-click fires exactly ONE POST /redteam/suite (one-submit guard)", async () => {
  let posts = 0;
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(latest())),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload())),
    http.post("*/api/v1/redteam/suite", () => { posts += 1; return HttpResponse.json(latest()); })
  );
  renderPage();
  const btn = await screen.findByTestId("redteam-run");
  fireEvent.click(btn);
  fireEvent.click(btn);
  await waitFor(() => expect(posts).toBe(1));
});

it("D1: while running, the button is disabled + aria-busy + labelled 'Running…'", async () => {
  let release: () => void = () => {};
  const gate = new Promise<void>((r) => (release = r));
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(latest())),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload())),
    http.post("*/api/v1/redteam/suite", async () => { await gate; return HttpResponse.json(latest()); })
  );
  renderPage();
  const btn = await screen.findByTestId("redteam-run");
  fireEvent.click(btn);
  await waitFor(() => expect(btn).toBeDisabled());
  expect(btn).toHaveAttribute("aria-busy", "true");
  expect(btn).toHaveTextContent(/Running…/);
  release();
  await waitFor(() => expect(btn).not.toBeDisabled());
});

it("D2: a large run is paginated — mounted rows stay bounded (≤50) and Next advances", async () => {
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(manyResults(120))),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  await screen.findByTestId("redteam-attacks");
  expect(screen.getAllByTestId("redteam-attack-row")).toHaveLength(50);
  expect(screen.getByTestId("redteam-page-indicator")).toHaveTextContent("Page 1 / 3");
  fireEvent.click(screen.getByTestId("redteam-next"));
  expect(screen.getByTestId("redteam-page-indicator")).toHaveTextContent("Page 2 / 3");
  expect(screen.getAllByTestId("redteam-attack-row")).toHaveLength(50);
});

it("D2: 'got-through only' filter shows just the misses (still bounded)", async () => {
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(manyResults(120, 4))),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  await screen.findByTestId("redteam-attacks");
  fireEvent.click(within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox"));
  expect(screen.getAllByTestId("redteam-attack-row").length).toBe(30);
  expect(screen.getAllByTestId("redteam-row-failed")).toHaveLength(30);
});
