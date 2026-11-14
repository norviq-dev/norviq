// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Red Team view. NO-MOCK-DATA proof: every rendered number comes from the MSW-mocked
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

it("honest empty state before any run (no fabricated efficacy)", async () => {
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json({ runs: [], total: 0 }))
  );
  renderPage();
  expect(await screen.findByTestId("redteam-empty")).toBeInTheDocument();
  expect(screen.getByText(/No red-team run yet/i)).toBeInTheDocument();
  expect(screen.queryByTestId("redteam-scorecard")).toBeNull();
});

it("scorecard renders the API's proven-blocking % + caught/got-through (not a hardcoded number)", async () => {
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

it("the secondary metrics render inside ONE grouped cluster, values mapped from results/latest", async () => {
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
  // The cluster is UNBOXED — no --bg-surface fill, no --border box, no radius (metrics + spacing kept)…
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

it("header shows a target-class COUNT (not the full comma list); names hide behind an expandable toggle", async () => {
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

it("per-technique breakdown + per-attack rows come from the payload, and a miss is flagged", async () => {
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

it("a rapid double-click fires exactly ONE POST /redteam/suite (one-submit guard)", async () => {
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

it("while running, the button is disabled + aria-busy + labelled 'Running…'", async () => {
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

it("a large run is paginated — mounted rows stay bounded (≤50) and Next advances", async () => {
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

it("'got-through only' filter shows just the misses (still bounded)", async () => {
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

// --- MCP / tool vector dimension -----------------------------------------------------------------

const MCP_VECTOR = "mcp-server-identity-unattested";

function withMcp(overrides: Record<string, unknown> = {}) {
  const base = latest();
  const eff = base.efficacy as Record<string, unknown>;
  return {
    ...base,
    results: [
      ...base.results,
      {
        attack_id: "MCP-02", attack_name: "Write via FORGED allowlisted server id", category: "mcp_identity",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "allow",
        passed: false, rule_id: "default_allow", atlas_technique: "AML.T0010",
        atlas_technique_name: "ML Supply Chain Compromise", owasp_control: null, owasp_control_name: null,
        mcp_vector: MCP_VECTOR, mcp_vector_title: "server_id is a self-asserted string"
      }
    ],
    efficacy: {
      ...eff,
      by_vector: [
        { vector_id: MCP_VECTOR, vector_title: "server_id is a self-asserted string", total: 2, caught: 1, got_through: 1, proven_blocking_pct: 50.0 }
      ],
      vector_coverage: {
        catalogued: 39, evaluate_reachable: 4, proxy_only: 29, out_of_scope: 6,
        exercised: 1, unexercised_reachable: ["resources-read-uri-gate"]
      },
      ...overrides
    }
  };
}

function serveMcp(payload: Record<string, unknown>) {
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(payload)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
}

it("scores MCP vectors as a third breakdown beside ATLAS and OWASP", async () => {
  serveMcp(withMcp());
  const panel = await screen.findByTestId("redteam-by-technique");
  // all three taxonomies live in one panel — the existing tests scope their lookups here
  expect(within(panel).getByText(/AML\.T0048/)).toBeInTheDocument();
  expect(within(panel).getByText(/LLM01:2025/)).toBeInTheDocument();
  const vec = within(panel).getByTestId("redteam-by-vector");
  expect(within(vec).getByText(new RegExp(MCP_VECTOR))).toBeInTheDocument();
  expect(within(vec).getByText(/50%/)).toBeInTheDocument();
});

it("states what the run did NOT measure, not only what it caught", async () => {
  serveMcp(withMcp());
  const band = await screen.findByTestId("redteam-mcp-coverage");
  expect(band).toHaveTextContent(/1 of 39/);
  expect(band).toHaveTextContent(/29/);
  // proxy-only vectors are mostly ENFORCED — the copy must not read as failure
  expect(band).toHaveTextContent(/not measured here/i);
  expect(band).not.toHaveTextContent(/failed/i);
  expect(screen.getByTestId("redteam-mcp-unexercised")).toHaveTextContent("resources-read-uri-gate");
});

it("the coverage band is OUTSIDE the metric cluster", async () => {
  // Three specs pairwise-check that no two direct children of the cluster overlap at 1440 and 720
  // wide. A fifth cell there is prohibited, so this asserts the band did not become one.
  serveMcp(withMcp());
  await screen.findByTestId("redteam-mcp-coverage");
  const cluster = screen.getByTestId("redteam-metric-cluster");
  expect(within(cluster).queryByTestId("redteam-mcp-coverage")).toBeNull();
  expect(cluster.children.length).toBe(4);
});

it("tags an MCP row with a chip, never a new column", async () => {
  serveMcp(withMcp());
  await screen.findByTestId("redteam-attacks");
  const rows = screen.getAllByTestId("redteam-attack-row");
  const chips = screen.getAllByTestId("fw-chip-mcp");
  expect(chips).toHaveLength(1);                       // only the MCP row is tagged
  expect(chips[0]).toHaveTextContent(MCP_VECTOR);
  expect(rows.length).toBeGreaterThan(chips.length);   // the other rows carry no MCP chip
  // the results table stays closed to new columns
  expect(screen.queryByRole("columnheader", { name: /^MCP$/ })).toBeNull();
  expect(screen.getAllByRole("columnheader", { name: "Frameworks" })).toHaveLength(1);
});

it("renders a run stored before this dimension existed", async () => {
  // Retention keeps older runs' efficacy blob verbatim; those have neither key. Rendering must not
  // throw, and must not invent a coverage claim it has no data for.
  serveMcp(latest());
  await screen.findByTestId("redteam-scorecard");
  expect(screen.queryByTestId("redteam-mcp-coverage")).toBeNull();
  expect(screen.queryByTestId("redteam-by-vector")).toBeNull();
  expect(screen.getByTestId("redteam-proven-pct")).toHaveTextContent("50%");
});

it("'got-through only' never lists a row the same table calls not-a-miss", async () => {
  // The filter was `!passed` while the badge and the scorecard both exclude `applicable: false`, so
  // filtering to got-through listed rows labelled "not enabled here" and the count disagreed with the
  // number above it. Surfaced by the MCP identity attacks, which are guardrail-conditional by design.
  const base = latest();
  serveMcp({
    ...base,
    results: [
      ...base.results,
      {
        attack_id: "MCP-01", attack_name: "Write via unlisted MCP server", category: "mcp_identity",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "allow",
        passed: false, applicable: false, rule_id: "default_allow",
        atlas_technique: "AML.T0010", atlas_technique_name: "Supply Chain",
        mcp_vector: MCP_VECTOR, mcp_vector_title: "server_id is a self-asserted string"
      }
    ]
  });
  await screen.findByTestId("redteam-attacks");
  fireEvent.click(within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox"));
  const shown = screen.getAllByTestId("redteam-attack-row").length;
  const failed = screen.getAllByTestId("redteam-row-failed").length;
  expect(shown).toBe(failed);                       // every listed row really is a miss
  expect(screen.queryByText(/not enabled here/i)).toBeNull();
});

// --- The table reads the server's verdict, so the filter count IS the scorecard number -----------
//
// The page used to re-derive "got through" as `!passed && applicable !== false`. A throttled or faulted
// block PASSES (actual block == expected block) and the server counts it as got-through; a monitored
// detection FAILS and the server counts it as would-block. A kind run had 17 `block /
// rate_limit_exceeded` red-team rows, and "Got through" read above zero over a filter listing none.

function servedRow(attack_id: string, o: Record<string, unknown>) {
  return {
    attack_id, attack_name: `Attack ${attack_id}`, category: "sql_injection", agent_class: "finance-agent",
    namespace: "default", expected: "block", applicable: true, atlas_technique: "AML.T0048",
    atlas_technique_name: "External Harms", owasp_control: null, owasp_control_name: null, ...o
  };
}

// Rows and efficacy exactly as norviq/api/redteam_efficacy.py serves them for this run.
function verdictRun() {
  return latest({
    total: 7, passed: 3, failed: 4, pass_rate: 42.9,
    results: [
      servedRow("SQL-001", { actual: "block", rule_id: "deny_sql_injection", passed: true, outcome: "caught" }),
      servedRow("PI-001", { actual: "block", rule_id: "rate_limit_exceeded", passed: true, outcome: "got_through" }),
      servedRow("DL-001", { actual: "block", rule_id: "evaluator_timeout", passed: true, outcome: "got_through" }),
      servedRow("PII-001", { actual: "audit", rule_id: "pii_detection", passed: false, outcome: "would_block" }),
      servedRow("FIN-001", { category: "sector_policy", actual: "allow", rule_id: "default_allow", passed: false,
        applicable: false, outcome: "not_enabled" }),
      servedRow("RL-001", { expected: "allow", actual: "block", rule_id: "rate_limit_exceeded", passed: false,
        outcome: "non_enforcement" }),
      servedRow("SH-001", { agent_class: "scorer", actual: "allow", rule_id: "default_allow", passed: false,
        outcome: "synthetic" })
    ],
    efficacy: {
      overall: { total: 4, caught: 1, would_block: 1, got_through: 2, proven_blocking_pct: 25.0, detected_pct: 50.0 },
      by_technique: [
        { technique_id: "AML.T0048", technique_name: "External Harms", total: 4, caught: 1, would_block: 1, got_through: 2, proven_blocking_pct: 25.0 }
      ],
      by_owasp: [],
      non_enforcement: 1,
      sector_not_enabled: 1,
      excluded_synthetic: 1
    }
  });
}

function rowFor(attackId: string): HTMLElement {
  const row = screen.getAllByTestId("redteam-attack-row").find((r) => within(r).queryByText(attackId));
  if (!row) throw new Error(`no row for ${attackId}`);
  return row;
}

it("the got-through filter lists exactly the scorecard's got-through rows — throttles in, monitored detections out", async () => {
  serveMcp(verdictRun());
  const scored = Number((await screen.findByTestId("redteam-gotthrough")).textContent?.replace(/\D/g, ""));
  expect(scored).toBe(2);

  // Before filtering: the throttled and the faulted block are the misses, though both `passed`.
  expect(within(rowFor("PI-001")).getByTestId("redteam-row-failed")).toBeInTheDocument();
  expect(within(rowFor("DL-001")).getByTestId("redteam-row-failed")).toBeInTheDocument();
  // The audited detection is NOT a miss, though it did not `pass`.
  const audited = rowFor("PII-001");
  expect(within(audited).queryByTestId("redteam-row-failed")).toBeNull();
  expect(within(audited).queryByText(/got through/i)).toBeNull();
  expect(within(audited).getByTestId("redteam-row-monitored")).toHaveTextContent(/detected — monitored/);
  expect(within(audited).getByTestId("redteam-row-monitored")).toHaveAttribute("title", expect.stringMatching(/Monitor/));
  expect(within(rowFor("FIN-001")).getByText(/not enabled here/)).toBeInTheDocument();

  const filter = within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox");
  fireEvent.click(filter);
  expect(filter).toBeChecked();
  const shown = screen.getAllByTestId("redteam-attack-row");
  expect(shown).toHaveLength(scored);
  expect(screen.getAllByTestId("redteam-row-failed")).toHaveLength(scored);
  expect(shown.map((r) => within(r).getByText(/^[A-Z]+-\d+$/).textContent)).toEqual(["PI-001", "DL-001"]);
});

it("an attack moved out of the denominator is shown with its reason, on its row and on the scorecard", async () => {
  // MCP-03 forges the pin status of a quarantined tool. The proxy refuses that call from its own pin
  // store before any policy runs, so the server reports the row `proxy_enforced` and leaves it out of
  // every bucket. Out of the score must never mean out of sight.
  const reason = "the quarantine is read from the proxy's pin store at Gate A";
  const base = verdictRun();
  serveMcp({
    ...base,
    results: [
      ...base.results,
      servedRow("MCP-03", { category: "mcp_identity", actual: "allow", rule_id: "default_allow", passed: false,
        mcp_vector: "quarantined-tool-asserts-pinned", outcome: "proxy_enforced", outcome_reason: reason })
    ],
    efficacy: { ...base.efficacy, proxy_enforced: 1 }
  });
  const label = await screen.findByTestId("redteam-row-proxy-enforced");
  expect(rowFor("MCP-03")).toContainElement(label);
  expect(label).toHaveTextContent(/enforced at the MCP proxy, not scored/);
  expect(label).toHaveAttribute("title", reason);
  expect(within(rowFor("MCP-03")).queryByTestId("redteam-row-failed")).toBeNull();

  expect(screen.getByTestId("redteam-proxy-enforced")).toHaveTextContent("1 enforced at the MCP proxy, not scored");
  expect(screen.getByTestId("redteam-not-enabled")).toHaveTextContent("1 not enabled here, not scored");
  // The got-through count is still the scored one, and the filter does not list the proxy row.
  expect(Number(screen.getByTestId("redteam-gotthrough").textContent?.replace(/\D/g, ""))).toBe(2);
  fireEvent.click(within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox"));
  expect(screen.queryByTestId("redteam-row-proxy-enforced")).toBeNull();
});

it("a row stored without `outcome` falls back to the old verdict — an inapplicable miss stays out of the filter", async () => {
  // Rows from runs written before the field existed carry no `outcome`; the page then falls back to
  // `!passed && applicable !== false`. That branch had no test: making it always return "got_through"
  // left every RedTeam test green.
  const base = latest();
  serveMcp({
    ...base,
    results: [
      ...base.results,
      { attack_id: "FIN-002", attack_name: "Sector attack, pack not enabled", category: "sector_policy",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "allow",
        passed: false, applicable: false, rule_id: "default_allow",
        atlas_technique: "AML.T0048", atlas_technique_name: "External Harms", owasp_control: null, owasp_control_name: null }
    ]
  });
  await screen.findByTestId("redteam-attacks");
  expect(within(rowFor("FIN-002")).getByText(/not enabled here/)).toBeInTheDocument();
  expect(within(rowFor("PI-001")).getByTestId("redteam-row-failed")).toBeInTheDocument();
  fireEvent.click(within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox"));
  expect(screen.getAllByTestId("redteam-attack-row").map((r) => within(r).getByText(/^[A-Z]+-\d+$/).textContent)).toEqual(["PI-001"]);
});

it("a new run resets the got-through filter and the pager in the same render that shows it", async () => {
  // The reset used to live in an effect keyed on run_id, which runs only AFTER the new run is on screen —
  // so a click in that gap was undone (2 of 32 lost clicks with four vitest processes in parallel). It is
  // done while rendering now; this pins that it still happens.
  let current = latest({ run_id: "run-1" });
  server.use(
    targetsHandler(),
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(current)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload())),
    http.post("*/api/v1/redteam/suite", () => { current = latest({ run_id: "run-2" }); return HttpResponse.json(current); })
  );
  renderPage();
  await screen.findByTestId("redteam-attacks");
  const filter = () => within(screen.getByTestId("redteam-failed-filter")).getByRole("checkbox");
  fireEvent.click(filter());
  expect(filter()).toBeChecked();
  fireEvent.click(screen.getByTestId("redteam-run"));
  await waitFor(() => expect(screen.getByTestId("redteam-run")).toBeEnabled());
  await waitFor(() => expect(filter()).not.toBeChecked());
  expect(screen.getAllByTestId("redteam-attack-row")).toHaveLength(2);
});

it("rows the scorecard does not score say why, in a muted label — never red", async () => {
  serveMcp(verdictRun());
  await screen.findByTestId("redteam-attacks");
  const runtime = rowFor("RL-001");
  const synthetic = rowFor("SH-001");
  expect(runtime).toHaveTextContent(/runtime control, not scored/);
  expect(synthetic).toHaveTextContent(/synthetic identity, not scored/);
  for (const r of [runtime, synthetic]) expect(within(r).queryByTestId("redteam-row-failed")).toBeNull();
});

it("an attack shows a chip for every technique and control its rule maps to, and the unmapped bucket has no id", async () => {
  // The API credits an attack to every ATLAS technique and OWASP control the Compliance mapping lists its
  // rule under. llm01_prompt_injection is listed under two techniques; chain_depth_limit under none.
  const mapped = latest({
    results: [
      {
        attack_id: "PI-001", attack_name: "Ignore instructions", category: "prompt_injection",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "block",
        passed: true, rule_id: "llm01_prompt_injection",
        atlas_techniques: [
          { technique_id: "AML.T0051", technique_name: "LLM Prompt Injection" },
          { technique_id: "AML.T0054", technique_name: "LLM Jailbreak" }
        ],
        owasp_controls: [{ control_id: "LLM01:2025", control_name: "Prompt Injection" }],
        atlas_technique: "AML.T0051", atlas_technique_name: "LLM Prompt Injection",
        owasp_control: "LLM01:2025", owasp_control_name: "Prompt Injection"
      },
      {
        attack_id: "CE-001", attack_name: "Chain depth abuse", category: "chain_exploit",
        agent_class: "finance-agent", namespace: "default", expected: "block", actual: "block",
        passed: true, rule_id: "chain_depth_limit", atlas_techniques: [], owasp_controls: [],
        atlas_technique: null, atlas_technique_name: null, owasp_control: null, owasp_control_name: null
      }
    ],
    efficacy: {
      overall: { total: 2, caught: 2, got_through: 0, proven_blocking_pct: 100.0 },
      by_technique: [
        { technique_id: "AML.T0051", technique_name: "LLM Prompt Injection", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 },
        { technique_id: "AML.T0054", technique_name: "LLM Jailbreak", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 },
        { technique_id: "unmapped", technique_name: "No ATLAS technique maps this rule", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 }
      ],
      by_owasp: [
        { control_id: "LLM01:2025", control_name: "Prompt Injection", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 }
      ],
      non_enforcement: 0,
      excluded_synthetic: 0
    }
  });
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(mapped)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  await screen.findByTestId("redteam-attacks");
  const rows = screen.getAllByTestId("redteam-attack-row");
  const pi = rows.find((r) => within(r).queryByText("PI-001"))!;
  const ce = rows.find((r) => within(r).queryByText("CE-001"))!;
  expect(within(pi).getAllByTestId("fw-chip-atlas").map((c) => c.textContent)).toEqual(["AML.T0051", "AML.T0054"]);
  expect(within(pi).getAllByTestId("fw-chip-owasp").map((c) => c.textContent)).toEqual(["LLM01:2025"]);
  expect(within(ce).queryByTestId("fw-chip-atlas")).toBeNull();
  expect(within(ce).queryByTestId("fw-chip-owasp")).toBeNull();

  const atlasRows = within(screen.getByTestId("redteam-by-technique"))
    .getAllByTestId("redteam-breakdown-row")
    .filter((r) => r.getAttribute("data-taxonomy") === "redteam-breakdown-atlas");
  const unmapped = atlasRows.find((r) => /No ATLAS technique maps this rule/.test(r.textContent ?? ""))!;
  expect(unmapped).toBeDefined();
  // The bucket is a condition, not a technique: its internal key is never shown as if it were an id.
  expect(unmapped.textContent).not.toMatch(/unmapped/);
});

it("an attack no OWASP control lists says so, on its row and under the OWASP table", async () => {
  // SC-001's rule, llm05_supply_chain, is under no 2025 OWASP control (LLM03:2025 Supply Chain is out of
  // scope in the shared mapping). Its row showed an ATLAS chip and nothing at all for OWASP, and the
  // OWASP table left it out without a word.
  const run = latest({
    results: [
      {
        attack_id: "SC-001", attack_name: "Load plugin", category: "supply_chain", agent_class: "finance-agent",
        namespace: "default", expected: "block", actual: "block", passed: true, outcome: "caught",
        rule_id: "llm05_supply_chain",
        atlas_techniques: [{ technique_id: "AML.T0053", technique_name: "LLM Plugin Compromise" }],
        owasp_controls: [], atlas_technique: "AML.T0053", atlas_technique_name: "LLM Plugin Compromise",
        owasp_control: null, owasp_control_name: null
      },
      {
        attack_id: "PI-001", attack_name: "Ignore instructions", category: "prompt_injection", agent_class: "finance-agent",
        namespace: "default", expected: "block", actual: "block", passed: true, outcome: "caught",
        rule_id: "llm01_prompt_injection",
        atlas_techniques: [{ technique_id: "AML.T0051", technique_name: "LLM Prompt Injection" }],
        owasp_controls: [{ control_id: "LLM01:2025", control_name: "Prompt Injection" }],
        atlas_technique: "AML.T0051", atlas_technique_name: "LLM Prompt Injection",
        owasp_control: "LLM01:2025", owasp_control_name: "Prompt Injection"
      },
      {
        attack_id: "RL-001", attack_name: "Session flood", category: "unbounded_consumption", agent_class: "finance-agent",
        namespace: "default", expected: "allow", actual: "allow", passed: true, outcome: "non_enforcement",
        rule_id: "default_allow", atlas_techniques: [], owasp_controls: [], atlas_technique: null,
        atlas_technique_name: null, owasp_control: null, owasp_control_name: null
      }
    ],
    efficacy: {
      overall: { total: 2, caught: 2, got_through: 0, proven_blocking_pct: 100.0 },
      by_technique: [
        { technique_id: "AML.T0051", technique_name: "LLM Prompt Injection", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 },
        { technique_id: "AML.T0053", technique_name: "LLM Plugin Compromise", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 }
      ],
      by_owasp: [
        { control_id: "LLM01:2025", control_name: "Prompt Injection", total: 1, caught: 1, got_through: 0, proven_blocking_pct: 100.0 }
      ],
      non_enforcement: 1,
      excluded_synthetic: 0
    }
  });
  server.use(
    http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json(run)),
    http.get("*/api/v1/redteam/results", () => HttpResponse.json(historyPayload()))
  );
  renderPage();
  await screen.findByTestId("redteam-attacks");
  const rows = screen.getAllByTestId("redteam-attack-row");
  const sc = rows.find((r) => within(r).queryByText("SC-001"))!;
  const pi = rows.find((r) => within(r).queryByText("PI-001"))!;
  const rl = rows.find((r) => within(r).queryByText("RL-001"))!;
  expect(within(sc).getByTestId("fw-chip-atlas")).toHaveTextContent("AML.T0053");
  expect(within(sc).getByTestId("fw-none-owasp")).toHaveTextContent("not mapped to an OWASP control");
  expect(within(sc).queryByTestId("fw-none-atlas")).toBeNull();
  expect(within(pi).queryByTestId("fw-none-owasp")).toBeNull();
  // A row with neither says both, rather than a bare dash.
  expect(within(rl).getByTestId("fw-none-atlas")).toHaveTextContent("not mapped to an ATLAS technique");
  expect(within(rl).getByTestId("fw-none-owasp")).toHaveTextContent("not mapped to an OWASP control");
  // Only scored rows are counted under the OWASP table: SC-001, not the allow-expected RL-001.
  expect(within(screen.getByTestId("redteam-by-technique")).getByTestId("redteam-owasp-unmapped"))
    .toHaveTextContent("1 scored attack is not mapped to an OWASP control and not counted in this table.");
});
