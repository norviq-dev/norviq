// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// NO-MOCK-DATA proof. Every assertion here checks that a value RENDERED by the Compliance page came
// from the MSW-mocked /api/v1/mitre/coverage (+ trend) response — not from any hardcoded frontend
// list. ATLAS and OWASP are BOTH live: the mock returns DIFFERENT numbers per `?framework=` (ATLAS
// enforced=7/enforceable=10 → 70%; OWASP enforced=4/enforceable=6 → 67%) and DIFFERENT technique
// lists. The tests assert each framework's card renders its OWN coverage %, that switching to OWASP
// surfaces an OWASP-only technique (and never an ATLAS-only one), that each card carries a real
// emblem element, and that the roadmap rows are inert "coming soon" with no %.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Compliance } from "./Compliance";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

// ATLAS coverage: 7 of 10 enforceable enforced (70%), 2 gaps, 1 OOS, blocked=1234, agent_classes=8,
// and exactly one ATLAS-only technique with one affected class.
function atlasPayload() {
  return {
    namespace: "default",
    range: "24h",
    framework: "atlas", // the live API returns the machine id here, NOT a display name — the card derives the name from meta
    enforceable_total: 10,
    enforced: 7,
    gap: 2,
    oos: 1,
    coverage_pct: 70,
    covered: 7,
    total: 11,
    observed: 900,
    blocked: 1234,
    agent_classes: 8,
    last_exported: "3 days ago",
    techniques: [
      {
        technique_id: "AML.T0051",
        name: "LLM Prompt Injection",
        description: "Adversary crafts inputs that override the agent's instructions.",
        scope: "enforceable",
        status: "enforced",
        also: "OWASP LLM · LLM01:2025",
        policies: ["comprehensive.rego · llm01_prompt_injection"],
        covered_policies: ["comprehensive.rego · llm01_prompt_injection"],
        covered: true,
        observed: 842,
        blocked: 842,
        affected_classes: [{ class: "customer-support", blocked: 842 }]
      }
    ]
  };
}

// OWASP coverage: DIFFERENT split — 4 of 6 enforceable enforced (67%), 2 gaps, 0 OOS. A distinctly
// OWASP technique (LLM06 Excessive Agency, a GAP) that does NOT appear in the ATLAS payload.
function owaspPayload() {
  return {
    namespace: "default",
    range: "24h",
    framework: "owasp", // machine id (matches the live API) — the display name "OWASP LLM Top 10 (2025)" comes from meta
    enforceable_total: 6,
    enforced: 4,
    gap: 2,
    oos: 0,
    coverage_pct: 67,
    covered: 4,
    total: 6,
    observed: 500,
    blocked: 321,
    agent_classes: 5,
    last_exported: "1 day ago",
    techniques: [
      {
        technique_id: "LLM06:2025",
        name: "Excessive Agency",
        description: "Agent granted more tool authority than its task requires.",
        scope: "enforceable",
        status: "gap",
        priority: "high",
        policies: [],
        covered_policies: [],
        covered: false,
        observed: 40,
        blocked: 0,
        affected_classes: [{ class: "ops-runner", blocked: 0 }]
      }
    ]
  };
}

// The client now uses the framework-neutral path /api/v1/compliance/:framework/coverage (+ /trend).
function useBothFrameworks() {
  server.use(
    http.get("/api/v1/compliance/:framework/coverage", ({ params }) =>
      HttpResponse.json(params.framework === "owasp" ? owaspPayload() : atlasPayload())
    ),
    http.get("/api/v1/compliance/:framework/trend", ({ params }) =>
      HttpResponse.json({ namespace: "default", range: "30d", framework: params.framework, points: [] })
    )
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <Compliance />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Compliance page — both frameworks live, every value from the API (no mock data)", () => {
  it("renders TWO live framework cards, each with its OWN coverage % (70% ATLAS, 67% OWASP)", async () => {
    useBothFrameworks();
    renderPage();

    // Both donut labels appear — proving each card fetched its own framework's coverage_pct.
    expect(await screen.findByText("70%")).toBeInTheDocument();
    expect(await screen.findByText("67%")).toBeInTheDocument();

    // Both framework names (from the API response) render.
    expect(screen.getByText("MITRE ATLAS")).toBeInTheDocument();
    expect(screen.getByText("OWASP LLM Top 10 (2025)")).toBeInTheDocument();

    // Each card shows its OWN per-framework blocked count (ATLAS 1,234 vs OWASP 321) — DIFFERENT numbers,
    // not a shared global total.
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("321")).toBeInTheDocument();
  });

  it("each live framework card renders a non-empty emblem element", async () => {
    useBothFrameworks();
    renderPage();

    await screen.findByText("70%");
    const emblems = document.querySelectorAll('[data-testid^="emblem-"]');
    expect(emblems.length).toBeGreaterThan(0);
    // Both live marks are present on the overview.
    expect(document.querySelector('[data-testid="emblem-atlas"]')).toBeTruthy();
    expect(document.querySelector('[data-testid="emblem-owasp"]')).toBeTruthy();
  });

  it("switching to OWASP drives the detail view off the OWASP coverage (OWASP technique, NOT an ATLAS-only one)", async () => {
    useBothFrameworks();
    renderPage();

    // Open the OWASP card's detail: it's the second "Open coverage detail →" button.
    const openButtons = await screen.findAllByText("Open coverage detail →");
    fireEvent.click(openButtons[1]);

    // The OWASP-only technique from the OWASP payload is present…
    expect(await screen.findAllByText("Excessive Agency")).toBeTruthy();
    expect(screen.getByText("LLM06:2025")).toBeInTheDocument();
    // …and the ATLAS-only technique must NOT appear (no cross-framework bleed / no baked-in list).
    expect(screen.queryByText("LLM Prompt Injection")).not.toBeInTheDocument();
    expect(screen.queryByText("AML.T0051")).not.toBeInTheDocument();
  });

  it("renders the ATLAS technique + affected-class chip, and NOT any technique outside the mock", async () => {
    useBothFrameworks();
    renderPage();

    // Open the ATLAS card's detail (first button).
    const openButtons = await screen.findAllByText("Open coverage detail →");
    fireEvent.click(openButtons[0]);

    // The one ATLAS technique from the API is present.
    expect(await screen.findAllByText("LLM Prompt Injection")).toBeTruthy();
    expect(screen.getByText("AML.T0051")).toBeInTheDocument();
    expect(await screen.findByText("customer-support")).toBeInTheDocument();
    // The evidence row is the covered_policy rule from the API.
    expect(screen.getByText("comprehensive.rego · llm01_prompt_injection")).toBeInTheDocument();

    // PROOF of no baked-in technique list: a well-known ATLAS technique that is NOT in our mock must
    // NOT appear anywhere (the design mockup hardcoded many of these — the real page must not).
    expect(screen.queryByText("Command & Scripting Interpreter")).not.toBeInTheDocument();
    expect(screen.queryByText("Unsecured Credentials")).not.toBeInTheDocument();
    expect(screen.queryByText("AML.T0050")).not.toBeInTheDocument();
  });

  it("framework CARDS show NO 'coverage steady' trend line — even when the trend WOULD render steady", async () => {
    // seed a trend with >=2 equal-enforced points → TrendText would render "coverage steady" on the card.
    server.use(
      http.get("/api/v1/compliance/:framework/coverage", ({ params }) =>
        HttpResponse.json(params.framework === "owasp" ? owaspPayload() : atlasPayload())
      ),
      http.get("/api/v1/compliance/:framework/trend", ({ params }) =>
        HttpResponse.json({
          namespace: "default", range: "30d", framework: params.framework,
          points: [
            { enforced: 7, coverage_pct: 70, captured_at: "2026-07-01T00:00:00Z" },
            { enforced: 7, coverage_pct: 70, captured_at: "2026-07-05T00:00:00Z" }
          ]
        })
      )
    );
    renderPage();
    // cards render (default overview — no detail drill-in open)…
    expect(await screen.findByText("70%")).toBeInTheDocument();
    expect(await screen.findByText("MITRE ATLAS")).toBeInTheDocument();
    // …and the "coverage steady" trend line is gone from the cards.
    expect(screen.queryByText(/coverage steady/i)).not.toBeInTheDocument();
    // the counts + blocked line the card keeps are still present.
    expect(screen.getByText("1,234")).toBeInTheDocument();
  });

  it("shows the degraded banner when both coverage fetches fail (bound to real error state)", async () => {
    server.use(
      http.get("/api/v1/compliance/:framework/coverage", () => HttpResponse.json({ error: "boom" }, { status: 500 })),
      http.get("/api/v1/compliance/:framework/trend", () =>
        HttpResponse.json({ namespace: "default", range: "30d", framework: "atlas", points: [] })
      )
    );
    renderPage();
    await waitFor(() => expect(screen.getByText(/API unavailable/i)).toBeInTheDocument());
  });

  it("roadmap frameworks are inert 'coming soon' cards with NO coverage numbers", async () => {
    useBothFrameworks();
    renderPage();

    // OWASP Agentic (NOT the LLM Top 10, which is live now) is a roadmap row with UPCOMING + no %.
    const agentic = await screen.findByText("OWASP Agentic Top 10");
    const card = agentic.closest("div")!.parentElement!.parentElement!;
    expect(within(card).getByText(/UPCOMING/i)).toBeInTheDocument();
    expect(within(card).queryByText(/%/)).not.toBeInTheDocument();

    // NIST / ISO / EU remain inert roadmap rows.
    expect(screen.getByText("NIST AI RMF")).toBeInTheDocument();
    expect(screen.getByText("ISO/IEC 42001")).toBeInTheDocument();
    expect(screen.getByText("EU AI Act")).toBeInTheDocument();
  });
});

// The proven-blocking efficacy overlay — coexists with the header range selector (which lives in the
// global Header, not this page, so it is unaffected). Coverage is "rules present"; this is "proven-blocking".
describe("Compliance — efficacy overlay (proven-blocking from the last Red Team run)", () => {
  it("shows the REAL proven-blocking % when a Red Team run exists", async () => {
    useBothFrameworks();
    server.use(
      http.get("*/api/v1/redteam/results/latest", () =>
        HttpResponse.json({
          has_run: true,
          efficacy: { overall: { total: 20, caught: 18, got_through: 2, proven_blocking_pct: 90.0 } }
        })
      )
    );
    renderPage();
    const banner = await screen.findByTestId("compliance-efficacy-banner");
    expect(within(banner).getByTestId("compliance-proven-blocking")).toHaveTextContent("90% proven-blocking");
    expect(within(banner).getByTestId("compliance-proven-blocking")).toHaveTextContent("18/20");
  });

  it("keeps the honest 'not efficacy-tested' caption before any run", async () => {
    useBothFrameworks();
    server.use(http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })));
    renderPage();
    const banner = await screen.findByTestId("compliance-efficacy-banner");
    expect(within(banner).getByTestId("compliance-not-tested")).toHaveTextContent(/not efficacy-tested/i);
    expect(within(banner).queryByTestId("compliance-proven-blocking")).toBeNull();
  });

  // Multi-select: checking ≥1 GAP reveals the batch bar; "Generate for selected" fires ONE
  // batch POST carrying every checked control + the chosen class_mode.
  it("multi-select + class-mode picker → one generate-batch POST with the checked controls", async () => {
    // A 2-gap OWASP payload so multiple controls can be selected.
    const twoGaps = () => ({
      ...owaspPayload(),
      techniques: [
        { technique_id: "LLM06:2025", name: "Excessive Agency", description: "d", scope: "enforceable",
          status: "gap", generatable: true, priority: "high", policies: ["llm06_excessive_agency"],
          covered_policies: [], covered: false,
          observed: 40, blocked: 0, affected_classes: [{ class: "ops-runner", blocked: 0 }] },
        { technique_id: "LLM05:2025", name: "Improper Output Handling", description: "d", scope: "enforceable",
          status: "gap", generatable: true, priority: "medium", policies: ["deny_sql_injection"],
          covered_policies: [], covered: false,
          observed: 10, blocked: 0, affected_classes: [{ class: "billing-bot", blocked: 0 }] }
      ]
    });
    let batchBody: { technique_ids?: string[]; class_mode?: string } | null = null;
    server.use(
      http.get("/api/v1/compliance/:framework/coverage", ({ params }) =>
        HttpResponse.json(params.framework === "owasp" ? twoGaps() : atlasPayload())),
      http.get("/api/v1/compliance/:framework/trend", ({ params }) =>
        HttpResponse.json({ namespace: "default", range: "30d", framework: params.framework, points: [] })),
      http.post("/api/v1/compliance/:framework/generate-batch", async ({ request }) => {
        batchBody = (await request.json()) as { technique_ids?: string[]; class_mode?: string };
        return HttpResponse.json({
          framework: "owasp", namespace: "default", class_mode: batchBody.class_mode, requested: 2,
          drafts_created: 2, results: [
            { status: "draft", draft_id: "d1", technique_id: "LLM06:2025", cls: "ops-runner", deeplink: "/policies/catalog?intent_draft=d1" },
            { status: "draft", draft_id: "d2", technique_id: "LLM05:2025", cls: "billing-bot", deeplink: "/policies/catalog?intent_draft=d2" }
          ]
        });
      })
    );
    renderPage();
    // Open the OWASP detail (second card) → the gap list renders.
    const openButtons = await screen.findAllByText("Open coverage detail →");
    fireEvent.click(openButtons[1]);
    // No batch bar until a gap is checked.
    expect(screen.queryByTestId("gap-batch-bar")).toBeNull();
    // Check BOTH gaps.
    fireEvent.click(await screen.findByTestId("gap-select-LLM06:2025"));
    fireEvent.click(await screen.findByTestId("gap-select-LLM05:2025"));
    expect(await screen.findByTestId("gap-batch-count")).toHaveTextContent("2 selected");
    // Pick a class-mode (all affected classes) and generate.
    fireEvent.change(screen.getByTestId("gap-batch-classmode"), { target: { value: "all" } });
    fireEvent.click(screen.getByTestId("gap-batch-generate"));
    // ONE batch POST fired, carrying BOTH controls + the chosen mode.
    await waitFor(() => expect(batchBody).not.toBeNull());
    expect(batchBody!.class_mode).toBe("all");
    expect([...(batchBody!.technique_ids ?? [])].sort()).toEqual(["LLM05:2025", "LLM06:2025"]);
    // The bar clears after a successful batch.
    await waitFor(() => expect(screen.queryByTestId("gap-batch-bar")).toBeNull());
  });
});
